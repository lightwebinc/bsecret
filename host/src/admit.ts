/**
 * The topic manager's transaction rules of spec section 11.1, the twin of
 * the Go internal/secrec/admit.go: classification, then a secret carrier's
 * rules 1 to 9, a vault token's rules 1 to 10, or the sweep rule. A
 * transaction is refused for the first rule it breaks, with the same reason
 * label in both languages, and every refusal is thrown: a topic manager
 * raises it rather than answer with empty instructions, so the engine
 * records nothing for the txid. No rule reads another topic or anything
 * this topic holds: the previous coins are held to the subject's inputs and
 * decide only retention, and every spend a rule reads is read from the
 * transactions the BEEF carries.
 */
import { type ChainTracker, type Transaction } from '@bsv/sdk'
import {
  BeefRefusal,
  DefaultMaxBEEF,
  LockTime,
  MaxSequence,
  aloneShape,
  bytesEqual,
  carrierShape,
  mined,
  readTokenOutput,
  readWire,
  readerLockingKey,
  storedToken as storedTx,
  subjectTx,
  tokenLockedTo,
  tokenShape,
  tokenSignedBy,
  tokenSpends,
  unlockingRefusal,
  verifyField,
  type Wire,
} from '@lightwebinc/bcommon'
import { KeyChain, KeySecret, KeyVault, Protocol, Refusal, checkCrypt, checkVaultTransition, contentID, decodeSecret, decodeVault, vaultID, type Secret, type Vault } from './secrec.js'
import { classify, firstPush, fundingScript, isFundingShape, pushDropScript, pushFields } from './script.js'
import { hashOrder, toHex } from './util.js'

export { DefaultMaxBEEF, mined, tokenBEEF } from '@lightwebinc/bcommon'

/** The host's sweep input bound when it names none. */
export const DefaultMaxSweepInputs = 1024

export interface Host {
  /** The topic's crypt identifier. */
  crypt: string
  /** A chain tracker over the host's own block headers. */
  headers?: ChainTracker
  /** The host's BEEF bound; DefaultMaxBEEF when omitted. */
  maxBEEF?: number
  /** The host's sweep input bound; DefaultMaxSweepInputs when omitted. */
  maxSweepInputs?: number
}

export interface Outpoint {
  /** Display order. */
  txid: string
  vout: number
}

export interface Carrier {
  secret: Secret
  /** The record's org. */
  owner: Uint8Array
  /** The record exactly as carried. */
  record: Uint8Array
  contentId: Uint8Array
  /** C = txid(K), hash byte order. */
  commitment: Uint8Array
  /** The outpoint the carrier spends. */
  funding: Outpoint
}

export interface VaultToken {
  vault: Vault
  record: Uint8Array
  vout: number
}

export type TxKind = 'secret' | 'vault-token' | 'sweep'

export interface Admission {
  kind: TxKind
  /** Hash byte order. */
  txid: Uint8Array
  outputs: number[]
  retain: number[]
  carrier?: Carrier
  token?: VaultToken
  /** The token at seq - 1, read from the parent the BEEF carries; absent at seq 0. */
  predecessor?: VaultToken
  /** The parent's txid, display order. */
  parent?: string
  /** The outpoint the token's predecessor input (at seq 0, its funding input) spends. */
  spends?: Outpoint
  /** For a sweep, every outpoint its inputs spend. */
  spent?: Outpoint[]
}

const bin = (s: { toBinary(): number[] }): Uint8Array => Uint8Array.from(s.toBinary())
const srcTxid = (i: Transaction['inputs'][number]): string => i.sourceTXID ?? i.sourceTransaction!.id('hex')

/** The key an owner's output is locked to under a key id. */
function lockingKey(keyID: string, owner: Uint8Array): Uint8Array {
  return Uint8Array.from(readerLockingKey(Protocol, keyID, toHex(owner)).encode(true) as number[])
}

function retained(tx: Transaction, held: number[]): number[] {
  for (const i of held) {
    if (!Number.isInteger(i) || i < 0 || i >= tx.inputs.length) throw new Error(`secrec: previous coin names input ${i} of ${tx.inputs.length}`)
  }
  return [...new Set(held)].sort((a, b) => a - b)
}

/** A BEEF shape's refusal, as this codec's. */
function beef<T>(f: () => T): T {
  try {
    return f()
  } catch (e) {
    if (e instanceof BeefRefusal) throw new Refusal('beef', e.message)
    throw e
  }
}

/**
 * Applies spec section 11.1 to one submission: the BEEF as it arrived, and
 * held, the indices of its subject's inputs that spend an output the topic
 * holds. SPV of the BEEF is the engine's and is assumed to have run.
 */
export async function admit(raw: Uint8Array | number[], held: number[], h: Host): Promise<Admission> {
  try {
    checkCrypt(h.crypt)
  } catch {
    throw new Error(`secrec: host crypt ${JSON.stringify(h.crypt)} breaks the grammar`)
  }
  const w = beef(() => readWire(Uint8Array.from(raw), h.maxBEEF ?? DefaultMaxBEEF))
  const tx = subjectTx(w)
  const a: Admission = { kind: 'sweep', txid: Uint8Array.from(tx.hash() as number[]), outputs: [], retain: retained(tx, held) }

  let claim: 'none' | 'secret' | 'vault-token' = 'none'
  let claims = 0
  let at = 0
  for (const [i, o] of tx.outputs.entries()) {
    const kind = classify(bin(o.lockingScript))
    if (kind === 'secret' || kind === 'vault-token') {
      claim = kind
      at = i
      claims++
    }
  }
  if (claims > 1) throw new Refusal('shape', `${claims} outputs claim a secret or a token`)
  if (claim === 'secret') {
    a.carrier = checkCarrier(w, tx, h)
    a.kind = 'secret'
    a.outputs = [0]
    return a
  }
  if (claim === 'vault-token') {
    await checkToken(a, w, tx, at, h)
    a.kind = 'vault-token'
    a.outputs = [at]
    return a
  }

  // Sweep: nothing claimed, output 0 funding-shaped under any key, mined.
  const first = tx.outputs[0]
  if (first !== undefined && isFundingShape(bin(first.lockingScript))) {
    beef(() => aloneShape(w, tx))
    if (!(await mined(tx, h.headers))) throw new Refusal('unmined')
    if (tx.inputs.length > (h.maxSweepInputs ?? DefaultMaxSweepInputs)) throw new Refusal('too-large', `a sweep of ${tx.inputs.length} inputs`)
    a.outputs = [0]
    a.spent = tx.inputs.map((i) => ({ txid: srcTxid(i), vout: i.sourceOutputIndex }))
    return a
  }
  throw new Refusal('not-bsecret')
}

/** The secret carrier's rules 1 to 9; 5 to 8 in bcommon's carrier order. */
function checkCarrier(w: Wire, tx: Transaction, h: Host): Carrier {
  // 1. shape.
  if (tx.inputs.length !== 1 || tx.outputs.length !== 1) throw new Refusal('shape', `${tx.inputs.length} inputs, ${tx.outputs.length} outputs`)
  const input = tx.inputs[0]!
  const out = tx.outputs[0]!
  // 2. beef: the carrier (unproven) and its funding tree (proven, minimally).
  const tree = beef(() => carrierShape(w, tx))
  // 3. the record's own rules.
  const lock = bin(out.lockingScript)
  const record = firstPush(lock)!
  const secret = decodeSecret(record)
  const c: Carrier = {
    secret,
    owner: secret.org,
    record,
    contentId: contentID(secret),
    commitment: Uint8Array.from(tx.hash() as number[]),
    funding: { txid: tree.txid, vout: input.sourceOutputIndex },
  }
  // 4. crypt.
  if (secret.crypt !== h.crypt) throw new Refusal('crypt', "not this topic's crypt")
  // 5. mineable.
  if (tx.lockTime < LockTime || (input.sequence ?? MaxSequence) === MaxSequence) throw new Refusal('mineable')
  // 6. unlock, bcommon's check.
  if (unlockingRefusal(tx) !== undefined) throw new Refusal('unlock')
  // 7. lock.
  const key = lockingKey(KeySecret, c.owner)
  const fields = pushFields(lock)
  if (fields?.length !== 2) throw new Refusal('lock', 'want the record and a signature')
  const sig = fields[1]!
  if (!bytesEqual(lock, pushDropScript(key, [record], sig))) throw new Refusal('lock')
  // 8. signature.
  if (!verifyField(key, record, sig)) throw new Refusal('signature')
  // 9. funding: the output spent, read from the funding tree in the BEEF.
  const src = tree.tx!.outputs[input.sourceOutputIndex]
  if (src === undefined || !bytesEqual(bin(src.lockingScript), fundingScript(key))) throw new Refusal('funding')
  if ((src.satoshis ?? 0) !== (out.satoshis ?? 0)) throw new Refusal('funding', 'the value is not carried whole')
  return c
}

/** One token output read well formed: fields, 1 satoshi, record, canonical lock, signature. */
export function readVaultOutput(script: Uint8Array, satoshis: number | undefined, vout: number): VaultToken | undefined {
  if (classify(script) !== 'vault-token') return undefined
  const to = readTokenOutput(script, satoshis, vout, 2)
  if (to === undefined) return undefined
  try {
    const vault = decodeVault(to.fields[1]!)
    const key = lockingKey(KeyVault, vault.org)
    if (!tokenLockedTo(to, script, key) || !tokenSignedBy(to, key)) return undefined
    return { vault, record: to.fields[1]!, vout }
  } catch {
    return undefined
  }
}

/** The one vault token a transaction holds, well formed, read without its parent (a stored token). */
export function readToken(tx: Transaction): VaultToken {
  let found: VaultToken | undefined
  for (const [i, o] of tx.outputs.entries()) {
    const s = bin(o.lockingScript)
    if (classify(s) !== 'vault-token') continue
    if (found !== undefined) throw new Refusal('shape', 'two token outputs')
    found = readVaultOutput(s, o.satoshis, i)
    if (found === undefined) throw new Refusal('shape', 'not a well-formed token')
  }
  if (found === undefined) throw new Refusal('not-bsecret')
  return found
}

/** A vault token as a host stores it (the token alone with its proof), read without its parent. */
export function storedToken(raw: Uint8Array): { tx: Transaction; token: VaultToken } {
  const tx = beef(() => storedTx(raw, DefaultMaxBEEF))
  return { tx, token: readToken(tx) }
}

const samePredecessor = (t: Vault, p: Vault): boolean => p.crypt === t.crypt && bytesEqual(p.org, t.org) && bytesEqual(p.vault, t.vault) && p.seq + 1 === t.seq

/** The vault token's rules 1 to 10. */
async function checkToken(a: Admission, w: Wire, tx: Transaction, at: number, h: Host): Promise<void> {
  const out = tx.outputs[at]!
  const lock = bin(out.lockingScript)
  // 1. shape.
  const to = readTokenOutput(lock, out.satoshis, at, 2)
  if (to === undefined) throw new Refusal('shape', 'a token is two fields, a signature and 1 satoshi')
  // 2. beef.
  const parent = beef(() => tokenShape(w, tx))
  // 3. the record's own rules.
  const vault = decodeVault(to.fields[1]!)
  const t: VaultToken = { vault, record: to.fields[1]!, vout: at }
  // 4. crypt.
  if (vault.crypt !== h.crypt) throw new Refusal('crypt', "not this topic's crypt")
  // 5. lock.
  const key = lockingKey(KeyVault, vault.org)
  if (!tokenLockedTo(to, lock, key)) throw new Refusal('lock')
  // 6. signature.
  if (!tokenSignedBy(to, key)) throw new Refusal('signature')
  // 7. unmined.
  if (!(await mined(tx, h.headers)) || !(await mined(parent.tx, h.headers))) throw new Refusal('unmined')
  // 8. token-input: every spend is read from the parent in the BEEF.
  const ptxid = hashOrder(parent.txid)
  const spends = tokenSpends(tx, parent)
  a.token = t
  a.parent = parent.txid
  if (vault.seq === 0) {
    if (spends.length !== 1) throw new Refusal('token-input', `seq 0 has ${spends.length} inputs spending its parent, want one`)
    const sp = spends[0]!
    if (!bytesEqual(sp.script, fundingScript(lockingKey(KeyChain, vault.org)))) throw new Refusal('token-input', 'seq 0 does not spend a chain-tree output of the owner')
    // 9. vault-id.
    if (!bytesEqual(vault.vault, vaultID(ptxid, sp.vout))) throw new Refusal('vault-id')
    a.spends = { txid: parent.txid, vout: sp.vout }
    return
  }
  let pred: VaultToken | undefined
  let spendsToken = 0
  for (const sp of spends) {
    if (classify(sp.script) !== 'vault-token') continue
    spendsToken++
    pred = readVaultOutput(sp.script, sp.satoshis, sp.vout) ?? pred
  }
  if (!bytesEqual(ptxid, vault.prev) || spendsToken !== 1 || pred === undefined || !samePredecessor(vault, pred.vault)) {
    throw new Refusal('token-input', "the parent's token at seq - 1 is not spent exactly once")
  }
  // 10. the transition rules.
  checkVaultTransition(pred.vault, ptxid, vault)
  a.predecessor = pred
  a.spends = { txid: parent.txid, vout: pred.vout }
}

/**
 * The index's and a reader's check on a vault's first token as a host
 * stores it: one well-formed token at seq 0, and an input whose outpoint
 * hashes to the vault identifier. It returns the token and that outpoint.
 */
export function checkFirstToken(tx: Transaction): { token: VaultToken; spends: Outpoint } {
  const token = readToken(tx)
  if (token.vault.seq !== 0) throw new Refusal('token-input', `seq ${token.vault.seq} is not a first token`)
  for (const i of tx.inputs) {
    const txid = srcTxid(i)
    if (bytesEqual(vaultID(hashOrder(txid), i.sourceOutputIndex), token.vault.vault)) return { token, spends: { txid, vout: i.sourceOutputIndex } }
  }
  throw new Refusal('vault-id')
}

/**
 * The same check on a later token against the one before it, each as a host
 * stores it: exactly one input of next spends a token output of prev, that
 * output is prev's token, and the transition rules hold.
 */
export function checkNextToken(prev: Transaction, prevToken: VaultToken, next: Transaction): VaultToken {
  const token = readToken(next)
  const ptxid = prev.id('hex')
  const spent = next.inputs.filter((i) => {
    if (srcTxid(i) !== ptxid) return false
    const o = prev.outputs[i.sourceOutputIndex]
    return o !== undefined && classify(bin(o.lockingScript)) === 'vault-token'
  })
  if (spent.length !== 1 || spent[0]!.sourceOutputIndex !== prevToken.vout || !bytesEqual(token.vault.prev, hashOrder(ptxid)) || !samePredecessor(token.vault, prevToken.vault)) {
    throw new Refusal('token-input', 'not a spend of the token before it')
  }
  checkVaultTransition(prevToken.vault, hashOrder(ptxid), token.vault)
  return token
}

/** Which of the tokens a host holds, each as stored, are rooted: txids in display order. */
export function rooted(txs: Transaction[]): Set<string> {
  const all: Array<{ tx: Transaction; token: VaultToken; id: string }> = []
  const out = new Set<string>()
  for (const tx of txs) {
    try {
      const token = readToken(tx)
      all.push({ tx, token, id: tx.id('hex') })
      checkFirstToken(tx)
      out.add(tx.id('hex'))
    } catch {
      // Not a token, or not a first token.
    }
  }
  for (let grew = true; grew; ) {
    grew = false
    for (const h of all) {
      if (out.has(h.id)) continue
      for (const p of all) {
        if (!out.has(p.id) || p.token.vault.seq + 1 !== h.token.vault.seq) continue
        try {
          checkNextToken(p.tx, p.token, h.tx)
          out.add(h.id)
          grew = true
          break
        } catch {
          // Not its successor.
        }
      }
    }
  }
  return out
}
