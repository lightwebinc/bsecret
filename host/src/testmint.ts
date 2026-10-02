/**
 * Test helpers that make fresh bsecret objects the golden vectors do not
 * hold: funding trees and vault tokens mined on a local chain, secrets
 * sealed and wrapped by the TypeScript SDK, carriers and sweeps. OwnerSim
 * and VaultSim are a minimal stand-in for an organisation's tooling: they
 * keep each vault's set and build every transition the way spec section 7.1
 * says, or, on request, the way it says not to. Every key is drawn from a
 * fixed label, so a party is the same on every run. Nothing here is part of
 * the module the host loads.
 */
import { randomBytes } from 'node:crypto'
import {
  CompletedProtoWallet,
  Hash,
  LockingScript,
  MerklePath,
  P2PKH,
  PrivateKey,
  ProtoWallet,
  PushDrop,
  Transaction,
  UnlockingScript,
  type ChainTracker,
  type CreateActionArgs,
  type CreateActionResult,
} from '@bsv/sdk'
import { LockTime, compareBytes, readerLockingKey } from '@lightwebinc/bcommon'
import { tokenBEEF } from './admit.js'
import { checkScalar, commitmentOf, encodePadded, epochWrapKey, seal, selfKeyID, symmetricKey, symmetricSeal } from './keyed.js'
import { setRoot, type Current } from './merkle.js'
import { DefaultLabels, KeyChain, KeySecret, KeyVault, Protocol, SelfProtocol, TagVault, contentID, encodeSecret, encodeVault, secretID, vaultID, type Entry, type Secret, type Vault } from './secrec.js'
import { fundingScript, pushDropScript } from './script.js'
import { concat, fromHex, sha256, toHex, utf8 } from './util.js'

export const sha = (s: string): Uint8Array => sha256(utf8(s))
const ls = (b: Uint8Array): LockingScript => LockingScript.fromBinary(Array.from(b))

/** A local chain: blocks of two, each a minted transaction beside a fixed sibling. */
export class Chain {
  readonly roots = new Map<number, string>()
  private height: number

  constructor(first = 50000, extra: Array<{ height: number; merkleRoot: string }> = []) {
    this.height = first
    for (const h of extra) this.roots.set(h.height, h.merkleRoot)
  }

  /** Gives tx a proof in a new block and returns it. */
  mine(tx: Transaction): Transaction {
    const height = this.height++
    tx.merklePath = new MerklePath(height, [
      [
        { offset: 0, hash: '55'.repeat(32) },
        { offset: 1, hash: tx.id('hex'), txid: true },
      ],
    ])
    this.roots.set(height, tx.merklePath.computeRoot(tx.id('hex')))
    return tx
  }

  /** a and b in one new block of four, at offsets 1 and 2, each with its own minimal path. */
  mineTogether(a: Transaction, b: Transaction): void {
    const height = this.height++
    const s0 = '66'.repeat(32)
    const s3 = '77'.repeat(32)
    const pair = (l: string, r: string): string => toHex(Uint8Array.from(Hash.hash256(Array.from(concat([fromHex(l).reverse(), fromHex(r).reverse()])))).reverse())
    a.merklePath = new MerklePath(height, [
      [
        { offset: 0, hash: s0 },
        { offset: 1, hash: a.id('hex'), txid: true },
      ],
      [{ offset: 1, hash: pair(b.id('hex'), s3) }],
    ])
    b.merklePath = new MerklePath(height, [
      [
        { offset: 2, hash: b.id('hex'), txid: true },
        { offset: 3, hash: s3 },
      ],
      [{ offset: 0, hash: pair(s0, a.id('hex')) }],
    ])
    this.roots.set(height, a.merklePath.computeRoot(a.id('hex')))
  }

  /** Takes the block at height out of the best chain: a reorganisation orphaned it. */
  orphan(height: number): void {
    this.roots.delete(height)
  }

  get tip(): number {
    return Math.max(...this.roots.keys())
  }

  get tracker(): ChainTracker {
    return {
      isValidRootForHeight: async (root, height) => this.roots.get(height) === root,
      currentHeight: async () => this.tip,
    }
  }

  get headers(): Array<{ height: number; merkleRoot: string }> {
    return [...this.roots].map(([height, merkleRoot]) => ({ height, merkleRoot }))
  }
}

/** One identity: its key, its wallet and its compressed public key. */
export class Party {
  readonly key: PrivateKey
  readonly id: Uint8Array
  readonly hex: string
  readonly wallet: CompletedProtoWallet

  constructor(
    readonly label: string,
    key?: PrivateKey,
  ) {
    this.key = key ?? PrivateKey.fromHex(toHex(sha(`bsecret/test/party/${label}`)))
    this.id = Uint8Array.from(this.key.toPublicKey().encode(true) as number[])
    this.hex = toHex(this.id)
    this.wallet = new CompletedProtoWallet(this.key)
  }

  /** The key a reader derives for this party's outputs under keyID. */
  derived(keyID: string): Uint8Array {
    return Uint8Array.from(readerLockingKey(Protocol, keyID, this.hex).encode(true) as number[])
  }

  async sign(keyID: string, data: Uint8Array): Promise<Uint8Array> {
    const r = await this.wallet.createSignature({ data: Array.from(data), protocolID: Protocol, keyID, counterparty: 'anyone' })
    return Uint8Array.from(r.signature)
  }

  unlock(keyID: string): ReturnType<PushDrop['unlock']> {
    return new PushDrop(this.wallet).unlock(Protocol, keyID, 'anyone', 'all', false)
  }
}

let nowhere = 0

/** A transaction from nowhere: one unsigned input of an outpoint no one holds. */
export function fromNowhere(outs: Array<{ satoshis: number; lockingScript: LockingScript }>): Transaction {
  return new Transaction(
    1,
    [{ sourceTXID: toHex(sha(`bsecret/test/nowhere/${nowhere++}/${Date.now()}`)), sourceOutputIndex: 0, unlockingScript: new UnlockingScript(), sequence: 0xffffffff }],
    outs,
    0,
  )
}

/** A mined funding tree of n outputs of 1000 satoshis, locked to derive(owner, keyID). */
export function fundingTree(owner: Party, keyID: string, n: number, chain: Chain): Transaction {
  const lock = ls(fundingScript(owner.derived(keyID)))
  return chain.mine(fromNowhere(Array.from({ length: n }, () => ({ satoshis: 1000, lockingScript: lock }))))
}

/** A carrier of record spending output vout of owner's tree, locked and signed under the secret key id. */
export async function carrier(tree: Transaction, vout: number, owner: Party, record: Uint8Array, lockTime = LockTime, keyID = KeySecret): Promise<Transaction> {
  const lock = pushDropScript(owner.derived(keyID), [record], await owner.sign(keyID, record))
  const tx = new Transaction(
    1,
    [{ sourceTransaction: tree, sourceOutputIndex: vout, unlockingScriptTemplate: owner.unlock(keyID), sequence: 0 }],
    [{ satoshis: tree.outputs[vout]!.satoshis!, lockingScript: ls(lock) }],
    lockTime,
  )
  await tx.sign()
  return tx
}

/**
 * An unmined vault token: output 0 the signed two-field PushDrop of the tag
 * and record, 1 satoshi; each input spends one of inputs with the owner's
 * key under its key id; what the inputs hold beyond 1 satoshi goes to
 * change.
 */
export async function token(owner: Party, record: Uint8Array, inputs: Array<{ src: Transaction; vout: number; keyID: string }>, tag: Uint8Array = TagVault): Promise<Transaction> {
  const lock = pushDropScript(owner.derived(KeyVault), [tag, record], await owner.sign(KeyVault, concat([tag, record])))
  const total = inputs.reduce((n, i) => n + i.src.outputs[i.vout]!.satoshis!, 0)
  const outs = [{ satoshis: 1, lockingScript: ls(lock) }]
  if (total > 1) outs.push({ satoshis: total - 1, lockingScript: new P2PKH().lock(owner.key.toAddress()) })
  const tx = new Transaction(
    1,
    inputs.map((i) => ({ sourceTransaction: i.src, sourceOutputIndex: i.vout, unlockingScriptTemplate: owner.unlock(i.keyID), sequence: 0xffffffff })),
    outs,
    0,
  )
  await tx.sign()
  return tx
}

/** A mined sweep of outputs vouts of owner's tree under keyID: its tombstone, funding-shaped, at output 0. */
export async function sweep(tree: Transaction, vouts: number[], owner: Party, chain: Chain, keyID = KeySecret): Promise<Transaction> {
  const value = vouts.reduce((n, v) => n + tree.outputs[v]!.satoshis!, 0)
  const tx = new Transaction(
    1,
    vouts.map((v) => ({ sourceTransaction: tree, sourceOutputIndex: v, unlockingScriptTemplate: owner.unlock(keyID), sequence: 0xffffffff })),
    [{ satoshis: value, lockingScript: ls(fundingScript(owner.derived(keyID))) }],
    0,
  )
  await tx.sign()
  return chain.mine(tx)
}

/** C = txid(K), hash byte order. */
export const commitment = (tx: Transaction): Uint8Array => Uint8Array.from(tx.hash() as number[])
export const cHex = (tx: Transaction): string => toHex(commitment(tx))

/** One epoch of the vault's group, as the organisation that sampled its key holds it. */
export interface EpochRef {
  epoch: number
  id: Uint8Array
  /** The epoch key's BRC-369 symmetric key. */
  symmetric: Uint8Array
}

/** A stand-in epoch of a group no chain backs: its id and key drawn from a label. */
export function epochOf(label: string, epoch: number): EpochRef {
  const key = sha(`bsecret/test/epoch/${label}/${epoch}`)
  checkScalar(key)
  return { epoch, id: sha(`bsecret/test/epoch-id/${label}/${epoch}`), symmetric: symmetricKey(key) }
}

/** One version of one secret as the owner made it, and its carrier. */
export interface Version {
  name: string
  value: string
  /** The content key. */
  key: Uint8Array
  secret: Secret
  record: Uint8Array
  cid: Uint8Array
  tx: Transaction
  /** The secret-tree output its carrier spends. */
  vout: number
}

/** A mined token and the BEEF it is published in. */
export interface Minted {
  tx: Transaction
  beef: Uint8Array
  rec: Vault
  record: Uint8Array
  /** The transaction its predecessor input (at seq 0, its funding input) spends. */
  parent: Transaction
}

const t0 = 1798761600
export const entryOf = (v: Version): Entry => ({ id: v.secret.id, version: v.secret.version, contentId: v.cid, commitment: v.secret.commitment })
const byId = (a: Entry[]): Entry[] => [...a].sort((x, y) => compareBytes(x.id, y.id))

/** A minimal owner's tooling over a local chain: its trees and its vaults. */
export class OwnerSim {
  readonly party: Party
  readonly secretTree: Transaction
  readonly chainTree: Transaction
  private secretAt = 0
  private chainAt = 0
  private drawn = 0

  constructor(
    readonly crypt: string,
    label: string,
    readonly chain: Chain,
    opts: { key?: PrivateKey; trees?: number; chains?: number } = {},
  ) {
    this.party = new Party(label, opts.key)
    this.secretTree = fundingTree(this.party, KeySecret, opts.trees ?? 64, chain)
    this.chainTree = fundingTree(this.party, KeyChain, opts.chains ?? 8, chain)
  }

  get hex(): string {
    return this.party.hex
  }

  nextSecretVout(): number {
    return this.secretAt++
  }
  nextChainVout(): number {
    return this.chainAt++
  }

  /** A fresh content key and salt: stand-ins for random draws, never the same twice. */
  draw(): { key: Uint8Array; salt: Uint8Array } {
    const n = this.drawn++
    const key = sha(`bsecret/test/key/${this.party.hex}/${n}`)
    checkScalar(key)
    return { key, salt: sha(`bsecret/test/salt/${this.party.hex}/${n}`).subarray(0, 4) }
  }

  /** A new vault keyed to group at epoch, its identifier that of the next chain-tree output. Its first token is not yet minted. */
  vault(name: string, hall: string, group: Uint8Array, epoch: EpochRef, o: { labels?: string[]; anchor?: number } = {}): VaultSim {
    return new VaultSim(this, name, hall, group, epoch, o.labels ?? DefaultLabels, o.anchor ?? 0, this.nextChainVout())
  }
}

/** One vault of an OwnerSim: its chain, its set and every version it made. */
export class VaultSim {
  readonly id: Uint8Array
  tip: Minted | undefined
  /** Every token minted, seq order. */
  history: Minted[] = []
  /** The set as the tooling folds it: by secret id (hex), the version and the epoch it was listed under. */
  set = new Map<string, { v: Version; epoch: number }>()
  /** The last version made of each name. */
  last = new Map<string, Version>()

  constructor(
    readonly owner: OwnerSim,
    readonly name: string,
    readonly hall: string,
    readonly group: Uint8Array,
    public epoch: EpochRef,
    readonly labels: string[],
    readonly anchor: number,
    private readonly chainVout: number,
  ) {
    this.id = vaultID(commitment(owner.chainTree), chainVout)
  }

  get idHex(): string {
    return toHex(this.id)
  }

  /** The secret identifier of name, in hex. */
  secret(name: string): string {
    return toHex(secretID(this.id, name))
  }

  /** The same vault at the same tip, to build a competing transition on. */
  fork(): VaultSim {
    const f = new VaultSim(this.owner, this.name, this.hall, this.group, this.epoch, this.labels, this.anchor, this.chainVout)
    f.tip = this.tip
    f.history = [...this.history]
    f.set = new Map(this.set)
    f.last = new Map(this.last)
    return f
  }

  /**
   * The next version of name: sealed under a fresh content key, wrapped to
   * the owner's wallet and under epoch (the vault's by default), and carried
   * on the next secret-tree output. wrapUnder wraps under another epoch's
   * key than the one the record names; mutate changes the record before its
   * content id is taken.
   */
  async version(name: string, value: string, o: { label?: string; epoch?: EpochRef; wrapUnder?: EpochRef; vout?: number; mutate?: (s: Secret) => void; key?: { key: Uint8Array; salt: Uint8Array }; lockTime?: number } = {}): Promise<Version> {
    const before = this.last.get(name)
    const epoch = o.epoch ?? this.epoch
    const { key, salt } = o.key ?? this.owner.draw()
    const segment = 16384
    const cipher = seal(key, salt, segment, encodePadded({ name, value: utf8(value), extra: [] }, 256))
    const secret: Secret = {
      crypt: this.owner.crypt,
      org: this.owner.party.id,
      vault: this.id,
      id: secretID(this.id, name),
      version: (before?.secret.version ?? 0) + 1,
      previous: before?.cid ?? new Uint8Array(32),
      label: o.label ?? 'internal',
      group: this.group,
      epoch: epoch.epoch,
      epochId: epoch.id,
      commitment: commitmentOf(key),
      hash: sha256(cipher),
      length: cipher.length,
      salt,
      segment,
      created: t0 + 60,
      self: new Uint8Array(80),
      wrap: new Uint8Array(80),
      inline: cipher,
      extra: [],
    }
    o.mutate?.(secret)
    const cid = contentID(secret)
    const self = await this.owner.party.wallet.encrypt({ protocolID: SelfProtocol, keyID: selfKeyID(cid), counterparty: 'self', plaintext: Array.from(key) })
    secret.self = Uint8Array.from(self.ciphertext)
    secret.wrap = symmetricSeal(epochWrapKey((o.wrapUnder ?? epoch).symmetric, cid), Uint8Array.from(randomBytes(32)), key)
    const record = encodeSecret(secret)
    const vout = o.vout ?? this.owner.nextSecretVout()
    const v: Version = { name, value, key, secret, record, cid, tx: await carrier(this.owner.secretTree, vout, this.owner.party, record, o.lockTime), vout }
    this.last.set(name, v)
    return v
  }

  /**
   * The next transition, mined: versions created and updated, names retired,
   * and the epoch it acknowledges (the vault's by default). The count, the
   * stale count and the root are those the tooling's own fold gives; mutate
   * may change the record before it is encoded, to build what a host must
   * refuse or the index must flag.
   */
  async token(change: { create?: Version[]; update?: Version[]; retire?: string[]; epoch?: EpochRef; mutate?: (v: Vault) => void; mine?: boolean } = {}): Promise<Minted> {
    const epoch = change.epoch ?? this.epoch
    const set = new Map(this.set)
    for (const name of change.retire ?? []) set.delete(this.secret(name))
    for (const v of [...(change.update ?? []), ...(change.create ?? [])]) set.set(toHex(v.secret.id), { v, epoch: epoch.epoch })
    const seq = this.tip === undefined ? 0 : this.tip.rec.seq + 1
    const current: Current[] = [...set.values()].map((x) => ({ id: x.v.secret.id, version: x.v.secret.version, contentId: x.v.cid, epoch: x.epoch, seq }))
    const rec: Vault = {
      crypt: this.owner.crypt,
      org: this.owner.party.id,
      vault: this.id,
      seq,
      prev: this.tip === undefined ? new Uint8Array(32) : commitment(this.tip.tx),
      name: this.name,
      hall: this.hall,
      group: this.group,
      epoch: epoch.epoch,
      epochId: epoch.id,
      labels: this.labels,
      anchor: this.anchor,
      create: byId((change.create ?? []).map(entryOf)),
      update: byId((change.update ?? []).map(entryOf)),
      retire: (change.retire ?? []).map((n) => secretID(this.id, n)).sort(compareBytes),
      count: set.size,
      stale: [...set.values()].filter((x) => x.epoch < epoch.epoch).length,
      root: setRoot(current),
      created: t0 + seq * 600,
      extra: [],
    }
    change.mutate?.(rec)
    const record = encodeVault(rec)
    const input = this.tip === undefined ? { src: this.owner.chainTree, vout: this.chainVout, keyID: KeyChain } : { src: this.tip.tx, vout: 0, keyID: KeyVault }
    const tx = await token(this.owner.party, record, [input])
    if (change.mine !== false) this.owner.chain.mine(tx)
    const m: Minted = { tx, beef: change.mine === false ? new Uint8Array(0) : tokenBEEF(tx, input.src), rec, record, parent: input.src }
    this.tip = m
    this.history.push(m)
    this.set = set
    this.epoch = epoch
    return m
  }
}

/**
 * A client wallet that can pay, as BRC-105's client asks of one: each
 * createAction spends a fresh coin mined on chain to the outputs asked for,
 * with change back to itself.
 */
export class PayingWallet extends ProtoWallet {
  constructor(
    private readonly key: PrivateKey,
    private readonly chain: Chain,
  ) {
    super(key)
  }

  coin(): Transaction {
    return this.chain.mine(fromNowhere([{ satoshis: 100000, lockingScript: new P2PKH().lock(this.key.toAddress()) }]))
  }

  async pay(outputs: Array<{ satoshis: number; lockingScript: string }>, coin = this.coin()): Promise<Transaction> {
    const tx = new Transaction(
      1,
      [{ sourceTransaction: coin, sourceOutputIndex: 0, unlockingScriptTemplate: new P2PKH().unlock(this.key), sequence: 0xffffffff }],
      [
        ...outputs.map((o) => ({ satoshis: o.satoshis, lockingScript: LockingScript.fromHex(o.lockingScript) })),
        { satoshis: 100000 - outputs.reduce((n, o) => n + o.satoshis, 0) - 100, lockingScript: new P2PKH().lock(this.key.toAddress()) },
      ],
      0,
    )
    await tx.sign()
    return tx
  }

  async createAction(args: CreateActionArgs): Promise<CreateActionResult> {
    const tx = await this.pay((args.outputs ?? []).map((o) => ({ satoshis: o.satoshis, lockingScript: o.lockingScript })))
    return { tx: tx.toAtomicBEEF(), txid: tx.id('hex') }
  }
}
