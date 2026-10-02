/**
 * Every Go-generated vector under testdata/vectors, run through the
 * TypeScript codec: the records decode and re-encode byte for byte, refuse
 * for the same reasons, the identifiers, roots, keys and wraps reproduce,
 * every version opens for whoever the Go codec says it opens for, and every
 * transaction case is admitted or refused exactly as the Go codec decided.
 */
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { test } from 'node:test'
import { PrivateKey, ProtoWallet, Transaction, type ChainTracker } from '@bsv/sdk'
import { readerLockingKey } from '@lightwebinc/bcommon'
import { DefaultMaxBEEF, DefaultMaxSweepInputs, admit, checkFirstToken, checkNextToken, rooted, storedToken, tokenBEEF, type Admission, type VaultToken } from './admit.js'
import { Listings, OutpointRow, VaultFold, carrierStatus, checkInSet, checkListed } from './chain.js'
import { checkScalar, commitmentOf, decodePayload, encodePayload, epochWrapKey, openSegments, readAsMember, readAsOwner, seal, selfKeyID, symmetricKey, unwrapFromEpoch, unwrapFromSelf } from './keyed.js'
import { decodeContext, encodeContext, proveSecret, setRoot, verifySecret } from './merkle.js'
import { Classes, parseQuery } from './query.js'
import {
  AnyoneKey,
  DefaultLabels,
  DomainCommitment,
  DomainEpochWrap,
  DomainSecretID,
  DomainSymmetric,
  DomainVaultID,
  LookupService,
  MagicPayload,
  MagicSecret,
  MagicVault,
  MaxLength,
  MaxPayload,
  Protocol,
  SelfProtocol,
  TagFunding,
  TagVault,
  TopicPrefix,
  checkVaultTransition,
  cipherLength,
  contentID,
  decodeSecret,
  decodeVault,
  encodeSecret,
  encodeVault,
  newCrypt,
  plainLength,
  reasonOf,
  secretID,
  topic,
  vaultID,
  type Secret,
  type Vault,
} from './secrec.js'
import { classify } from './script.js'
import { displayTxid, fromHex, toHex } from './util.js'

const dir = new URL('../../testdata/vectors/', import.meta.url)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const load = (name: string): any => JSON.parse(readFileSync(new URL(name, dir), 'utf8'))
const hexFile = (name: string): Uint8Array => fromHex(readFileSync(new URL(name, dir), 'utf8').trim())
const hex = (b: Uint8Array): string => toHex(b)
const reason = (f: () => unknown): string => {
  try {
    f()
  } catch (e) {
    return reasonOf(e)
  }
  return 'ok'
}
const reasonAsync = async (f: () => Promise<unknown>): Promise<string> => {
  try {
    await f()
  } catch (e) {
    return reasonOf(e)
  }
  return 'ok'
}

const derivation = load('derivation-v1.json')
const privOf = (party: string): PrivateKey => PrivateKey.fromHex(derivation.identities.find((p: { party: string }) => p.party === party).privateKey)

test('derivation-v1: the registry values, every derived key and every identifier', async () => {
  const r = derivation.registry
  assert.deepEqual(r.protocol, Protocol)
  assert.deepEqual(r.selfProtocol, SelfProtocol)
  assert.equal(r.tagVault, hex(TagVault))
  assert.equal(r.tagFunding, hex(TagFunding))
  assert.equal(r.magicVault, hex(MagicVault))
  assert.equal(r.magicSecret, hex(MagicSecret))
  assert.equal(r.magicPayload, hex(MagicPayload))
  assert.equal(r.topicPrefix, TopicPrefix)
  assert.equal(r.lookupService, LookupService)
  assert.equal(r.anyoneKey, hex(AnyoneKey))
  assert.equal(r.domainSymmetric, DomainSymmetric)
  assert.equal(r.domainCommitment, DomainCommitment)
  assert.equal(r.domainVaultId, DomainVaultID)
  assert.equal(r.domainSecretId, DomainSecretID)
  assert.equal(r.domainEpochWrap, DomainEpochWrap)
  assert.deepEqual(r.defaultLabels, DefaultLabels)
  for (const d of derivation.derivedKeys) {
    for (const k of ['vault', 'secret', 'chain']) assert.equal(readerLockingKey(Protocol, k, d.identityKey).toString(), d[k], `${d.party} ${k}`)
  }
  const drawn = derivation.crypts.drawnFromBytes
  const bytes = fromHex(drawn.bytes)
  let at = 0
  assert.equal(newCrypt('example_crypt', (n) => bytes.subarray(at, (at += n))), drawn.result)
  assert.equal(topic(derivation.crypts.vectors), derivation.crypts.topic)
  const ids = derivation.ids
  const vault = vaultID(fromHex(ids.genesisTxid), 0)
  assert.equal(hex(vault), ids.vaultId)
  assert.equal(`${displayTxid(fromHex(ids.genesisTxid))}.0`, ids.genesisOutpoint)
  for (const [name, id] of Object.entries(ids.secrets)) assert.equal(hex(secretID(vault, name)), id, name)
  for (const e of derivation.group.epochs) {
    assert.equal(hex(symmetricKey(fromHex(e.key))), e.symmetricKey)
    assert.equal(hex(commitmentOf(fromHex(e.key))), e.commitment)
  }
  // The self wrap: the owner's wallet opens it through the SDK's BRC-2, and
  // no other wallet does, nor the owner's under another content id.
  const w = derivation.selfWrap
  const cid = fromHex(w.contentId)
  assert.equal(selfKeyID(cid), w.keyId)
  const commitment = commitmentOf(fromHex(w.key))
  assert.equal(hex(await unwrapFromSelf(new ProtoWallet(privOf('org')), cid, fromHex(w.wrap), commitment)), w.key)
  assert.equal(await reasonAsync(() => unwrapFromSelf(new ProtoWallet(privOf('alice')), cid, fromHex(w.wrap), commitment)), 'undecryptable')
  assert.equal(await reasonAsync(() => unwrapFromSelf(new ProtoWallet(privOf('org')), fromHex('00'.repeat(32)), fromHex(w.wrap), commitment)), 'undecryptable')
})

test('every .hex record decodes and re-encodes byte for byte', () => {
  let n = 0
  for (const name of readdirSync(dir)) {
    if (!name.endsWith('.hex')) continue
    const raw = hexFile(name)
    if (name.startsWith('vault-')) assert.equal(hex(encodeVault(decodeVault(raw))), hex(raw), name)
    else assert.equal(hex(encodeSecret(decodeSecret(raw))), hex(raw), name)
    n++
  }
  assert.ok(n >= 17, `${n} hex files`)
})

test('refusal-v1: every record refused for the same reason, unknown keys kept', () => {
  const f = load('refusal-v1.json')
  assert.ok(f.refusals.length >= 70)
  const decode: Record<string, (b: Uint8Array) => unknown> = { vault: decodeVault, secret: decodeSecret, payload: decodePayload }
  for (const r of f.refusals) assert.equal(reason(() => decode[r.record]!(fromHex(r.hex))), r.reason, `${r.record}: ${r.label}`)
  const big = decodeSecret(fromHex(f.largestAccepted.hex))
  assert.equal(big.length, f.largestAccepted.length)
  assert.equal(plainLength(big.length, big.segment), MaxPayload)
  assert.ok(big.length <= MaxLength)
  for (const u of f.unknownKeyKept) {
    const raw = fromHex(u.hex)
    if (u.record === 'vault') {
      const v = decodeVault(raw)
      assert.equal(v.extra.length, 1)
      assert.equal(hex(encodeVault(v)), u.hex)
    } else if (u.record === 'payload') {
      assert.equal(hex(encodePayload(decodePayload(raw))), u.hex)
    } else {
      assert.equal(hex(encodeSecret(decodeSecret(raw))), u.hex)
    }
  }
})

test('query-v1: every class, and every question parsed or refused', () => {
  const f = load('query-v1.json')
  assert.deepEqual(
    f.classes.map((c: { class: string; members: string[]; price: string; limit: number }) => [c.class, c.members, c.price === 'free', c.limit]),
    Classes.map((c) => [c.name, c.members, c.free, c.limit]),
  )
  for (const q of f.questions) {
    const got = reason(() => parseQuery(q.question))
    assert.equal(got !== 'ok', q.refused, q.question)
    if (!q.refused) assert.equal(parseQuery(q.question).class.name, q.class)
    else assert.equal(got, 'query')
  }
})

test('script-v1: the classifier', () => {
  for (const s of load('script-v1.json').scripts) assert.equal(classify(fromHex(s.script)), s.claims === 'none' ? 'none' : s.claims, s.label)
})

const vaultFile = load('vault-v1.json')
const chain: Vault[] = vaultFile.records.map((r: { file: string }) => decodeVault(hexFile(r.file)))
const chainTxids: Uint8Array[] = vaultFile.records.map((r: { standInTxid: string }) => fromHex(r.standInTxid))

test('vault-v1: the chain folds, every transition verdict, every fold case', () => {
  const fold = new VaultFold()
  for (const [i, r] of vaultFile.records.entries()) {
    const v = chain[i]!
    assert.equal(fold.apply(v), r.status, r.file)
    assert.equal(hex(setRoot(fold.setNow())), r.root)
    assert.equal(fold.setNow().length, r.count)
    assert.equal(fold.stale(), r.stale)
    assert.equal(v.seq, r.seq)
    assert.equal(hex(v.prev), r.prev)
  }
  assert.equal(hex(setRoot([])), vaultFile.emptyRoot)
  assert.ok(vaultFile.transitions.length >= 25)
  for (const t of vaultFile.transitions) {
    const got = reason(() => checkVaultTransition(chain[t.from]!, chainTxids[t.from]!, decodeVault(fromHex(t.to))))
    assert.equal(got === 'ok' ? 'admitted' : got, t.verdict, t.label)
  }
  for (const c of vaultFile.fold) {
    const f = new VaultFold()
    assert.equal(c.after.length, c.records.length, c.label)
    for (const [i, r] of c.records.entries()) {
      assert.equal(f.apply(decodeVault(fromHex(r))), c.statuses[i], `${c.label} token ${i}`)
      // The fold is atomic: a record that breaks it leaves the set of the
      // record before it, and both codecs reach the same set.
      const a = c.after[i]!
      assert.equal(hex(setRoot(f.setNow())), a.root, `${c.label} token ${i} root`)
      assert.equal(f.setNow().length, a.count, `${c.label} token ${i} count`)
      assert.equal(f.stale(), a.stale, `${c.label} token ${i} stale`)
    }
  }
})

const secretOf = (file: string): Secret => decodeSecret(hexFile(file))

test('vault-v1: a reader in-set check case by case, and the inclusion context', () => {
  assert.ok(vaultFile.inSet.length >= 7)
  for (const c of vaultFile.inSet) {
    const token = c.token === undefined ? chain[c.tokenSeq]! : decodeVault(fromHex(c.token))
    const path = decodeContext(fromHex(c.context))
    assert.equal(hex(encodeContext(path)), c.context, c.label)
    const got = reason(() => checkInSet(token, chainTxids[c.tokenSeq]!, secretOf(c.record), path))
    assert.equal(got === 'ok' ? 'in the set' : got, c.verdict, c.label)
  }
  // The context of the last token's set is the one the file carries.
  const sc = vaultFile.secretContext
  const fold = new VaultFold()
  for (const v of chain) fold.apply(v)
  const rec = secretOf(`secret-${sc.secret.replace('/', '-')}-v${sc.version}.hex`)
  const ctx = proveSecret(sc.setOf, fromHex(sc.token), fold.setNow(), rec.id)
  assert.equal(hex(encodeContext(ctx)), sc.context)
  assert.equal(verifySecret(ctx, rec.id, rec.version, contentID(rec), chain[sc.setOf]!.root), sc.verifies)
  assert.equal(verifySecret(ctx, rec.id, rec.version - 1, contentID(rec), chain[sc.setOf]!.root), false)
})

const secretFile = load('secret-v1.json')

test('secret-v1: content ids, and each record against the token that lists it', () => {
  for (const r of secretFile.records) {
    const rec = secretOf(r.file)
    assert.equal(hex(contentID(rec)), r.contentId, r.file)
    assert.equal(rec.inline !== undefined, r.inline, r.file)
    assert.equal(hex(rec.id), r.id)
    assert.equal(hex(commitmentOf(fromHex(r.key))), hex(rec.commitment))
  }
  const u = secretFile.contentId.unknownKeyKept
  assert.equal(hex(contentID(decodeSecret(fromHex(u.hex)))), u.contentId)
  assert.ok(secretFile.listings.length >= 14)
  for (const l of secretFile.listings) {
    const token = l.token === undefined ? chain[l.tokenSeq ?? 0]! : decodeVault(fromHex(l.token))
    const got = reason(() => checkListed(token, secretOf(l.record)))
    assert.equal(got === 'ok' ? 'listed' : got, l.verdict, l.label)
  }
})

test('secret-v1: every version opens for the owner and for the members of its epoch, and for nobody else', async () => {
  const epochs = derivation.group.epochs as Array<{ epoch: number; symmetricKey: string; holders: string[] }>
  const owner = new ProtoWallet(privOf('org'))
  for (const r of secretFile.records) {
    const rec = secretOf(r.file)
    const cid = contentID(rec)
    assert.equal(hex(epochWrapKey(fromHex(epochs[r.epoch]!.symmetricKey), cid)), r.epochWrapKey)
    assert.equal(selfKeyID(cid), r.selfKeyId)
    // The owner's wallet opens the self wrap the Go codec wrote.
    assert.equal(hex(await unwrapFromSelf(owner, cid, rec.self, rec.commitment)), r.key, r.file)
    for (const e of epochs) {
      const got = reason(() => unwrapFromEpoch(fromHex(e.symmetricKey), cid, rec.wrap, rec.commitment))
      assert.equal(got === 'ok', e.epoch === r.epoch, `${r.file} under epoch ${e.epoch}`)
    }
    for (const name of ['alice', 'bob', 'carol', 'dave']) {
      const e = epochs[r.epoch]!
      assert.equal(e.holders.includes(name), r.opens[name] === 'opens', `${r.file}: ${name}`)
    }
    if (rec.inline === undefined) continue
    const p = readAsMember(rec, rec.inline, fromHex(epochs[r.epoch]!.symmetricKey))
    assert.equal(p.name, r.name)
    assert.equal(new TextDecoder().decode(p.value), r.value)
    assert.equal(p.type, r.type)
    assert.equal(p.pad?.length ?? 0, r.padBytes)
    assert.equal(hex(encodePayload(p)), r.payload)
    assert.equal((await readAsOwner(owner, rec, rec.inline)).name, r.name)
    // The TypeScript seal writes the ciphertext the Go codec wrote.
    assert.equal(hex(seal(fromHex(r.key), rec.salt, rec.segment, fromHex(r.payload))), hex(rec.inline), r.file)
  }
  // A version whose wrap is under another epoch's key than the one it names.
  const mk = secretFile.misKeyed
  const rec = decodeSecret(fromHex(mk.record))
  assert.equal(reason(() => unwrapFromEpoch(fromHex(epochs[rec.epoch]!.symmetricKey), contentID(rec), rec.wrap, rec.commitment)), mk.underTheEpochItNames)
})

test('keyed-v1: a member read, in the order of the checks', () => {
  const f = load('keyed-v1.json')
  const sym = fromHex(f.epochSymmetricKey)
  let two = 0
  for (const c of f.cases) {
    const rec = decodeSecret(fromHex(c.record ?? f.record))
    const got = reason(() => readAsMember(rec, fromHex(c.ciphertext), sym))
    assert.equal(got === 'ok' ? 'opens' : got, c.verdict, c.label)
    if (c.faults.length === 2) two++
  }
  assert.ok(two >= 4)
  const s = f.segments
  const k = fromHex(s.key)
  checkScalar(k)
  assert.equal(hex(symmetricKey(k)), s.symmetricKey)
  assert.equal(hex(seal(k, fromHex(s.salt), s.segment, fromHex(s.plaintext))), s.ciphertext)
  assert.equal(hex(openSegments(k, fromHex(s.salt), s.segment, fromHex(s.ciphertext))), s.plaintext)
  assert.equal(reason(() => openSegments(k, fromHex(s.salt), s.segment, fromHex(s.swapped.ciphertext))), s.swapped.verdict)
  for (const l of f.lengths) {
    const got = reason(() => plainLength(l.length, l.segment))
    assert.equal(got === 'ok' ? 'accepted' : got, l.verdict, `length ${l.length}`)
    if (got === 'ok') {
      assert.equal(plainLength(l.length, l.segment), l.plaintext)
      assert.equal(cipherLength(l.plaintext, l.segment), l.length)
    }
  }
})

// ---- transactions ----

const txFile = load('transaction-v1.json')
const roots = new Map<number, string>(txFile.headers.map((h: { height: number; merkleRoot: string }) => [h.height, h.merkleRoot]))
const headers: ChainTracker = { isValidRootForHeight: async (r: string, h: number) => roots.get(h) === r, currentHeight: async () => 0 }

/** An admission in the Go vectors' JSON shape. */
function admits(a: Admission): Record<string, unknown> {
  const j: Record<string, unknown> = { kind: a.kind, outputsToAdmit: a.outputs, coinsToRetain: a.retain }
  if (a.carrier !== undefined) {
    j.commitment = hex(a.carrier.commitment)
    j.record = hex(a.carrier.record)
    j.owner = hex(a.carrier.owner)
    j.contentId = hex(a.carrier.contentId)
    j.fundingTxid = a.carrier.funding.txid
    j.fundingVout = a.carrier.funding.vout
  }
  if (a.token !== undefined) {
    j.seq = a.token.vault.seq
    j.record = hex(a.token.record)
    j.parentTxid = a.parent
    if (a.predecessor !== undefined) j.predecessorSeq = a.predecessor.vault.seq
    j.spends = `${a.spends!.txid}.${a.spends!.vout}`
  }
  if (a.spent !== undefined) j.spent = a.spent.map((o) => `${o.txid}.${o.vout}`)
  return j
}

test('transaction-v1: every case admitted or refused as the Go codec decided', async () => {
  assert.equal(txFile.maxBeef, DefaultMaxBEEF)
  assert.equal(txFile.maxSweepInputs, DefaultMaxSweepInputs)
  assert.ok(txFile.cases.length >= 130)
  const rows: Record<string, number> = {}
  for (const c of txFile.cases) {
    const held = c.previousCoins.map((p: { inputIndex: number }) => p.inputIndex)
    const host = { crypt: txFile.crypt, headers, maxBEEF: txFile.maxBeef, maxSweepInputs: c.maxSweepInputs }
    if (c.verdict === 'refuse') {
      assert.equal(await reasonAsync(() => admit(fromHex(c.beef), held, host)), c.reason, c.name)
      rows[c.rule] = (rows[c.rule] ?? 0) + 1
      // Previous coins decide no verdict.
      assert.equal(await reasonAsync(() => admit(fromHex(c.beef), [], host)), c.reason, `${c.name}, no previous coins`)
      continue
    }
    const a = await admit(fromHex(c.beef), held, host)
    assert.equal(displayTxid(a.txid), c.txid, c.name)
    assert.deepEqual(admits(a), c.admits, c.name)
  }
  assert.deepEqual(rows, txFile.rows)
})

test('transaction-v1: stored tokens read without their parents, walked by spends and replayed', () => {
  let prev: { tx: Transaction; token: VaultToken } | undefined
  for (const s of txFile.stored) {
    const cur = storedToken(fromHex(s.stored))
    assert.equal(cur.tx.id('hex'), s.txid)
    assert.equal(cur.token.vault.seq, s.seq)
    assert.equal(hex(cur.token.record), s.record)
    assert.equal(hex(cur.token.vault.vault), txFile.vault)
    if (prev === undefined) {
      const first = checkFirstToken(cur.tx)
      assert.equal(`${first.spends.txid}.${first.spends.vout}`, s.spends)
    } else {
      checkNextToken(prev.tx, prev.token, cur.tx)
      assert.equal(reason(() => checkFirstToken(cur.tx)), 'token-input')
      assert.equal(hex(tokenBEEF(cur.tx, prev.tx)), s.replayBeef, s.name)
    }
    prev = cur
  }
  assert.equal(txFile.stored.length, 4)
})

test('index-v1: rooted tokens, the fold, outpoint rows and carrier statuses', () => {
  const f = load('index-v1.json')
  const fold = new VaultFold()
  const listings = new Listings()
  const txs: Transaction[] = []
  for (const c of f.chain) {
    const { tx, token } = storedToken(fromHex(c.stored))
    assert.equal(fold.apply(token.vault), c.status)
    assert.equal(fold.setNow().length, c.count)
    assert.equal(fold.stale(), c.stale)
    listings.apply(token.vault)
    txs.push(tx)
  }
  assert.equal(rooted(txs).size, txs.length)
  assert.equal(rooted([...txs].reverse()).size, txs.length)
  assert.equal(rooted(txs.slice(1)).size, 0)
  assert.deepEqual([...rooted([txs[0]!, txs[2]!, txs[3]!])], [txs[0]!.id('hex')])
  const rows = new Map<string, OutpointRow>()
  const row = (o: string): OutpointRow => rows.get(o) ?? rows.set(o, new OutpointRow()).get(o)!
  for (const c of f.carriers) row(c.outpoint).add(fromHex(c.commitment))
  for (const o of f.outpoints) {
    const r = row(o.outpoint)
    assert.equal(r.winner === undefined ? '' : hex(r.winner), o.winner ?? '')
    assert.deepEqual(r.others.map(hex), o.others)
    r.swept = o.swept
  }
  const seen = new Set<string>()
  for (const c of f.carriers) {
    const st = carrierStatus(row(c.outpoint), fromHex(c.commitment), listings, decodeSecret(fromHex(c.record)))
    assert.equal(st, c.status, c.label)
    seen.add(st)
  }
  assert.deepEqual([...seen].sort(), ['listed', 'mismatched', 'retracted', 'superseded', 'unlisted'])
  const dr = new OutpointRow()
  for (const c of f.dropped.added) dr.add(fromHex(c))
  assert.equal(hex(dr.winner!), f.dropped.winner)
  assert.equal(dr.status(fromHex(f.dropped.winner)), undefined)
  dr.dropped = true
  for (const c of f.dropped.afterTheDrop.superseded) assert.equal(dr.status(fromHex(c)), 'superseded')
  dr.add(fromHex(f.dropped.later))
  assert.equal(hex(dr.winner!), f.dropped.afterTheLater.winner)
  for (const c of f.dropped.afterTheLater.superseded) assert.equal(dr.status(fromHex(c)), 'superseded')
  for (const order of [f.bounded.added, [...f.bounded.added].reverse()]) {
    const r = new OutpointRow()
    for (const c of order) r.add(fromHex(c))
    assert.equal(hex(r.winner!), f.bounded.winner)
    assert.deepEqual(r.others.map(hex), f.bounded.others)
    assert.equal(r.more, f.bounded.more)
  }
})
