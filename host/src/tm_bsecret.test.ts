/**
 * tm_bsecret on its own: every golden transaction admitted or refused
 * through the topic manager exactly as the vectors say, every refusal
 * record of refusal-v1.json refused inside a real carrier or token for its
 * reason, a BEEF over the host's bound, a sweep over the host's input
 * bound, a header source that cannot answer, and every refusal label a host
 * counts shown to be reachable.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { P2PKH, PrivateKey, Transaction } from '@bsv/sdk'
import { DefaultMaxBEEF, tokenBEEF } from './admit.js'
import { HeaderTracker } from './headers.js'
import { classify, pushDropScript } from './script.js'
import { KeyChain, KeySecret } from './secrec.js'
import { Chain, OwnerSim, Party, carrier, epochOf, fromNowhere, fundingTree, sweep, token } from './testmint.js'
import { FakeHost, beefOf, byName, heldOf, refusalVectors, tracker, txVectors } from './testutil.js'
import { Reasons, Refused, SecretTopicManager } from './tm_bsecret.js'
import { fromHex } from './util.js'

const v = txVectors()
const seen = new Set<string>()

async function verdict(tm: SecretTopicManager, beef: number[] | Uint8Array, held: number[]): Promise<{ admit?: { outputsToAdmit: number[]; coinsToRetain: number[] }; reason?: string }> {
  try {
    return { admit: await tm.identifyAdmissibleOutputs(Array.from(beef), held) }
  } catch (e) {
    if (!(e instanceof Refused)) throw e
    seen.add(e.reason)
    return { reason: e.reason }
  }
}

test('every transaction vector is admitted or refused, raising, as the vectors say', async () => {
  const host = new FakeHost()
  const headers = tracker(v.headers)
  let admitted = 0
  let refused = 0
  const managers = new Map<number, SecretTopicManager>()
  const distinct = new Map<string, Set<string>>()
  const refusedBy = new Map<string, number>()
  for (const t of v.cases) {
    const bound = t.maxSweepInputs ?? v.maxSweepInputs
    if (!managers.has(bound)) managers.set(bound, new SecretTopicManager(v.topic, host, headers, v.maxBeef, bound))
    const tm = managers.get(bound)!
    const got = await verdict(tm, beefOf(t), heldOf(t))
    if (t.verdict === 'admit') {
      assert.deepEqual(got.admit, { outputsToAdmit: t.admits!.outputsToAdmit, coinsToRetain: t.admits!.coinsToRetain }, t.name)
      admitted++
      const k = `${bound}|${t.admits!.kind}`
      distinct.set(k, (distinct.get(k) ?? new Set()).add(t.txid))
    } else {
      assert.equal(got.reason, t.reason, t.name)
      refused++
      refusedBy.set(t.reason!, (refusedBy.get(t.reason!) ?? 0) + 1)
    }
  }
  assert.deepEqual([v.cases.length, admitted, refused], [139, 21, 118])
  // A txid admitted before in another BEEF is counted once, and once as a
  // repeat. A sweep at its own bound is decided by a second manager, which
  // counts it apart.
  for (const kind of ['secret', 'vault-token', 'sweep']) {
    const want = [...distinct].filter(([k]) => k.endsWith(`|${kind}`)).reduce((n, [, s]) => n + s.size, 0)
    const all = v.cases.filter((t) => t.verdict === 'admit' && t.admits!.kind === kind).length
    assert.equal(host.count('bsecret_admitted_total', { kind }), want, kind)
    assert.equal(host.count('bsecret_admitted_repeats_total', { kind }), all - want, kind)
  }
  assert.deepEqual([host.count('bsecret_admitted_total', { kind: 'secret' }), host.count('bsecret_admitted_total', { kind: 'vault-token' }), host.count('bsecret_admitted_total', { kind: 'sweep' })], [8, 7, 3])
  for (const [reason, n] of refusedBy) assert.equal(host.count('bsecret_refused_total', { reason }), n, reason)
  assert.equal(host.count('bsecret_refused_total', { reason: 'beef' }), 19)
})

/** The vectors' organisation: 32 bytes of 0x51, a public test key. */
const vectorOrg = new Party('vector org', PrivateKey.fromHex('51'.repeat(32)))

test('every refusal record, carried by an otherwise valid carrier or token, is refused for its reason', async () => {
  const chain = new Chain(60000, v.headers)
  const tm = new SecretTopicManager(v.topic, new FakeHost(), chain.tracker)
  const vectors = refusalVectors().filter((r) => r.record !== 'payload')
  assert.ok(vectors.length >= 60)
  const secrets = fundingTree(vectorOrg, KeySecret, vectors.length, chain)
  const chains = fundingTree(vectorOrg, KeyChain, vectors.length, chain)
  const unclaimed: string[] = []
  for (const [i, r] of vectors.entries()) {
    const rec = fromHex(r.hex)
    if (r.record === 'secret') {
      // A record that does not start as a secret record claims nothing: the
      // classifier reads the map head and the magic and no further.
      const claims = classify(pushDropScript(vectorOrg.derived(KeySecret), [rec], new Uint8Array(70))) === 'secret'
      if (!claims) unclaimed.push(r.reason)
      const got = await verdict(tm, (await carrier(secrets, i, vectorOrg, rec)).toAtomicBEEF(), [])
      assert.equal(got.reason, claims ? r.reason : 'not-bsecret', `secret: ${r.label}`)
    } else {
      const tk = await token(vectorOrg, rec, [{ src: chains, vout: i, keyID: KeyChain }])
      chain.mine(tk)
      assert.equal((await verdict(tm, tokenBEEF(tk, chains), [])).reason, r.reason, `vault: ${r.label}`)
    }
  }
  // Only what breaks the map head or the magic fails to claim.
  assert.deepEqual([...new Set(unclaimed)].sort(), ['cbor', 'key-type', 'magic', 'missing', 'too-large'].filter((x) => unclaimed.includes(x)))
})

test('a BEEF over the host bound is refused beef, whatever it carries; bytes that are no BEEF too', async () => {
  const chain = new Chain(61000)
  const owner = new OwnerSim(v.crypt, 'big tree owner', chain, { trees: 6000 })
  // 6000 funding outputs of 49 bytes and more: the carrier's BEEF is over 256 KiB.
  const vault = owner.vault('big', 'example_hall_vkqzmtrwxp', new Uint8Array(16), epochOf('big', 0))
  const beef = (await vault.version('a', 'value')).tx.toAtomicBEEF()
  assert.ok(beef.length > DefaultMaxBEEF)
  const tm = new SecretTopicManager(v.topic, new FakeHost(), chain.tracker)
  assert.equal((await verdict(tm, beef, [])).reason, 'beef')
  assert.equal((await verdict(tm, [1, 2, 3], [])).reason, 'beef')
  // The host's own bound may be higher than the floor: the same carrier is then admitted.
  const wide = new SecretTopicManager(v.topic, new FakeHost(), chain.tracker, 1 << 20)
  assert.deepEqual((await verdict(wide, beef, [])).admit, { outputsToAdmit: [0], coinsToRetain: [] })
})

test('a sweep over the host input bound is refused too-large; a plain payment is not-bsecret', async () => {
  const chain = new Chain(62000)
  const owner = new Party('sweeper')
  const tree = fundingTree(owner, KeySecret, 1025, chain)
  const big = await sweep(tree, Array.from({ length: 1025 }, (_, i) => i), owner, chain)
  const tm = new SecretTopicManager(v.topic, new FakeHost(), chain.tracker)
  assert.equal((await verdict(tm, big.toAtomicBEEF(), [])).reason, 'too-large')
  const payer = new Party('payer')
  const coin = chain.mine(fromNowhere([{ satoshis: 5000, lockingScript: new P2PKH().lock(payer.key.toAddress()) }]))
  const plain = new Transaction(1, [{ sourceTransaction: coin, sourceOutputIndex: 0, unlockingScriptTemplate: new P2PKH().unlock(payer.key), sequence: 0xffffffff }], [{ satoshis: 4000, lockingScript: new P2PKH().lock(owner.key.toAddress()) }], 0)
  await plain.sign()
  assert.equal((await verdict(tm, plain.toAtomicBEEF(), [])).reason, 'not-bsecret')
})

test('a header source that cannot answer refuses a token unmined, raising, so it is decided again later', async () => {
  const host = new FakeHost()
  const tm = new SecretTopicManager(v.topic, host, new HeaderTracker('http://127.0.0.1:9', 500))
  const t = byName(v, 'vault-token-create')
  assert.equal((await verdict(tm, beefOf(t), heldOf(t))).reason, 'unmined')
  assert.equal(host.count('bsecret_refused_total', { reason: 'unmined' }), 1)
  const ok = new SecretTopicManager(v.topic, host, tracker(v.headers))
  assert.deepEqual((await verdict(ok, beefOf(t), heldOf(t))).admit, { outputsToAdmit: [0], coinsToRetain: [] })
})

test('admission reads no other record: a carrier of a vault nobody made, and a token before its predecessor, are admitted on their own bytes', async () => {
  const chain = new Chain(63000)
  const tm = new SecretTopicManager(v.topic, new FakeHost(), chain.tracker)
  const owner = new OwnerSim(v.crypt, 'alone', chain)
  const vault = owner.vault('alone', 'example_hall_vkqzmtrwxp', new Uint8Array(16), epochOf('alone', 0))
  const a = await vault.version('a', 'one')
  // The carrier before any token of its vault, under an epoch no group began.
  assert.deepEqual((await verdict(tm, a.tx.toAtomicBEEF(), [])).admit, { outputsToAdmit: [0], coinsToRetain: [] })
  const t0 = await vault.token({ create: [a] })
  const t1 = await vault.token({ update: [await vault.version('a', 'two')] })
  // seq 1 first, with no previous coin: the manager holds nothing and asks for nothing.
  assert.deepEqual((await verdict(tm, t1.beef, [])).admit, { outputsToAdmit: [0], coinsToRetain: [] })
  assert.deepEqual((await verdict(tm, t0.beef, [])).admit, { outputsToAdmit: [0], coinsToRetain: [] })
  assert.deepEqual(await tm.identifyNeededInputs(), [])
})

test('every refusal label a host counts is reachable, and each has a test above', () => {
  assert.deepEqual(Reasons.filter((r) => !seen.has(r)), [])
})

test('the manager needs no inputs, documents itself, and refuses a topic that is not a crypt', async () => {
  const tm = new SecretTopicManager(v.topic, new FakeHost(), tracker(v.headers))
  assert.equal(tm.crypt, v.crypt)
  assert.deepEqual(await tm.identifyNeededInputs(), [])
  assert.match(await tm.getDocumentation(), /raised/)
  assert.deepEqual(await tm.getMetaData(), { name: v.topic, shortDescription: `Admits the bsecret crypt ${v.crypt}.` })
  assert.throws(() => new SecretTopicManager('tm_other_x_abcdefghij', new FakeHost(), tracker(v.headers)))
  assert.throws(() => new SecretTopicManager('tm_bsecret_Bad_abcdefghij', new FakeHost(), tracker(v.headers)))
  assert.throws(() => new SecretTopicManager(v.topic, new FakeHost(), tracker(v.headers), 0))
})

test('an admission is counted once per transaction; a repeat the engine lets through is counted apart', async () => {
  const host = new FakeHost()
  const tm = new SecretTopicManager(v.topic, host, tracker(v.headers))
  const s = byName(v, 'sweep')
  for (let i = 0; i < 3; i++) await verdict(tm, beefOf(s), heldOf(s))
  assert.equal(host.count('bsecret_admitted_total', { kind: 'sweep' }), 1)
  assert.equal(host.count('bsecret_admitted_repeats_total', { kind: 'sweep' }), 2)
})
