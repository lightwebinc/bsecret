/**
 * The module inside the real overlay engine (the upstream release the
 * reference host's engine is a one-patch fork of, at the same version),
 * over an in-memory store: what the engine records for a refusal, the
 * suppression attacks spec section 11.1 guards against, a token refused
 * while the host's headers lag and admitted once they catch up, every golden
 * transaction, every lookup class hydrated by the engine, restore from the
 * engine's own storage in any order, and a sibling host filled by replay
 * from what the first one stores.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Transaction } from '@bsv/sdk'
import { storedToken, tokenBEEF } from './admit.js'
import { checkInSet } from './chain.js'
import { MemoryJournal } from './journal.js'
import type { SecretLookupService } from './ls_bsecret.js'
import { decodeContext } from './merkle.js'
import { secretModule } from './module.js'
import { firstPush } from './script.js'
import { LookupService, decodeSecret, decodeVault, secretID } from './secrec.js'
import { answer, config, crypt, outputs, setup, submit, topic } from './testhost.js'
import { Chain, OwnerSim, cHex, epochOf, sweep } from './testmint.js'
import { FakeHost, MemoryStorage, beefOf, byName, readVectors, txVectors } from './testutil.js'
import { displayTxid, fromHex, hashOrder, toHex } from './util.js'

const v = txVectors()
const hall = 'example_hall_vkqzmtrwxp'
const group = fromHex('406504d3fbe1ae098f09a49dffa12222')

const applied = (s: MemoryStorage, txid: string): Promise<boolean> => s.doesAppliedTransactionExist({ txid, topic })
const id = (n: string): string => byName(v, n).txid
const org = byName(v, 'secret-carrier-api-token-v1').admits!.owner!
const sid = (name: string): string => toHex(secretID(fromHex(v.vault), name))

test('suppression: a manager that records refusals loses a genuine carrier, token and sweep to a copy in a worse BEEF; tm_bsecret does not', async () => {
  for (const [worseName, genuineName] of [
    ['carrier-beef-tree-unproven', 'secret-carrier-api-token-v1'],
    ['token-alone', 'vault-token-settle'],
    ['token-parent-txid-only', 'vault-token-settle'],
    ['token-atomic-beef', 'vault-token-update'],
  ]) {
    const worse = byName(v, worseName!)
    const genuine = byName(v, genuineName!)
    assert.equal(worse.txid, genuine.txid)
    const naive = await setup({ naive: true })
    assert.deepEqual(await submit(naive.engine, beefOf(worse)), [])
    assert.ok(await applied(naive.storage, genuine.txid), `${worseName}: the refusal is recorded as applied`)
    const before = naive.calls()
    assert.deepEqual(await submit(naive.engine, beefOf(genuine)), [])
    assert.equal(naive.calls(), before, `${worseName}: the genuine object is a duplicate the manager never sees`)

    const real = await setup()
    assert.deepEqual(await submit(real.engine, beefOf(worse)), [], `${worseName}: raised, nothing admitted`)
    assert.equal(await applied(real.storage, genuine.txid), false, `${worseName}: nothing recorded`)
    assert.equal(real.host.count('bsecret_refused_total', { reason: 'beef' }), 1)
    assert.deepEqual(await submit(real.engine, beefOf(genuine)), [genuine.admits!.outputsToAdmit[0]!], `${worseName}: the genuine object is admitted`)
  }
})

test("a token whose parent's block the host's headers lack is refused without a trace, and admitted once they catch up", async () => {
  const chain = new Chain(71000)
  const owner = new OwnerSim(crypt, 'lagging owner', chain)
  const vault = owner.vault('lag', hall, group, epochOf('lag', 0))
  const t0 = await vault.token()
  const t1 = await vault.token({ create: [await vault.version('a', 'one')] })
  // The host's headers: everything but the block of seq 0, the parent of seq 1.
  const height = t0.tx.merklePath!.blockHeight
  const root = chain.roots.get(height)!
  const s = await setup({ chain })
  chain.orphan(height)
  assert.deepEqual(await submit(s.engine, t1.beef), [], 'refused unmined')
  assert.equal(s.host.count('bsecret_refused_total', { reason: 'unmined' }), 1)
  assert.equal(await applied(s.storage, t1.tx.id('hex')), false)
  chain.roots.set(height, root)
  assert.deepEqual(await submit(s.engine, t1.beef), [0], 'decided again and admitted')
  assert.equal(s.ls.tokenStatus(t1.tx.id('hex')), 'pending', 'its predecessor is not held')
  assert.deepEqual(await answer(s.engine, { crypt, org: owner.hex, vault: vault.idHex }), [], 'a pending token is not the latest')
  assert.deepEqual(await submit(s.engine, t0.beef), [0])
  assert.equal(s.ls.tokenStatus(t1.tx.id('hex')), 'consistent')
  assert.deepEqual(await answer(s.engine, { crypt, org: owner.hex, vault: vault.idHex }), [t1.tx.id('hex')])
})

test('every transaction vector through the engine: admitted as the vectors say, nothing refused recorded, and every lookup class answers them', async () => {
  const { engine: e, storage, ls, host } = await setup()
  const admitted = new Set(v.cases.filter((t) => t.verdict === 'admit').map((t) => t.txid))
  const engineRefused: string[] = []
  for (const t of v.cases) {
    const got = await submit(e, beefOf(t))
    if (got === undefined) {
      // The engine's own SPV refuses before any manager runs: a proof at a
      // height its headers do not hold, a script its interpreter refuses.
      assert.equal(t.verdict, 'refuse', t.name)
      engineRefused.push(t.name)
    }
    if (t.verdict === 'admit') {
      assert.ok(await applied(storage, t.txid), t.name)
    } else if (!admitted.has(t.txid)) {
      assert.deepEqual(got ?? [], [], t.name)
      assert.equal(await applied(storage, t.txid), false, t.name)
    }
  }
  assert.equal(v.cases.length, 139)
  assert.ok(engineRefused.length > 0)

  // The index, against what the Go codec computed from the same objects (index-v1.json).
  const index = readVectors<{ carriers: Array<{ label: string; commitment: string; status: string }>; chain: Array<{ txid: string; status: string }>; outpoints: Array<{ outpoint: string; winner?: string; others: string[]; more: number; dropped: boolean; swept: boolean }> }>('index-v1.json')
  for (const t of index.chain) assert.deepEqual([ls.tokenStatus(t.txid), ls.rooted(t.txid)], [t.status, true], t.txid)
  let checked = 0
  for (const k of index.carriers) {
    if (!ls.holds(k.commitment)) continue
    assert.equal(await ls.status(k.commitment), k.status, k.label)
    checked++
  }
  assert.equal(checked, 8, 'every carrier the transaction vectors hold')
  for (const o of index.outpoints) {
    const r = ls.outpointRow(o.outpoint)
    if (r === undefined) continue
    assert.deepEqual([r.winner, r.others, r.more, r.dropped, r.sweeps.length > 0], [o.winner ?? '', o.others, o.more, o.dropped, o.swept], o.outpoint)
  }
  // The token built on a parent that was never admissible is held, and never rooted.
  assert.deepEqual([ls.tokenStatus(id('vault-token-on-unadmitted-parent')), ls.rooted(id('vault-token-on-unadmitted-parent'))], ['pending', false])
  assert.equal(host.count('bsecret_token_status_total', { status: 'consistent' }), 6)
  assert.equal(host.count('bsecret_token_status_total', { status: 'pending' }), 1)
  assert.equal(host.gauges.get('bsecret_tokens_pending')!(), 1)

  // Every class, hydrated by the engine. Two rooted tokens share seq 3 (the
  // token and a copy that also spends its parent's change): both are latest.
  const tip = [id('vault-token-settle'), id('vault-token-spends-parent-change-too')].sort()
  const q = { crypt, org, vault: v.vault }
  assert.deepEqual(await answer(e, q), tip)
  assert.deepEqual(await answer(e, { ...q, seq: '0' }), [id('vault-token-create')])
  assert.deepEqual(await answer(e, { ...q, seq: '8' }), [id('vault-token-on-unadmitted-parent')], 'a token that is not rooted is answered by vault-seq alone')
  const second = toHex(decodeVault(fromHex(byName(v, 'vault-token-second-vault').admits!.record!)).vault)
  const both = [second, v.vault].sort()
  const latestOf = (vault: string): string[] => (vault === second ? [id('vault-token-second-vault')] : tip)
  assert.deepEqual(await answer(e, { crypt, vaultsOf: org }), both.flatMap(latestOf))
  assert.deepEqual(await answer(e, { crypt, vaultsOf: org, after: both[0]! }), latestOf(both[1]!))
  assert.deepEqual(await answer(e, { crypt, vaultsOf: org, after: both[1]! }), [])

  // secret: the version the set holds, with a context a reader's first check accepts.
  const api = await outputs(e, { ...q, secret: sid('tx/api-token') })
  assert.deepEqual(api.map((o) => o.txid), [id('secret-carrier-api-token-v3')])
  const ctx = decodeContext(Uint8Array.from(api[0]!.context!))
  assert.deepEqual([ctx.seq, displayTxid(ctx.token), ctx.size], [3, tip[0], 2], 'of two rooted tokens that both verify, the lowest txid')
  const latest = decodeVault(fromHex(byName(v, 'vault-token-settle').admits!.record!))
  const rec = decodeSecret(firstPush(Uint8Array.from(api[0]!.tx.outputs[0]!.lockingScript.toBinary()))!)
  checkInSet(latest, hashOrder(tip[0]!), rec, ctx)
  assert.deepEqual(await answer(e, { ...q, secret: sid('tx/tls-key') }), [], 'retired: the set does not hold it')
  assert.deepEqual(await answer(e, { ...q, secret: sid('tx/ssh-key') }), [], 'never listed')

  // version: listed, unlisted and mismatched carriers; never a superseded or a retracted one.
  // Two carriers share api-token v1's outpoint; the lower txid wins it.
  const apiV1 = [id('secret-carrier-api-token-v1'), id('carrier-locktime-max')].sort()[0]!
  assert.deepEqual(await answer(e, { ...q, secret: sid('tx/api-token'), version: '1' }), [apiV1], "the outpoint's winner, not the carrier it superseded")
  assert.deepEqual(await answer(e, { ...q, secret: sid('tx/db-password'), version: '1' }), [], 'its funding outpoint was swept')
  assert.deepEqual(await answer(e, { ...q, secret: sid('tx/tls-key'), version: '1' }), [id('secret-carrier-tls-key-v1')], 'retired, still held')
  assert.deepEqual(await answer(e, { ...q, secret: sid('tx/ssh-key'), version: '1' }), [id('secret-carrier-ssh-key-v1')])
  assert.deepEqual(await answer(e, { ...q, pending: sid('tx/ssh-key') }), [id('secret-carrier-ssh-key-v1')])
  assert.deepEqual(await answer(e, { ...q, pending: sid('tx/api-token') }), [], 'nothing above the listed version')

  // secrets and label: the set, ascending by identifier, each with its path.
  const set = [
    [sid('tx/api-token'), id('secret-carrier-api-token-v3')],
    [sid('tx/db-password'), id('secret-carrier-db-password-v2')],
  ].sort(([a], [b]) => (a! < b! ? -1 : 1))
  const all = await outputs(e, { crypt, org, secretsOf: v.vault })
  assert.deepEqual(all.map((o) => o.txid), set.map(([, txid]) => txid))
  for (const o of all) {
    const r = decodeSecret(firstPush(Uint8Array.from(o.tx.outputs[0]!.lockingScript.toBinary()))!)
    checkInSet(latest, hashOrder(tip[0]!), r, decodeContext(Uint8Array.from(o.context!)))
  }
  assert.deepEqual(await answer(e, { crypt, org, secretsOf: v.vault, after: set[0]![0]! }), [set[1]![1]])
  assert.deepEqual(await answer(e, { crypt, org, secretsOf: v.vault, after: set[1]![0]! }), [])
  const labels = new Map(all.map((o) => [o.txid, decodeSecret(firstPush(Uint8Array.from(o.tx.outputs[0]!.lockingScript.toBinary()))!).label]))
  for (const label of new Set(labels.values())) {
    assert.deepEqual(await answer(e, { ...q, label }), set.map(([, txid]) => txid!).filter((txid) => labels.get(txid) === label), label)
  }
  assert.deepEqual(await answer(e, { ...q, label: 'no-such-label' }), [])
  assert.deepEqual(await answer(e, { ...q, label: labels.get(set[0]![1]!)!, after: set[1]![0]! }), [])

  // sweep: a row's spend, a spend still in the bounded table, and one of an outpoint nothing used.
  const spent = byName(v, 'sweep').admits!.spent!
  assert.deepEqual(await answer(e, { crypt, spent: spent[0]! }), [id('sweep')])
  assert.deepEqual(await answer(e, { crypt, spent: spent[1]! }), [id('sweep')])
  assert.deepEqual(await answer(e, { crypt, spent: byName(v, 'funding-tree-alone').admits!.spent![0]! }), [id('funding-tree-alone')])
  assert.deepEqual(await answer(e, { crypt, spent: `${'00'.repeat(32)}.0` }), [])

  // history and audit are free on a host that prices nothing.
  const h = { crypt, history: org, vault: v.vault, secret: sid('tx/api-token') }
  assert.deepEqual(await answer(e, h), [apiV1, id('secret-carrier-api-token-v2'), id('secret-carrier-api-token-v3')])
  assert.deepEqual(await answer(e, { ...h, after: '1' }), [id('secret-carrier-api-token-v2'), id('secret-carrier-api-token-v3')])
  assert.deepEqual(await answer(e, { ...h, after: '3' }), [])
  const a = { crypt, audit: org, vault: v.vault }
  const trail = [id('vault-token-create'), id('vault-token-update'), id('vault-token-rekey-same-block'), ...tip]
  assert.deepEqual(await answer(e, a), trail, 'the rooted chain, by seq then txid: never the token on the unadmitted parent')
  assert.deepEqual(await answer(e, { ...a, after: '1' }), trail.slice(2))
  assert.deepEqual(await answer(e, { ...a, after: '3' }), [])
  // A question that is not exactly one class, or of a crypt the host does not carry, is an error.
  await assert.rejects(e.lookup({ service: LookupService, query: { ...q, extra: 'x' } }), /refused/)
  await assert.rejects(e.lookup({ service: LookupService, query: { crypt: 'other_crypt_abcdefghij', vaultsOf: org } }), /does not carry/)
  for (const cls of ['vault', 'vault-seq', 'vaults', 'vaults-after', 'secret', 'version', 'pending', 'secrets', 'secrets-after', 'label', 'label-after', 'sweep', 'history', 'history-after', 'audit', 'audit-after']) {
    assert.ok(host.count('bsecret_lookups_total', { class: cls }) > 0, `${cls} was asked`)
  }
})

/** The questions a scenario asks, with the statuses it holds. */
async function snapshot(ls: SecretLookupService, questions: Array<Record<string, unknown>>, carriers: string[], tokens: string[]) {
  const answers = []
  for (const q of questions) answers.push(await ls.lookup({ service: LookupService, query: q }))
  const statuses = []
  for (const k of carriers) statuses.push(await ls.status(k))
  return { answers, carriers: statuses, tokens: tokens.map((t) => `${ls.tokenStatus(t)} ${ls.rooted(t)}`) }
}

test('restore from the engine storage reaches the same answers and statuses whatever order the rows come in, with or without their BEEF or the token rows', async () => {
  const chain = new Chain(72000, v.headers)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'restore owner', chain)
  const [e0, e1] = [epochOf('restore', 0), epochOf('restore', 1)]
  const vault = owner.vault('restore vault', hall, group, e0)
  const a1 = await vault.version('a', 'a one')
  const b1 = await vault.version('b', 'b one', { label: 'confidential' })
  const t0 = await vault.token({ create: [a1, b1] })
  const a2 = await vault.version('a', 'a two')
  const t1 = await vault.token({ update: [a2] })
  const t2 = await vault.token({ epoch: e1 })
  const a3 = await vault.version('a', 'a three')
  const b2 = await vault.version('b', 'b two', { label: 'confidential' })
  const t3 = await vault.token({ update: [a3, b2] })
  const c1 = await vault.version('c', 'c one, never listed')
  // A second carrier on a1's funding output: version 1 again, with other content.
  vault.last.delete('a')
  const twin = await vault.version('a', 'a second carrier on one funding output', { vout: a1.vout })
  vault.last.set('a', a3)
  const sw = await sweep(owner.secretTree, [b1.vout], owner.party, chain)
  // In order, so each token spends a held one and the engine keeps it as a spent output.
  for (const m of [t0, t1]) assert.deepEqual(await submit(s.engine, m.beef), [0])
  for (const x of [a1, b1, a2, a3, b2, c1, twin]) assert.deepEqual(await submit(s.engine, x.tx.toAtomicBEEF()), [0])
  // The last two tokens, the latest first: pending until its parent arrives.
  assert.deepEqual(await submit(s.engine, t3.beef), [0])
  assert.equal(s.ls.tokenStatus(t3.tx.id('hex')), 'pending')
  assert.deepEqual(await submit(s.engine, t2.beef), [0])
  assert.equal(s.ls.tokenStatus(t3.tx.id('hex')), 'consistent')
  assert.deepEqual(await submit(s.engine, sw.toAtomicBEEF()), [0])
  assert.deepEqual(await submit(s.engine, beefOf(byName(v, 'funding-tree-alone'))), [0], 'an unmatched spend, in the bounded table')

  const q = { crypt, org: owner.hex, vault: vault.idHex }
  const questions: Array<Record<string, unknown>> = [
    q,
    { ...q, seq: '1' },
    { crypt, vaultsOf: owner.hex },
    { ...q, secret: vault.secret('a') },
    { ...q, secret: vault.secret('a'), version: '1' },
    { ...q, secret: vault.secret('b'), version: '1' },
    { ...q, pending: vault.secret('c') },
    { crypt, org: owner.hex, secretsOf: vault.idHex },
    { ...q, label: 'confidential' },
    { crypt, spent: `${owner.secretTree.id('hex')}.${b1.vout}` },
    { crypt, history: owner.hex, vault: vault.idHex, secret: vault.secret('a') },
    { crypt, audit: owner.hex, vault: vault.idHex },
    { crypt, spent: byName(v, 'funding-tree-alone').admits!.spent![0]! },
  ]
  const carriers = [a1, b1, a2, a3, b2, c1, twin].map((x) => cHex(x.tx))
  const tokens = [t0, t1, t2, t3].map((m) => m.tx.id('hex'))
  const want = await snapshot(s.ls, questions, carriers, tokens)
  assert.deepEqual(want.tokens, Array(4).fill('consistent true'))
  const lower = cHex(a1.tx) < cHex(twin.tx)
  assert.deepEqual(want.carriers, [lower ? 'listed' : 'superseded', 'retracted', 'listed', 'listed', 'listed', 'unlisted', lower ? 'superseded' : 'mismatched'])
  assert.deepEqual(want.answers[3]!.map((f) => f.txid), [a3.tx.id('hex')])
  assert.deepEqual(want.answers[5], [], 'b version 1 was swept')
  assert.equal(want.answers[11]!.length, 4)

  const rows = await s.storage.findUTXOsForTopic(topic, undefined, undefined, true)
  assert.ok(!rows.some((o) => o.txid === t0.tx.id('hex')), 'a token its successor spent is not among the unspent rows')
  const bare = rows.map((o) => ({ ...o, beef: undefined }))
  const noTokens = new MemoryJournal()
  for (const l of s.journal.lines) if (l.k !== 't') noTokens.append(l)
  for (const [label, order, journal] of [
    ['as stored', rows, s.journal],
    ['reversed', [...rows].reverse(), s.journal],
    ['without BEEF', bare, s.journal],
    ['nothing handed over', [], s.journal],
    ['without the token rows: walked back through the stored tokens', rows, noTokens],
  ] as const) {
    const host = new FakeHost()
    const again = secretModule(host, config, [topic], journal, chain.tracker).ls
    assert.ok((await again.restore(order as never, s.storage)) > 0, label)
    const got = await snapshot(again, questions, carriers, tokens)
    if (order.length === 0) {
      // The bounded table is rebuilt from the tombstones the host hands
      // over and is never journaled, so a restore handed nothing has no
      // unmatched spends; everything the journal names is read back.
      assert.deepEqual(got.answers.pop(), [], label)
      assert.deepEqual(got, { ...want, answers: want.answers.slice(0, -1) }, label)
      continue
    }
    assert.deepEqual(got, want, label)
    assert.equal(host.count('bsecret_token_status_total', { status: 'consistent' }), 4, label)
    assert.equal(host.count('bsecret_token_status_total', { status: 'pending' }), 0, `${label}: folded once every token is read`)
  }
})

test('a sibling host is filled by replay: each token read as the first host stores it, alone, and its BEEF rebuilt with the token before it', async () => {
  const chain = new Chain(73000, v.headers)
  const first = await setup({ chain })
  const owner = new OwnerSim(crypt, 'replay owner', chain)
  const vault = owner.vault('replay vault', hall, group, epochOf('replay', 0))
  const a1 = await vault.version('a', 'one')
  await vault.token({ create: [a1] })
  await vault.token({ update: [await vault.version('a', 'two')] })
  await vault.token({ retire: ['a'] })
  for (const m of vault.history) assert.deepEqual(await submit(first.engine, m.beef), [0])
  // What the first host answers is the token alone with its proof.
  const stored: Transaction[] = []
  for (let seq = 0; seq < 3; seq++) {
    const a = await outputs(first.engine, { crypt, org: owner.hex, vault: vault.idHex, seq: String(seq) })
    const { tx, token } = storedToken(Uint8Array.from(a[0]!.beef))
    assert.deepEqual([tx.id('hex'), token.vault.seq], [vault.history[seq]!.tx.id('hex'), seq])
    assert.equal(tx.inputs[0]!.sourceTransaction, undefined, 'stored without its parent')
    stored.push(tx)
  }
  const second = await setup({ chain })
  // Any order: the latest first, each pending until its parent arrives.
  assert.deepEqual(await submit(second.engine, tokenBEEF(stored[2]!, stored[1]!)), [0])
  assert.deepEqual(await submit(second.engine, tokenBEEF(stored[1]!, stored[0]!)), [0])
  assert.equal(second.ls.tokenStatus(stored[2]!.id('hex')), 'pending')
  assert.deepEqual(toHex(tokenBEEF(stored[2]!, stored[1]!)), toHex(vault.history[2]!.beef), 'the BEEF the publisher made, byte for byte')
  // At seq 0 the parent is the chain tree, which no host keeps: from the publisher.
  assert.deepEqual(await submit(second.engine, tokenBEEF(stored[0]!, owner.chainTree)), [0])
  assert.equal(second.ls.tokenStatus(stored[2]!.id('hex')), 'consistent')
  for (const q of [{ crypt, org: owner.hex, vault: vault.idHex }, { crypt, audit: owner.hex, vault: vault.idHex }]) {
    assert.deepEqual(await answer(second.engine, q), await answer(first.engine, q))
  }
  // A restart of the sibling folds the same chain from its own parentless storage.
  const again = secretModule(new FakeHost(), config, [topic], second.journal, chain.tracker).ls
  await again.restore(await second.storage.findUTXOsForTopic(topic, undefined, undefined, true), second.storage)
  assert.deepEqual(stored.map((t) => again.tokenStatus(t.id('hex'))), ['consistent', 'consistent', 'consistent'])
})

test('one answered carrier per funding outpoint: the lowest commitment wins, eight others are kept as evidence, and the rest are dropped, deleted and never restored', async () => {
  const chain = new Chain(74000, v.headers)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'evidence owner', chain)
  const vault = owner.vault('evidence vault', hall, group, epochOf('evidence', 0))
  const vout = owner.nextSecretVout()
  // Twelve carriers on one funding output: the owner equivocated.
  const many: Transaction[] = []
  for (let i = 0; i < 12; i++) {
    vault.last.delete('a')
    many.push((await vault.version('a', `value ${i}`, { vout })).tx)
  }
  for (const x of many) assert.deepEqual(await submit(s.engine, x.toAtomicBEEF()), [0])
  const sorted = [...many].sort((a, b) => (cHex(a) < cHex(b) ? -1 : 1))
  const q = { crypt, org: owner.hex, vault: vault.idHex, secret: vault.secret('a'), version: '1' }
  assert.deepEqual(await answer(s.engine, q), [sorted[0]!.id('hex')], 'one answered carrier per funding output')
  const op = `${owner.secretTree.id('hex')}.${vout}`
  assert.deepEqual(s.ls.outpointRow(op), { winner: cHex(sorted[0]!), others: sorted.slice(1, 9).map(cHex), more: 3, dropped: false, sweeps: [] })
  // The winner and eight superseded are kept; the other three were dropped and deleted.
  await s.ls.flush()
  for (const x of sorted.slice(9)) assert.equal(await s.storage.findOutput(x.id('hex'), 0, topic), null)
  for (const x of sorted.slice(0, 9)) assert.notEqual(await s.storage.findOutput(x.id('hex'), 0, topic), null)
  assert.equal(s.ls.carrierCount, 9)
  assert.equal(s.host.count('bsecret_dropped_total', { why: 'evidence' }), 3)
  assert.equal(s.host.count('bsecret_equivocations_total'), 11)
  assert.deepEqual(await submit(s.engine, sorted[11]!.toAtomicBEEF()), [], 'offered again, a dropped carrier is a duplicate')
  // A carrier the row turned away is journaled as a count, without its commitment.
  const kept = new Set(sorted.slice(0, 9).map(cHex))
  const lines = s.journal.lines.filter((l) => l.k === 'c' || l.k === 'm')
  assert.equal(lines.length, 12)
  assert.ok(lines.filter((l) => l.k === 'c').length >= 9)
  const again = secretModule(new FakeHost(), config, [topic], s.journal, chain.tracker).ls
  await again.restore(await s.storage.findUTXOsForTopic(topic, undefined, undefined, true), s.storage)
  assert.equal(again.carrierCount, 9)
  assert.deepEqual(again.outpointRow(op), s.ls.outpointRow(op), 'the same row, whatever was dropped')
  assert.ok([...kept].every((k) => again.holds(k)))
  assert.deepEqual((await again.lookup({ service: LookupService, query: q })).map((f) => f.txid), [sorted[0]!.id('hex')])
})
