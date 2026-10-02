/**
 * Defects a review of the index proved against the running module, each
 * pinned here with the sequence that showed it: what a restart must not
 * lose, what arrival order must not decide, and what a row must not count
 * twice.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { Output } from '@lightwebinc/bcommon'
import { tokenBEEF } from './admit.js'
import { MemoryJournal } from './journal.js'
import { secretModule } from './module.js'
import { parseQuery } from './query.js'
import { KeyChain, KeyVault, LookupService, encodeVault, reasonOf } from './secrec.js'
import { answer, config, crypt, setup, submit, topic, type Rig } from './testhost.js'
import { Chain, OwnerSim, cHex, carrier, epochOf, sweep, token, type Version } from './testmint.js'
import { FakeHost, MemoryStorage } from './testutil.js'
import { fromHex, hashOrder } from './util.js'

const hall = 'example_hall_vkqzmtrwxp'
const group = fromHex('406504d3fbe1ae098f09a49dffa12222')

async function restored(s: Rig, chain: Chain, journal = s.journal) {
  const ls = secretModule(new FakeHost(), config, [topic], journal, chain.tracker).ls
  await ls.restore(await s.storage.findUTXOsForTopic(topic, undefined, undefined, true), s.storage)
  return ls
}

/** Twelve carriers on one funding output, lowest commitment first. */
async function equivocations(owner: OwnerSim, label: string, n = 12): Promise<{ all: Version[]; op: string }> {
  const vault = owner.vault(label, hall, group, epochOf(label, 0))
  const first = await vault.version('a', 'one')
  const all = [first]
  for (let i = 1; i < n; i++) {
    vault.last.delete('a')
    all.push(await vault.version('a', `equivocation ${i}`, { vout: first.vout }))
  }
  all.sort((x, y) => (cHex(x.tx) < cHex(y.tx) ? -1 : 1))
  return { all, op: `${owner.secretTree.id('hex')}.${first.vout}` }
}

test('a sweep that waits in the table still retracts after a restart, although a later transaction spent its tombstone', async () => {
  const chain = new Chain(93000)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'sweep owner', chain)
  const vault = owner.vault('sweeps', hall, group, epochOf('sweeps', 0))
  const a1 = await vault.version('a', 'swept before it is published here')
  const op = `${owner.secretTree.id('hex')}.${a1.vout}`
  // The sweep arrives before the carrier it retracts, and waits in the table.
  const s1 = await sweep(owner.secretTree, [a1.vout], owner.party, chain)
  assert.deepEqual(await submit(s.engine, s1.toAtomicBEEF()), [0])
  // The owner funds its next carrier from the sweep's output: storage now holds the tombstone as spent.
  const b1 = await vault.version('b', 'one')
  assert.deepEqual(await submit(s.engine, (await carrier(s1, 0, owner.party, b1.record)).toAtomicBEEF()), [0])
  assert.equal((await s.storage.findUTXOsForTopic(topic)).some((o) => o.txid === s1.id('hex')), false, 'not among the unspent rows a restore is handed')
  const again = await restored(s, chain)
  assert.deepEqual([again.tableSize, again.sweepCount], [s.ls.tableSize, s.ls.sweepCount], 'the table is the same after a restart')
  assert.deepEqual((await again.lookup({ service: LookupService, query: { crypt, spent: op } })).map((f) => f.txid), [s1.id('hex')])
  // The retracted carrier arrives afterwards, at the live host and at the restored one.
  assert.deepEqual(await submit(s.engine, a1.tx.toAtomicBEEF()), [0])
  await again.outputAdmittedByTopic({ mode: 'whole-tx', topic, atomicBEEF: a1.tx.toAtomicBEEF(), outputIndex: 0 })
  assert.deepEqual([await s.ls.status(cHex(a1.tx)), await again.status(cHex(a1.tx))], ['retracted', 'retracted'])
  assert.deepEqual(await again.lookup({ service: LookupService, query: { crypt, org: owner.hex, vault: vault.idHex, secret: vault.secret('a'), version: '1' } }), [])
})

test('a token turned away from a full seq while it was pending is read again once its predecessor is rooted', async () => {
  const chain = new Chain(92000)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'bound owner', chain, { chains: 400 })
  const vault = owner.vault('bound', hall, group, epochOf('bound', 0))
  const a1 = await vault.version('a', 'one')
  const t0 = await vault.token({ create: [a1] })
  const t1 = await vault.token({ update: [await vault.version('a', 'two')] })
  const a3 = await vault.version('a', 'three')
  const t2 = await vault.token({ update: [a3] })
  const a4 = await vault.version('a', 'four')
  const t3 = await vault.token({ update: [a4] })
  const id = (m: { tx: { id: (e: 'hex') => string } }): string => m.tx.id('hex')
  // The owner's own rootless tokens at seq 2, each on a parent no host admits, until eight have a txid below the real one's.
  const rogues: Array<{ beef: Uint8Array; txid: string }> = []
  for (let n = 0; rogues.filter((r) => r.txid < id(t2)).length < 8; n++) {
    const pseudo = encodeVault({ ...t1.rec, prev: hashOrder((n + 1).toString(16).padStart(64, '0')), created: t1.rec.created + 1 + n })
    const x = await token(owner.party, pseudo, [{ src: owner.chainTree, vout: owner.nextChainVout(), keyID: KeyChain }])
    chain.mine(x)
    const y = await token(owner.party, encodeVault({ ...t2.rec, prev: Uint8Array.from(x.hash() as number[]), created: t2.rec.created + 1 + n }), [{ src: x, vout: 0, keyID: KeyVault }])
    chain.mine(y)
    rogues.push({ beef: tokenBEEF(y, x), txid: y.id('hex') })
  }
  for (const r of rogues) assert.deepEqual(await submit(s.engine, r.beef), [0])
  for (const x of [a3, a4]) assert.deepEqual(await submit(s.engine, x.tx.toAtomicBEEF()), [0])
  // A replay in any order: the last tokens first.
  assert.deepEqual(await submit(s.engine, t3.beef), [0])
  assert.deepEqual(await submit(s.engine, t2.beef), [0])
  assert.equal(s.ls.tokenStatus(id(t2)), undefined, 'pending, and above eight lower txids: the seq holds no more')
  assert.deepEqual(await submit(s.engine, t0.beef), [0])
  assert.deepEqual(await submit(s.engine, t1.beef), [0])
  // Its predecessor is rooted now: the host reads it back from its own storage, and the chain is whole.
  const q = { crypt, org: owner.hex, vault: vault.idHex }
  assert.deepEqual([s.ls.tokenStatus(id(t2)), s.ls.tokenStatus(id(t3))], ['consistent', 'consistent'])
  assert.deepEqual(await answer(s.engine, q), [id(t3)])
  assert.deepEqual(await answer(s.engine, { ...q, secret: vault.secret('a') }), [a4.tx.id('hex')])
  assert.ok((await answer(s.engine, { ...q, seq: '2' })).includes(id(t2)))
  assert.equal((await answer(s.engine, { ...q, seq: '2' })).length, 8)
  // The same as a host given the chain in order, and as a restart.
  const inOrder = await setup({ chain })
  for (const r of rogues) await submit(inOrder.engine, r.beef)
  for (const t of [t0, t1, t2, t3]) await submit(inOrder.engine, t.beef)
  assert.deepEqual(await answer(inOrder.engine, { ...q, seq: '2' }), await answer(s.engine, { ...q, seq: '2' }))
  const again = await restored(s, chain)
  assert.deepEqual((await again.lookup({ service: LookupService, query: q })).map((f) => f.txid), [id(t3)])
})

test('a member named __proto__ is a member no class defines: refused, never dropped', async () => {
  const s = await setup()
  const q = `{"crypt":"${crypt}","org":"03baf7689c0a3558fb604589036a8d1e4b685d909f6e0e2c6018a14049ae64ec26","vault":"${'ab'.repeat(32)}","__proto__":"x"}`
  for (const form of [q, JSON.parse(q) as unknown]) {
    let got = 'parsed'
    try {
      parseQuery(form)
    } catch (e) {
      got = reasonOf(e)
    }
    assert.equal(got, 'query', typeof form)
  }
  await assert.rejects(s.engine.lookup({ service: LookupService, query: JSON.parse(q) as unknown }), /no class has these members/)
  // The members a question does carry are its own, whatever they are named.
  assert.deepEqual(Object.keys(parseQuery(`{"crypt":"${crypt}","vaultsOf":"03baf7689c0a3558fb604589036a8d1e4b685d909f6e0e2c6018a14049ae64ec26"}`).members).sort(), ['crypt', 'vaultsOf'])
})

test('a sweep admitted in two crypts answers in both', async () => {
  const chain = new Chain(94000)
  const crypt2 = 'other_crypt_abcdefghij'
  const topic2 = `tm_bsecret_${crypt2}`
  const m = secretModule(new FakeHost(), { ...config, crypts: [crypt, crypt2] }, [topic, topic2], new MemoryJournal(), chain.tracker)
  const storage = new MemoryStorage()
  await m.ls.restore([], storage)
  const o1 = new OwnerSim(crypt, 'two crypt owner', chain)
  const o2 = new OwnerSim(crypt2, 'two crypt owner', chain)
  const a = await o1.vault('x', hall, group, epochOf('x', 0)).version('a', 'one')
  // The second crypt's carrier on the same tree: the funding key does not name a crypt.
  const b = await carrier(o1.secretTree, 1, o2.party, (await o2.vault('y', hall, group, epochOf('y', 0)).version('b', 'one')).record)
  const admit = async (t: string, tx: typeof a.tx): Promise<void> => await m.ls.outputAdmittedByTopic({ mode: 'whole-tx', topic: t, atomicBEEF: tx.toAtomicBEEF(), outputIndex: 0 })
  await admit(topic, a.tx)
  await admit(topic2, b)
  const sw = await sweep(o1.secretTree, [0, 1], o1.party, chain)
  await admit(topic, sw)
  await admit(topic2, sw)
  const tree = o1.secretTree.id('hex')
  const asked = async (c: string, op: string): Promise<string[]> => (await m.ls.lookup({ service: LookupService, query: { crypt: c, spent: op } })).map((f) => f.txid)
  assert.deepEqual([await m.ls.status(cHex(a.tx)), await m.ls.status(cHex(b))], ['retracted', 'retracted'])
  assert.deepEqual(await asked(crypt, `${tree}.0`), [sw.id('hex')])
  assert.deepEqual(await asked(crypt2, `${tree}.1`), [sw.id('hex')], 'the crypt whose carrier it retracts')
  assert.equal(m.ls.sweepCount, 1)
  // Dropped from one topic, it still answers in the other.
  m.ls.outputNoLongerRetainedInHistory(sw.id('hex'), 0, topic)
  assert.deepEqual([await asked(crypt, `${tree}.0`), await asked(crypt2, `${tree}.1`)], [[], [sw.id('hex')]])
})

test('a carrier the row turns away is counted once, however many times the engine lets it through', async () => {
  const chain = new Chain(94500)
  const s = await setup({ chain })
  const { all, op } = await equivocations(new OwnerSim(crypt, 'race owner', chain), 'race', 13)
  // A winner and eight others, the lowest of all held back.
  for (const x of all.slice(1, 10)) assert.deepEqual(await submit(s.engine, x.tx.toAtomicBEEF()), [0])
  assert.equal(s.ls.outpointRow(op)!.more, 0)
  // One carrier offered three times at once: all three pass the engine's duplicate check.
  const beef = all[12]!.tx.toAtomicBEEF()
  assert.deepEqual(await Promise.all([submit(s.engine, beef), submit(s.engine, beef), submit(s.engine, beef)]), [[0], [0], [0]])
  assert.equal(s.ls.outpointRow(op)!.more, 1)
  // The lowest arrives: the row stops keeping its highest, which is counted once, a repeat of it included.
  assert.deepEqual(await submit(s.engine, all[0]!.tx.toAtomicBEEF()), [0])
  assert.equal(s.ls.outpointRow(op)!.more, 2)
  assert.equal(s.ls.holds(cHex(all[9]!.tx)), false)
  await s.ls.outputAdmittedByTopic({ mode: 'whole-tx', topic, atomicBEEF: all[9]!.tx.toAtomicBEEF(), outputIndex: 0 })
  assert.equal(s.ls.outpointRow(op)!.more, 2)
  assert.equal(s.journal.lines.filter((l) => l.k === 'm').length, 1)
  assert.equal((await restored(s, chain)).outpointRow(op)!.more, 2, 'and the journal replays to the same count')
})

test('a restart with the journal a line short keeps the lowest commitment storage holds as the winner', async () => {
  const chain = new Chain(97000)
  const s = await setup({ chain })
  const { all, op } = await equivocations(new OwnerSim(crypt, 'short journal owner', chain), 'short')
  // All but the lowest: a winner, eight others, two turned away.
  for (const x of all.slice(1)) assert.deepEqual(await submit(s.engine, x.tx.toAtomicBEEF()), [0])
  assert.equal(s.ls.outpointRow(op)!.more, 2)
  // The state directory as it was copied here; then the true lowest arrives.
  const copy = new MemoryJournal()
  for (const l of s.journal.lines) copy.append(l)
  assert.deepEqual(await submit(s.engine, all[0]!.tx.toAtomicBEEF()), [0])
  assert.equal(s.ls.outpointRow(op)!.winner, cHex(all[0]!.tx))
  // The host comes back with the copy: storage holds a carrier the rows do not name.
  const again = await restored(s, chain, copy)
  assert.equal(again.outpointRow(op)!.winner, cHex(all[0]!.tx), 'the lowest ever admitted')
  assert.ok(again.holds(cHex(all[0]!.tx)))
  assert.notEqual(await s.storage.findOutput(all[0]!.tx.id('hex'), 0, topic), null, 'not deleted')
  assert.deepEqual([await again.status(cHex(all[0]!.tx)), await again.status(cHex(all[1]!.tx))], ['unlisted', 'superseded'])
  assert.deepEqual(again.outpointRow(op), s.ls.outpointRow(op), 'the row the live host has')
})

test('what the index drops is deleted from storage at once, and a store that cannot delete does not grow a queue', async () => {
  const chain = new Chain(97500)
  const s = await setup({ chain })
  const { all } = await equivocations(new OwnerSim(crypt, 'delete owner', chain), 'delete', 11)
  for (const x of all) assert.deepEqual(await submit(s.engine, x.tx.toAtomicBEEF()), [0])
  // Nine kept, two turned away, with no retention pass in between.
  assert.deepEqual([s.ls.carrierCount, (await s.storage.findUTXOsForTopic(topic)).length, s.ls.pendingDeletes], [9, 9, 0])
  // A store with no deleteOutput keeps what was dropped; the module does not keep a list of it.
  const chain2 = new Chain(98000)
  const { all: more } = await equivocations(new OwnerSim(crypt, 'delete owner b', chain2), 'delete b', 31)
  const store = new MemoryStorage()
  const cannot = new Proxy(store, { get: (t, k) => (k === 'deleteOutput' ? undefined : Reflect.get(t, k)) }) as MemoryStorage
  const host = new FakeHost()
  const ls = secretModule(host, config, [topic], new MemoryJournal(), chain2.tracker).ls
  await ls.restore([], cannot)
  for (const x of more) await ls.outputAdmittedByTopic({ mode: 'whole-tx', topic, atomicBEEF: x.tx.toAtomicBEEF(), outputIndex: 0 })
  await ls.prune()
  assert.deepEqual([ls.carrierCount, ls.pendingDeletes], [9, 0])
  assert.equal(host.lines.filter((l) => l.msg.includes('cannot delete dropped outputs')).length, 1, 'said once')
})

test('an admission that meets a restore in flight waits for it, and is decided as any other', async () => {
  const chain = new Chain(98500)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'in flight owner', chain)
  const { all, op } = await equivocations(owner, 'in flight')
  for (const x of all.slice(1)) assert.deepEqual(await submit(s.engine, x.tx.toAtomicBEEF()), [0])
  assert.equal(s.ls.outpointRow(op)!.more, 2)
  // A chain of two tokens, and a journal that does not name them: the restore walks back from the second to the first.
  const vault = owner.vault('walked', hall, group, epochOf('walked', 0))
  const t0 = await vault.token()
  const t1 = await vault.token()
  for (const m of [t0, t1]) assert.deepEqual(await submit(s.engine, m.beef), [0])
  const journal = new MemoryJournal()
  for (const l of s.journal.lines) if (l.k !== 't') journal.append(l)
  const ls = secretModule(new FakeHost(), config, [topic], journal, chain.tracker).ls
  // While it reads the first token, the lowest commitment of all is admitted on the full row.
  let admitted: Promise<void> | undefined
  const meanwhile = new Proxy(s.storage, {
    get: (t, k) =>
      k === 'findOutput'
        ? async (...args: Parameters<MemoryStorage['findOutput']>): Promise<Output | null> => {
            if (args[0] === t0.tx.id('hex') && admitted === undefined) {
              admitted = ls.outputAdmittedByTopic({ mode: 'whole-tx', topic, atomicBEEF: all[0]!.tx.toAtomicBEEF(), outputIndex: 0 })
              await new Promise((resolve) => setTimeout(resolve, 20))
            }
            return await t.findOutput(...args)
          }
        : Reflect.get(t, k),
  }) as MemoryStorage
  await ls.restore(await s.storage.findUTXOsForTopic(topic, undefined, undefined, true), meanwhile)
  assert.notEqual(admitted, undefined, 'the admission came during the restore')
  await admitted
  assert.ok(ls.holds(cHex(all[0]!.tx)), 'kept: it is the lowest ever admitted')
  assert.equal(ls.outpointRow(op)!.winner, cHex(all[0]!.tx))
  assert.deepEqual([ls.outpointRow(op)!.others.length, ls.outpointRow(op)!.more], [8, 3])
  assert.deepEqual([ls.tokenStatus(t0.tx.id('hex')), ls.tokenStatus(t1.tx.id('hex'))], ['consistent', 'consistent'])
})
