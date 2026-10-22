/**
 * The contract review's attacks on spec sections 11.2 and 14, replayed
 * against the module on the real engine: a second, rootless chain under a
 * vault's identifier; a wrap under another epoch's key than the one its
 * record names; a rollback by an old inclusion path; storage that funding
 * does not bound; and two rooted tokens at one seq after a reorganization.
 * The rest are where their own subject is tested:
 *
 *   suppression by a worse BEEF; headers that lag     engine.test.ts
 *   a sweep before its carriers; the bounded table    ls_bsecret.test.ts
 *   retention floors; the sticky dropped winner       ls_bsecret.test.ts
 *   a vault that never acknowledges                   exit.test.ts
 *   a handshake flood on the priced route             paid.test.ts
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { Transaction } from '@bsv/sdk'
import { tokenBEEF } from './admit.js'
import { checkInSet } from './chain.js'
import { readAsMember } from './keyed.js'
import { decodeContext, verifySecret } from './merkle.js'
import { secretModule } from './module.js'
import { firstPush } from './script.js'
import { KeyChain, LookupService, decodeSecret, decodeVault, encodeVault, reasonOf } from './secrec.js'
import { answer, config, crypt, outputs, setup, submit, topic, type Rig } from './testhost.js'
import { Chain, OwnerSim, cHex, epochOf, sweep, token, type Minted, type VaultSim, type Version } from './testmint.js'
import { FakeHost } from './testutil.js'
import { displayTxid, fromHex, hashOrder } from './util.js'

const hall = 'example_hall_vkqzmtrwxp'
const group = fromHex('406504d3fbe1ae098f09a49dffa12222')
const day = 86400

async function put(s: Rig, ...versions: Version[]): Promise<void> {
  for (const x of versions) assert.deepEqual(await submit(s.engine, x.tx.toAtomicBEEF()), [0], `${x.name}@${x.secret.version}`)
}
async function mint(s: Rig, ...tokens: Minted[]): Promise<void> {
  for (const m of tokens) assert.deepEqual(await submit(s.engine, m.beef), [0], `seq ${m.rec.seq}`)
}
const q = (vault: VaultSim): { crypt: string; org: string; vault: string } => ({ crypt, org: vault.owner.hex, vault: vault.idHex })
const ids = (ms: Minted[]): string[] => ms.map((m) => m.tx.id('hex'))
const recordOf = (tx: Transaction) => decodeSecret(firstPush(Uint8Array.from(tx.outputs[0]!.lockingScript.toBinary()))!)

async function restored(s: Rig, chain: Chain, now?: () => number) {
  const ls = secretModule(new FakeHost(), config, [topic], s.journal, chain.tracker, now).ls
  await ls.restore(await s.storage.findUTXOsForTopic(topic, undefined, undefined, true), s.storage)
  return ls
}

test('a rootless chain under a vault\'s identifier is admitted, and is never the latest, never folded and lists nothing', async () => {
  const chain = new Chain(88000)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'rootless owner', chain)
  const [e0, e1] = [epochOf('rootless', 0), epochOf('rootless', 1)]
  const vault = owner.vault('rooted', hall, group, e0)
  const a1 = await vault.version('a', 'one')
  const t0 = await vault.token({ create: [a1] })
  // The vault acknowledges a new epoch: it is in debt, and its chain admits only re-keying.
  const t1 = await vault.token({ epoch: e1 })
  await put(s, a1)
  await mint(s, t0, t1)
  const honest = vault.fork()
  const n1 = await honest.version('new', 'created while a is stale')
  const refused = await honest.token({ create: [n1], mutate: (r) => (r.stale = 0) })
  assert.deepEqual(await submit(s.engine, refused.beef), [], 'on the real chain a create while in debt is refused')
  assert.equal(s.host.count('bsecret_refused_total', { reason: 'debt' }), 1)

  // The same owner mints a transaction with a well-formed token output at
  // seq 7 that spends no predecessor. No host admits it.
  const pseudo = encodeVault({ ...t1.rec, seq: 7, prev: hashOrder('11'.repeat(32)), stale: 0, count: 0, root: decodeVault(t0.record).root, create: [], update: [], retire: [] })
  const x = await token(owner.party, pseudo, [{ src: owner.chainTree, vout: owner.nextChainVout(), keyID: KeyChain }])
  chain.mine(x)
  assert.deepEqual(await submit(s.engine, tokenBEEF(x, owner.chainTree)), [], 'the pseudo-predecessor is refused')
  assert.equal(s.host.count('bsecret_refused_total', { reason: 'token-input' }), 1)
  // On it, a chain every host admits: each token passes every rule against
  // the bytes of its parent. It creates while the real vault is in debt.
  const rogue = vault.fork()
  rogue.tip = { tx: x, beef: new Uint8Array(0), rec: decodeVault(pseudo), record: pseudo, parent: owner.chainTree }
  rogue.set = new Map()
  const r1 = await rogue.version('rogue', 'listed by a token off the chain')
  const y = await rogue.token({ create: [r1] })
  const z = await rogue.token({ update: [await rogue.version('rogue', 'two')] })
  await put(s, r1)
  // The set the rogue tokens claim is the fold of their own change lists on
  // an empty set; nothing an admission rule reads says otherwise.
  assert.deepEqual([y.rec.seq, z.rec.seq], [8, 9])
  await mint(s, y, z)
  assert.deepEqual(ids([y, z]).map((t) => `${s.ls.tokenStatus(t)} ${s.ls.rooted(t)}`), ['pending false', 'pending false'])
  // Never the latest, although its seq is the highest the host holds for the vault.
  assert.deepEqual(await answer(s.engine, q(vault)), [t1.tx.id('hex')])
  assert.deepEqual(await answer(s.engine, { crypt, vaultsOf: owner.hex }), [t1.tx.id('hex')])
  assert.deepEqual(await answer(s.engine, { crypt, audit: owner.hex, vault: vault.idHex }), ids([t0, t1]), 'not part of the trail')
  assert.deepEqual(await answer(s.engine, { ...q(vault), seq: '9' }), [z.tx.id('hex')], 'answered by vault-seq alone')
  // Never folded, and it lists nothing: its record is unlisted, the set is the real chain's.
  assert.equal(await s.ls.status(cHex(r1.tx)), 'unlisted')
  assert.deepEqual(await answer(s.engine, { ...q(vault), secret: vault.secret('rogue') }), [])
  assert.deepEqual(await answer(s.engine, { crypt, org: owner.hex, secretsOf: vault.idHex }), [a1.tx.id('hex')])
  const ctx = decodeContext(Uint8Array.from((await outputs(s.engine, { ...q(vault), secret: vault.secret('a') }))[0]!.context!))
  assert.deepEqual([ctx.seq, displayTxid(ctx.token)], [1, t1.tx.id('hex')])
  // The real chain goes on, still bound by its debt, and stays the latest below the rogue seq.
  const a2 = await vault.version('a', 'two')
  const t2 = await vault.token({ update: [a2] })
  await put(s, a2)
  await mint(s, t2)
  assert.deepEqual(await answer(s.engine, q(vault)), [t2.tx.id('hex')])
  // A restart reads the rootless tokens back and roots none of them.
  const again = await restored(s, chain)
  assert.deepEqual(ids([y, z]).map((t) => `${again.tokenStatus(t)} ${again.rooted(t)}`), ['pending false', 'pending false'])
  assert.deepEqual((await again.lookup({ service: LookupService, query: q(vault) })).map((f) => f.txid), [t2.tx.id('hex')])
  assert.equal(again.pendingTokens, 2)
})

test('a wrap under another epoch\'s key than the one its record names is admitted, listed and answered: only a holder of the named key can tell', async () => {
  const chain = new Chain(88500)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'mis-keying owner', chain)
  const [e0, e1] = [epochOf('miskey', 0), epochOf('miskey', 1)]
  const vault = owner.vault('mis-keyed', hall, group, e0)
  const a1 = await vault.version('a', 'one')
  const t0 = await vault.token({ create: [a1] })
  const t1 = await vault.token({ epoch: e1 })
  // The re-keyed version names epoch 1, and its wrap is under epoch 0's key.
  const a2 = await vault.version('a', 'two', { wrapUnder: e0 })
  const t2 = await vault.token({ update: [a2] })
  await put(s, a1, a2)
  await mint(s, t0, t1, t2)
  // Every check a host and its index can make passes: the contract says so (spec section 6.3).
  assert.equal(a2.secret.epoch, 1)
  assert.equal(await s.ls.status(cHex(a2.tx)), 'listed')
  assert.deepEqual(ids([t0, t1, t2]).map((t) => s.ls.tokenStatus(t)), ['consistent', 'consistent', 'consistent'])
  assert.equal(t2.rec.stale, 0, 'the trail says the vault settled')
  const got = await outputs(s.engine, { ...q(vault), secret: vault.secret('a') })
  assert.deepEqual(got.map((o) => o.txid), [a2.tx.id('hex')])
  const rec = recordOf(got[0]!.tx)
  checkInSet(t2.rec, hashOrder(t2.tx.id('hex')), rec, decodeContext(Uint8Array.from(got[0]!.context!)))
  // A member of epoch 1 opens with the key of the epoch the record names, and no other: it does not open, which names the owner.
  let refusal = 'opens'
  try {
    readAsMember(rec, rec.inline!, e1.symmetric)
  } catch (e) {
    refusal = reasonOf(e)
  }
  assert.equal(refusal, 'undecryptable')
  // The limit, stated: a removed member that tries its old key opens the version.
  assert.equal(new TextDecoder().decode(readAsMember(rec, rec.inline!, e0.symmetric).value), 'two')
})

test('a rollback by an old inclusion path: a path names the token whose set it is, and an answer below a token the reader holds is refused', async () => {
  const chain = new Chain(89000)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'rollback owner', chain)
  const vault = owner.vault('rollback', hall, group, epochOf('rollback', 0))
  const a1 = await vault.version('a', 'one')
  const t0 = await vault.token({ create: [a1] })
  await put(s, a1)
  await mint(s, t0)
  // What a host answers at seq 0, kept by an attacker.
  const old = (await outputs(s.engine, { ...q(vault), secret: vault.secret('a') }))[0]!
  const oldCtx = decodeContext(Uint8Array.from(old.context!))
  const a2 = await vault.version('a', 'two')
  const t1 = await vault.token({ update: [a2] })
  await put(s, a2)
  await mint(s, t1)
  // The old answer still proves what it proved, and nothing about the latest token.
  assert.ok(verifySecret(oldCtx, a1.secret.id, 1, a1.cid, t0.rec.root))
  assert.equal(verifySecret(oldCtx, a1.secret.id, 1, a1.cid, t1.rec.root), false)
  const first = (f: () => void): string => {
    try {
      f()
      return 'in the set'
    } catch (e) {
      return reasonOf(e)
    }
  }
  assert.equal(first(() => checkInSet(t1.rec, hashOrder(t1.tx.id('hex')), recordOf(old.tx), oldCtx)), 'listing', 'the old version with its old path, against the latest token')
  assert.equal(first(() => checkInSet(t0.rec, hashOrder(t0.tx.id('hex')), recordOf(old.tx), oldCtx)), 'in the set', 'only against the token it names')
  // The host answers the latest set, and its context names the token it used.
  const now = (await outputs(s.engine, { ...q(vault), secret: vault.secret('a') }))[0]!
  const ctx = decodeContext(Uint8Array.from(now.context!))
  assert.deepEqual([now.txid, ctx.seq, displayTxid(ctx.token)], [a2.tx.id('hex'), 1, t1.tx.id('hex')])
  assert.equal(first(() => checkInSet(t1.rec, hashOrder(t1.tx.id('hex')), recordOf(now.tx), ctx)), 'in the set')
  // A path of the right seq under another token's txid is refused too: two tokens can share a seq.
  assert.equal(first(() => checkInSet(t1.rec, hashOrder('22'.repeat(32)), recordOf(now.tx), ctx)), 'listing')
  // The old version is not the set's: only version and history answer it.
  assert.deepEqual(await answer(s.engine, { ...q(vault), secret: vault.secret('a'), version: '1' }), [a1.tx.id('hex')])
  // A host that never received seq 1 answers seq 0 as latest, and says so: a
  // reader that verified seq 1 refuses an answer below it (rollback).
  const behind = await setup({ chain })
  await put(behind, a1, a2)
  await mint(behind, t0)
  assert.deepEqual(await answer(behind.engine, q(vault)), [t0.tx.id('hex')])
  const remembered = t1.rec.seq
  const lagging = decodeContext(Uint8Array.from((await outputs(behind.engine, { ...q(vault), secret: vault.secret('a') }))[0]!.context!))
  assert.ok(lagging.seq < remembered, 'the context shows the answer is below the token the reader holds')
})

test('storage: what funding does not bound is bounded by the rows, the floors and the table', async () => {
  const chain = new Chain(89500)
  let now = 1_800_000_000
  const s = await setup({ chain, now: () => now, spendTable: 8 })
  const owner = new OwnerSim(crypt, 'storage owner', chain, { trees: 100, chains: 30 })
  const e0 = epochOf('storage', 0)
  // Carriers for vaults that do not exist: admitted on their own bytes, and gone after 24 hours.
  const ghosts: Version[] = []
  for (let i = 0; i < 20; i++) ghosts.push(await owner.vault(`ghost ${i}`, hall, group, e0).version('g', `value ${i}`))
  await put(s, ...ghosts)
  assert.equal(s.ls.carrierCount, 20)
  assert.equal(s.ls.vaultCount, 0, 'a carrier makes no vault')
  now += day
  assert.equal(await s.ls.prune(), 20)
  assert.equal(s.ls.carrierCount, 0)
  assert.equal((await s.storage.findUTXOsForTopic(topic)).length, 0, 'deleted from storage, each its whole funding tree')
  assert.deepEqual(await submit(s.engine, ghosts[0]!.tx.toAtomicBEEF()), [], 'a dropped carrier offered again is a duplicate: the engine keeps its applied row')
  // The same carriers on one funding output: the row is the winner, eight others and a count.
  const vault = owner.vault('held', hall, group, e0)
  const a1 = await vault.version('a', 'one')
  await mint(s, await vault.token({ create: [a1] }))
  await put(s, a1)
  const flood: Version[] = []
  for (let i = 0; i < 40; i++) {
    vault.last.delete('a')
    flood.push(await vault.version('a', `equivocation ${i}`, { vout: a1.vout }))
  }
  await put(s, ...flood)
  await s.ls.flush()
  const row = s.ls.outpointRow(`${owner.secretTree.id('hex')}.${a1.vout}`)!
  assert.deepEqual([row.others.length, row.more], [8, 32])
  assert.equal(s.ls.carrierCount, 9)
  assert.equal((await s.storage.findUTXOsForTopic(topic)).filter((o) => o.outputIndex === 0 && o.txid !== vault.tip!.tx.id('hex')).length, 9, 'nine outputs, however many were offered')
  const all = [a1, ...flood].map((x) => cHex(x.tx)).sort()
  assert.equal(row.winner, all[0])
  assert.deepEqual(row.others, all.slice(1, 9))
  assert.deepEqual((await answer(s.engine, { ...q(vault), secret: vault.secret('a'), version: '1' })).length, 1, 'one answered carrier per funding output')
  // A stranger's chain of sweeps of its own outputs: the table, and nothing more.
  const stranger = new OwnerSim(crypt, 'stranger', chain, { trees: 60 })
  for (let i = 0; i < 50; i++) assert.deepEqual(await submit(s.engine, (await sweep(stranger.secretTree, [i], stranger.party, chain)).toAtomicBEEF()), [0])
  await s.ls.flush()
  assert.equal(s.ls.tableSize, 8)
  assert.equal(s.ls.sweepCount, 8)
  assert.equal(s.ls.rowCount, 21, 'a sweep of an outpoint no carrier used makes no row')
  // A swept outpoint stays swept for the host's life: a carrier made later on it is a fresh txid, and retracted.
  const b1 = await vault.version('b', 'one')
  await put(s, b1)
  assert.deepEqual(await submit(s.engine, (await sweep(owner.secretTree, [b1.vout], owner.party, chain)).toAtomicBEEF()), [0])
  now += 400 * day
  await s.ls.prune()
  assert.equal(s.ls.holds(cHex(b1.tx)), false, 'the retracted carrier itself is long gone')
  vault.last.delete('b')
  const b1again = await vault.version('b', 'made again on the swept outpoint', { vout: b1.vout })
  await put(s, b1again)
  assert.equal(await s.ls.status(cHex(b1again.tx)), 'retracted')
  assert.deepEqual(await answer(s.engine, { ...q(vault), secret: vault.secret('b'), version: '1' }), [])
  const again = await restored(s, chain, () => now)
  assert.equal(await again.status(cHex(b1again.tx)), 'retracted')
  assert.deepEqual(again.outpointRow(`${owner.secretTree.id('hex')}.${a1.vout}`), s.ls.outpointRow(`${owner.secretTree.id('hex')}.${a1.vout}`))
})

test('a reorganization: two rooted tokens at one seq are both answered, each branch folded on its own, and the set is that of the one the host\'s headers hold', async () => {
  const chain = new Chain(90000)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'reorg owner', chain)
  const vault = owner.vault('reorg', hall, group, epochOf('reorg', 0))
  const a1 = await vault.version('a', 'one')
  const t0 = await vault.token({ create: [a1] })
  // Two tokens spend seq 0's output: one mined first and orphaned, one mined in its place.
  const other = vault.fork()
  const a2 = await vault.version('a', 'two, on the first branch')
  const first = await vault.token({ update: [a2] })
  const a2b = await other.version('a', 'two, on the second branch')
  const second = await other.token({ update: [a2b] })
  await put(s, a1, a2, a2b)
  await mint(s, t0, first, second)
  const pair = ids([first, second]).sort()
  assert.deepEqual(ids([first, second]).map((t) => `${s.ls.tokenStatus(t)} ${s.ls.rooted(t)}`), ['consistent true', 'consistent true'])
  assert.deepEqual(await answer(s.engine, q(vault)), pair, 'every candidate at the highest seq')
  assert.deepEqual(await answer(s.engine, { crypt, audit: owner.hex, vault: vault.idHex }), [t0.tx.id('hex'), ...pair])
  const used = async (ls = s.ls): Promise<{ carrier: string; token: string }> => {
    const f = await ls.lookup({ service: LookupService, query: { ...q(vault), secret: vault.secret('a') } })
    return { carrier: f[0]!.txid, token: displayTxid(decodeContext(Uint8Array.from(f[0]!.context!)).token) }
  }
  const lowest = pair[0] === first.tx.id('hex') ? { carrier: a2.tx.id('hex'), token: first.tx.id('hex') } : { carrier: a2b.tx.id('hex'), token: second.tx.id('hex') }
  // Both proofs verify in the host's headers: it cannot tell, and uses the lowest txid.
  assert.deepEqual(await used(), lowest)
  // The first block leaves the best chain: the answer uses the second branch, and names it.
  const [h1, h2] = [first.tx.merklePath!.blockHeight, second.tx.merklePath!.blockHeight]
  const roots = [chain.roots.get(h1)!, chain.roots.get(h2)!]
  chain.orphan(h1)
  const fresh = async () => await restored(s, chain)
  assert.deepEqual(await used(await fresh()), { carrier: a2b.tx.id('hex'), token: second.tx.id('hex') })
  // A carrier's status is taken against the branch the answer uses.
  const ls2 = await fresh()
  assert.deepEqual([await ls2.status(cHex(a2.tx)), await ls2.status(cHex(a2b.tx))], ['mismatched', 'listed'])
  // The other way round.
  chain.roots.set(h1, roots[0]!)
  chain.orphan(h2)
  const ls1 = await fresh()
  assert.deepEqual(await used(ls1), { carrier: a2.tx.id('hex'), token: first.tx.id('hex') })
  assert.deepEqual([await ls1.status(cHex(a2.tx)), await ls1.status(cHex(a2b.tx))], ['listed', 'mismatched'])
  // Neither verifies: the lowest txid, and both are still answered as latest.
  chain.orphan(h1)
  const neither = await fresh()
  assert.deepEqual(await used(neither), lowest)
  assert.deepEqual((await neither.lookup({ service: LookupService, query: q(vault) })).map((f) => f.txid), pair, 'a tip whose stored proof no longer verifies is not hidden')
  chain.roots.set(h1, roots[0]!)
  chain.roots.set(h2, roots[1]!)
  // A held token offered again is a duplicate: the engine takes no proof by submission.
  assert.deepEqual(await submit(s.engine, first.beef), [])
  // The chain goes on from the second: the higher seq is the latest, and the first branch stays in the trail.
  const a3 = await other.version('a', 'three')
  const third = await other.token({ update: [a3] })
  await put(s, a3)
  await mint(s, third)
  assert.deepEqual(await answer(s.engine, q(vault)), [third.tx.id('hex')])
  assert.deepEqual(await used(), { carrier: a3.tx.id('hex'), token: third.tx.id('hex') })
  assert.deepEqual(await answer(s.engine, { crypt, audit: owner.hex, vault: vault.idHex }), [t0.tx.id('hex'), ...pair, third.tx.id('hex')])
  assert.deepEqual([await s.ls.status(cHex(a2.tx)), await s.ls.status(cHex(a2b.tx)), await s.ls.status(cHex(a3.tx))], ['mismatched', 'listed', 'listed'])
  // Retraction follows the sweeps a host holds, not its view of the best chain.
  const sw = await sweep(owner.secretTree, [a3.vout], owner.party, chain)
  assert.deepEqual(await submit(s.engine, sw.toAtomicBEEF()), [0])
  chain.orphan(sw.merklePath!.blockHeight)
  assert.equal(await s.ls.status(cHex(a3.tx)), 'retracted')
  assert.deepEqual(await answer(s.engine, { ...q(vault), secret: vault.secret('a') }), [])
  assert.deepEqual(await answer(s.engine, { crypt, spent: `${owner.secretTree.id('hex')}.${a3.vout}` }), [sw.id('hex')])
  // A restart in any order of rows reaches the same branches.
  const rows = await s.storage.findUTXOsForTopic(topic, undefined, undefined, true)
  for (const order of [rows, [...rows].reverse()]) {
    const ls = secretModule(new FakeHost(), config, [topic], s.journal, chain.tracker).ls
    await ls.restore(order, s.storage)
    assert.deepEqual(ids([t0, first, second, third]).map((t) => `${ls.tokenStatus(t)} ${ls.rooted(t)}`), Array(4).fill('consistent true'))
    assert.deepEqual((await ls.lookup({ service: LookupService, query: q(vault) })).map((f) => f.txid), [third.tx.id('hex')])
    assert.equal(await ls.status(cHex(a3.tx)), 'retracted')
  }
})
