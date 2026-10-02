/**
 * The index rules of spec section 11.2 and the retention floors of section
 * 11.3, through the module on the real engine: which tokens are rooted, in
 * any order; a chain that breaks; every carrier status and which class
 * answers it; pages and cursors; the bound on tokens at one seq; the
 * bounded table of spends; retention; the set tree; and the journal file.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { PrivateKey, Transaction } from '@bsv/sdk'
import { rooted, storedToken } from './admit.js'
import { FileJournal, JournalFile, MemoryJournal } from './journal.js'
import { FloorDays, MaxPerSeq, SecretLookupService, SetTree } from './ls_bsecret.js'
import { decodeContext, encodeContext, proveSecret, setRoot, verifySecret, type Current } from './merkle.js'
import { secretModule } from './module.js'
import { firstPush } from './script.js'
import { LookupService, decodeSecret } from './secrec.js'
import { answer, config, crypt, outputs, setup, submit, topic, type Rig } from './testhost.js'
import { Chain, OwnerSim, cHex, carrier, epochOf, sha, sweep, type Minted, type VaultSim, type Version } from './testmint.js'
import { FakeHost, byName, readVectors, txVectors } from './testutil.js'
import { displayTxid, fromHex, toHex } from './util.js'

const v = txVectors()
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

test('index-v1 rooted: the same tokens are rooted as the Go codec says, in the order given and the reverse', async () => {
  const index = readVectors<{ rooted: Array<{ label: string; held: string[]; rooted: string[] }> }>('index-v1.json')
  const named = (label: string): { txid: string; beef: number[] } => {
    const seq = /^seq ([0-3])$/.exec(label)
    if (seq !== null) {
      const s = v.stored[Number(seq[1])]!
      return { txid: s.txid, beef: Array.from(fromHex(s.stored)) }
    }
    const t = byName(v, label === 'second vault seq 0' ? 'vault-token-second-vault' : 'vault-token-on-unadmitted-parent')
    return { txid: t.txid, beef: Array.from(fromHex(t.beef)) }
  }
  assert.equal(index.rooted.length, 5)
  for (const c of index.rooted) {
    for (const order of [c.held, [...c.held].reverse()]) {
      const ls = new SecretLookupService({ crypts: new Set([crypt]), host: new FakeHost(), journal: new MemoryJournal() })
      const txs: Transaction[] = []
      for (const label of order) {
        const n = named(label)
        const tx = Transaction.fromBEEF(n.beef, n.txid)
        txs.push(tx)
        ls.outputAdmittedByTopic({ mode: 'whole-tx', atomicBEEF: tx.toAtomicBEEF(), outputIndex: 0, topic })
      }
      const want = c.rooted.map((l) => named(l).txid).sort()
      assert.deepEqual(order.map((l) => named(l).txid).filter((t) => ls.rooted(t)).sort(), want, c.label)
      // What the index keeps of a token decides as the codec's own check on the transactions does.
      assert.deepEqual([...rooted(txs)].sort(), want, c.label)
    }
  }
})

test('a chain admitted in any order is pending until its first token arrives, then rooted and folded from seq 0', async () => {
  const chain = new Chain(80000)
  const owner = new OwnerSim(crypt, 'order owner', chain)
  const vault = owner.vault('order', hall, group, epochOf('order', 0))
  const a1 = await vault.version('a', 'one')
  await vault.token({ create: [a1] })
  for (let n = 2; n <= 6; n++) await vault.token({ update: [await vault.version('a', `value ${n}`)] })
  const s = await setup({ chain })
  const order = [3, 5, 1, 4, 2]
  for (const i of order) await mint(s, vault.history[i]!)
  assert.deepEqual(vault.history.slice(1).map((m) => s.ls.tokenStatus(m.tx.id('hex'))), Array(5).fill('pending'))
  assert.deepEqual(await answer(s.engine, q(vault)), [], 'nothing is latest without the first token')
  assert.deepEqual(await answer(s.engine, { crypt, vaultsOf: owner.hex }), [])
  assert.deepEqual(await answer(s.engine, { crypt, audit: owner.hex, vault: vault.idHex }), [], 'no chain yet')
  assert.deepEqual(await answer(s.engine, { ...q(vault), seq: '3' }), [vault.history[3]!.tx.id('hex')], 'vault-seq answers a pending token')
  assert.equal(s.ls.pendingTokens, 5)
  await mint(s, vault.history[0]!)
  assert.deepEqual(vault.history.map((m) => `${s.ls.tokenStatus(m.tx.id('hex'))} ${s.ls.rooted(m.tx.id('hex'))}`), Array(6).fill('consistent true'))
  assert.deepEqual(await answer(s.engine, q(vault)), [vault.tip!.tx.id('hex')])
  assert.deepEqual(await answer(s.engine, { crypt, audit: owner.hex, vault: vault.idHex }), ids(vault.history))
  assert.equal(s.host.count('bsecret_token_status_total', { status: 'pending' }), 5)
  assert.equal(s.host.count('bsecret_token_status_total', { status: 'consistent' }), 6)
  // A long chain offered latest first roots without recursion.
  const long = owner.vault('long', hall, group, epochOf('order', 0))
  for (let n = 0; n < 40; n++) await long.token()
  for (const m of [...long.history].reverse()) await mint(s, m)
  assert.deepEqual(await answer(s.engine, q(long)), [long.tip!.tx.id('hex')])
})

test('a token whose counts its change lists do not give breaks the chain for good: the set stays that of the token before it', async () => {
  const chain = new Chain(80500)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'broken owner', chain)
  const [e0, e1] = [epochOf('broken', 0), epochOf('broken', 1)]

  // set-mismatch: a root the fold does not reproduce. Every host admits it.
  const vault = owner.vault('false root', hall, group, e0)
  const a1 = await vault.version('a', 'one')
  const b1 = await vault.version('b', 'one')
  const t0 = await vault.token({ create: [a1, b1] })
  const a2 = await vault.version('a', 'two')
  const t1 = await vault.token({ update: [a2], mutate: (r) => (r.root = sha('not the root')) })
  const a3 = await vault.version('a', 'three')
  const t2 = await vault.token({ update: [a3] })
  await put(s, a1, b1, a2, a3)
  await mint(s, t0, t1, t2)
  assert.deepEqual(ids([t0, t1, t2]).map((t) => s.ls.tokenStatus(t)), ['consistent', 'set-mismatch', 'set-mismatch'], 'sticky: the token after it has it too')
  assert.deepEqual(await answer(s.engine, q(vault)), [t2.tx.id('hex')], 'the latest rooted token is still answered; a reader folds and fails closed')
  const got = await outputs(s.engine, { ...q(vault), secret: vault.secret('a') })
  assert.deepEqual(got.map((o) => o.txid), [a1.tx.id('hex')], 'the set of the last token before the break')
  const ctx = decodeContext(Uint8Array.from(got[0]!.context!))
  assert.deepEqual([ctx.seq, displayTxid(ctx.token)], [0, t0.tx.id('hex')], "the context names the token it used, below the vault's latest")
  assert.ok(verifySecret(ctx, a1.secret.id, 1, a1.cid, t0.rec.root))
  assert.deepEqual(await answer(s.engine, { crypt, org: owner.hex, secretsOf: vault.idHex }), [a1, b1].sort((x, y) => (toHex(x.secret.id) < toHex(y.secret.id) ? -1 : 1)).map((x) => x.tx.id('hex')))
  // What a broken token lists is not listed: its carriers are pending, never the set's.
  assert.deepEqual([await s.ls.status(cHex(a1.tx)), await s.ls.status(cHex(a2.tx)), await s.ls.status(cHex(a3.tx))], ['listed', 'unlisted', 'unlisted'])
  assert.equal(s.host.count('bsecret_token_status_total', { status: 'set-mismatch' }), 2)
  assert.ok(s.host.lines.some((l) => l.msg === 'ls_bsecret token status' && l.extra?.['status'] === 'set-mismatch' && l.extra?.['txid'] === t1.tx.id('hex')))

  // stale-mismatch: a secret already re-keyed updated again and counted as clearing the debt.
  const debt = owner.vault('false debt', hall, group, e0)
  const c1 = await debt.version('c', 'one')
  const d1 = await debt.version('d', 'one')
  const u0 = await debt.token({ create: [c1, d1] })
  const u1 = await debt.token({ epoch: e1 })
  const c2 = await debt.version('c', 'two')
  const u2 = await debt.token({ update: [c2] })
  const c3 = await debt.version('c', 'three')
  const u3 = await debt.token({ update: [c3], mutate: (r) => (r.stale = 0) })
  await put(s, c1, d1, c2, c3)
  await mint(s, u0, u1, u2, u3)
  assert.deepEqual([u1.rec.stale, u2.rec.stale, u3.rec.stale], [2, 1, 0], 'its arithmetic passes admission')
  assert.deepEqual(ids([u0, u1, u2, u3]).map((t) => s.ls.tokenStatus(t)), ['consistent', 'consistent', 'consistent', 'stale-mismatch'])
  assert.deepEqual(await answer(s.engine, { ...q(debt), secret: debt.secret('c') }), [c2.tx.id('hex')])

  // commitment-reuse: a version under a content key an earlier token listed. It does not stop the set.
  const reuse = owner.vault('reuse', hall, group, e0)
  const key = owner.draw()
  const f1 = await reuse.version('f', 'one', { key })
  const w0 = await reuse.token({ create: [f1] })
  const f2 = await reuse.version('f', 'two', { key })
  const w1 = await reuse.token({ update: [f2] })
  const f3 = await reuse.version('f', 'three')
  const w2 = await reuse.token({ update: [f3] })
  await put(s, f1, f2, f3)
  await mint(s, w0, w1, w2)
  assert.deepEqual(ids([w0, w1, w2]).map((t) => s.ls.tokenStatus(t)), ['consistent', 'commitment-reuse', 'consistent'])
  assert.deepEqual(await answer(s.engine, { ...q(reuse), secret: reuse.secret('f') }), [f3.tx.id('hex')])
  assert.equal(s.host.count('bsecret_token_status_total', { status: 'commitment-reuse' }), 1)
})

test('every carrier status, and which class answers it', async () => {
  const chain = new Chain(81000)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'status owner', chain)
  const [e0, e1] = [epochOf('status', 0), epochOf('status', 1)]
  const vault = owner.vault('statuses', hall, group, e0, { anchor: 1 })
  const a1 = await vault.version('a', 'one')
  const b1 = await vault.version('b', 'one')
  const t0 = await vault.token({ create: [a1, b1] })
  // mismatched: version 1 of a again, with other content, on another outpoint.
  vault.last.delete('a')
  const other = await vault.version('a', 'not what the token lists')
  vault.last.set('a', a1)
  // mismatched: a label that is not one of the vault's.
  const alien = await vault.version('x', 'one', { label: 'top-secret' })
  // unlisted: two versions no token lists yet.
  const a2 = await vault.version('a', 'two')
  const a3 = await vault.version('a', 'three')
  // retracted: a carrier whose funding outpoint a sweep spends.
  const gone = await vault.version('g', 'one')
  const sw = await sweep(owner.secretTree, [gone.vout], owner.party, chain)
  // mismatched: a record keyed under epoch 0 that a token of epoch 1 lists.
  const t1 = await vault.token({ epoch: e1 })
  const b2 = await vault.version('b', 'two', { epoch: e0 })
  const t2 = await vault.token({ update: [b2] })
  await put(s, a1, b1, other, alien, a2, a3, gone, b2)
  await mint(s, t0, t1, t2)
  assert.deepEqual(await submit(s.engine, sw.toAtomicBEEF()), [0])
  const status = async (x: Version): Promise<string | undefined> => await s.ls.status(cHex(x.tx))
  assert.deepEqual([await status(a1), await status(b1), await status(other), await status(alien), await status(a2), await status(a3), await status(gone), await status(b2)], [
    'listed',
    'listed',
    'mismatched',
    'mismatched',
    'unlisted',
    'unlisted',
    'retracted',
    'mismatched',
  ])
  assert.equal(s.ls.tokenStatus(t2.tx.id('hex')), 'consistent', 'the fold cannot see the record: only its carrier is mismatched')
  const of = (name: string): string => vault.secret(name)
  // secret: only a listed carrier of the version the set holds.
  assert.deepEqual(await answer(s.engine, { ...q(vault), secret: of('a') }), [a1.tx.id('hex')])
  assert.deepEqual(await answer(s.engine, { ...q(vault), secret: of('b') }), [], 'the set holds version 2, whose only carrier is mismatched')
  // version and history: listed, unlisted and mismatched.
  assert.deepEqual(await answer(s.engine, { ...q(vault), secret: of('a'), version: '1' }), [a1.tx.id('hex'), other.tx.id('hex')].sort())
  assert.deepEqual(await answer(s.engine, { ...q(vault), secret: of('b'), version: '2' }), [b2.tx.id('hex')])
  assert.deepEqual(await answer(s.engine, { ...q(vault), secret: of('g'), version: '1' }), [], 'retracted: no class answers it')
  assert.deepEqual(await answer(s.engine, { ...q(vault), pending: of('g') }), [])
  assert.deepEqual(await answer(s.engine, { crypt, history: owner.hex, vault: vault.idHex, secret: of('g') }), [])
  assert.deepEqual(await answer(s.engine, { crypt, history: owner.hex, vault: vault.idHex, secret: of('a') }), [...[a1.tx.id('hex'), other.tx.id('hex')].sort(), a2.tx.id('hex'), a3.tx.id('hex')])
  // pending: unlisted versions above the set's, highest first; a mismatched one is not pending.
  assert.deepEqual(await answer(s.engine, { ...q(vault), pending: of('a') }), [a3.tx.id('hex'), a2.tx.id('hex')])
  assert.deepEqual(await answer(s.engine, { ...q(vault), pending: of('x') }), [], 'its label is not one of the vault\'s')
  assert.deepEqual(await answer(s.engine, { ...q(vault), secret: of('x'), version: '1' }), [alien.tx.id('hex')])
  // sweep: the spend, with the outpoint's row.
  assert.deepEqual(await answer(s.engine, { crypt, spent: `${owner.secretTree.id('hex')}.${gone.vout}` }), [sw.id('hex')])
  assert.equal(s.host.count('bsecret_retractions_total'), 1)
  // A carrier of a vault the host holds no chain of is unlisted, and answered by version alone.
  const nowhere = owner.vault('never minted', hall, group, e0)
  const n1 = await nowhere.version('n', 'one')
  await put(s, n1)
  assert.equal(await status(n1), 'unlisted')
  assert.deepEqual(await answer(s.engine, { ...q(nowhere), secret: nowhere.secret('n'), version: '1' }), [n1.tx.id('hex')])
  assert.deepEqual(await answer(s.engine, { ...q(nowhere), secret: nowhere.secret('n') }), [])
  assert.deepEqual(await answer(s.engine, { ...q(nowhere), pending: nowhere.secret('n') }), [n1.tx.id('hex')])
})

test('pages: 64 tokens or 16 carriers, in order, strictly after the cursor, never splitting a seq, a secret or a version', async () => {
  const chain = new Chain(82000)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'page owner', chain, { trees: 130, chains: 70 })
  const e0 = epochOf('pages', 0)
  const vault = owner.vault('pages', hall, group, e0)
  // 20 secrets, labelled alternately; one of them carried twice.
  const first: Version[] = []
  for (let i = 0; i < 20; i++) first.push(await vault.version(`s/${String(i).padStart(2, '0')}`, `value ${i}`, { label: i % 2 === 0 ? 'internal' : 'public' }))
  await vault.token({ create: first })
  await put(s, ...first)
  const sorted = [...first].sort((x, y) => (toHex(x.secret.id) < toHex(y.secret.id) ? -1 : 1))
  // The sixteenth secret the host will answer (s/00 is updated below and answers nothing).
  const twinOf = sorted.filter((x) => x.name !== 's/00')[15]!
  // The same record on a second funding output: the same version, carried twice.
  const twin = await carrier(owner.secretTree, owner.nextSecretVout(), owner.party, twinOf.record)
  assert.deepEqual(await submit(s.engine, twin.toAtomicBEEF()), [0])
  // 69 more tokens: 70 in all.
  for (let n = 2; n <= 70; n++) await vault.token({ update: [await vault.version('s/00', `value ${n}`)] })
  await mint(s, ...vault.history)

  const audit = { crypt, audit: owner.hex, vault: vault.idHex }
  const page1 = await answer(s.engine, audit)
  assert.deepEqual(page1, ids(vault.history.slice(0, 64)))
  assert.deepEqual(await answer(s.engine, { ...audit, after: '63' }), ids(vault.history.slice(64)))
  assert.deepEqual(await answer(s.engine, { ...audit, after: '69' }), [])

  // secrets: 16 carriers a page; the secret carried twice is not split across two pages.
  const pair = [twinOf.tx.id('hex'), twin.id('hex')].sort()
  // s/00 was updated 69 times and none of its later carriers was published:
  // the host holds no carrier of its listed version, and answers none.
  const expect = sorted.flatMap((x) => (x === twinOf ? pair : x.name === 's/00' ? [] : [x.tx.id('hex')]))
  const all = { crypt, org: owner.hex, secretsOf: vault.idHex }
  const p1 = await outputs(s.engine, all)
  assert.equal(p1.length, 15, 'the sixteenth and seventeenth carriers are one secret: the page stops before it')
  const cursor = (o: { tx: Transaction }): string => toHex(decodeSecret(firstPush(Uint8Array.from(o.tx.outputs[0]!.lockingScript.toBinary()))!).id)
  const p2 = await outputs(s.engine, { ...all, after: cursor(p1[p1.length - 1]!) })
  assert.deepEqual([...p1, ...p2].map((o) => o.txid), expect)
  assert.deepEqual(await answer(s.engine, { ...all, after: cursor(p2[p2.length - 1]!) }), [])
  // label: the same set, filtered.
  const internal = await answer(s.engine, { ...q(vault), label: 'internal' })
  assert.deepEqual(internal, sorted.filter((x) => x.secret.label === 'internal' && x.name !== 's/00').flatMap((x) => (x === twinOf ? pair : [x.tx.id('hex')])))

  // history: 16 carriers a page, by version.
  const hv = owner.vault('history', hall, group, e0)
  const versions: Version[] = []
  for (let n = 1; n <= 20; n++) versions.push(await hv.version('h', `value ${n}`))
  await put(s, ...versions)
  const h = { crypt, history: owner.hex, vault: hv.idHex, secret: hv.secret('h') }
  assert.deepEqual(await answer(s.engine, h), versions.slice(0, 16).map((x) => x.tx.id('hex')))
  assert.deepEqual(await answer(s.engine, { ...h, after: '16' }), versions.slice(16).map((x) => x.tx.id('hex')))
  assert.deepEqual(await answer(s.engine, { ...q(hv), pending: hv.secret('h') }), versions.slice(12).reverse().map((x) => x.tx.id('hex')), 'pending: the 8 highest versions')

  // vaults: the latest rooted token of each, by vault identifier, 64 a page.
  const many: VaultSim[] = [vault]
  for (let i = 0; i < 66; i++) {
    const x = owner.vault(`v ${i}`, hall, group, e0)
    await mint(s, await x.token())
    many.push(x)
  }
  const byId = [...many].sort((x, y) => (x.idHex < y.idHex ? -1 : 1))
  const vs = { crypt, vaultsOf: owner.hex }
  assert.deepEqual(await answer(s.engine, vs), byId.slice(0, 64).map((x) => x.tip!.tx.id('hex')))
  assert.deepEqual(await answer(s.engine, { ...vs, after: byId[63]!.idHex }), byId.slice(64).map((x) => x.tip!.tx.id('hex')))
})

test('at most 8 tokens are kept at one seq: rooted before others, then the lowest txids', async () => {
  const chain = new Chain(83000)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'crowd owner', chain)
  const vault = owner.vault('crowd', hall, group, epochOf('crowd', 0))
  const t0 = await vault.token()
  // Two tokens at seq 1 that both spend seq 0: only one is offered to the host.
  const hidden = vault.fork()
  const t1 = await vault.token()
  const h1 = await hidden.token({ mutate: (r) => (r.name = 'hidden branch') })
  await mint(s, t0, t1)
  // Ten tokens at seq 2 on the hidden one: admitted, each on its parent's bytes, and pending.
  const strays: Minted[] = []
  for (let i = 0; i < 10; i++) {
    const f = hidden.fork()
    strays.push(await f.token({ mutate: (r) => (r.created += i) }))
  }
  assert.equal(h1.rec.seq, 1)
  await mint(s, ...strays)
  const low = ids(strays).sort()
  assert.deepEqual(await answer(s.engine, { ...q(vault), seq: '2' }), low.slice(0, MaxPerSeq), 'the eight lowest txids')
  assert.ok(s.host.lines.filter((l) => l.msg === 'ls_bsecret kept no more tokens at this seq').length === 2)
  // A token at seq 2 that descends from the held chain takes a place whatever its txid.
  const t2 = await vault.token()
  await mint(s, t2)
  assert.ok(s.ls.rooted(t2.tx.id('hex')))
  const kept = await answer(s.engine, { ...q(vault), seq: '2' })
  assert.equal(kept.length, MaxPerSeq)
  assert.ok(kept.includes(t2.tx.id('hex')))
  assert.deepEqual(kept.filter((t) => t !== t2.tx.id('hex')), low.filter((t) => t !== t2.tx.id('hex')).slice(0, MaxPerSeq - 1))
  assert.deepEqual(await answer(s.engine, q(vault)), [t2.tx.id('hex')])
  // A restart reads every stored token again and reaches the same eight.
  const again = secretModule(new FakeHost(), config, [topic], s.journal, chain.tracker).ls
  await again.restore(await s.storage.findUTXOsForTopic(topic, undefined, undefined, true), s.storage)
  assert.deepEqual((await again.lookup({ service: LookupService, query: { ...q(vault), seq: '2' } })).map((f) => f.txid), kept)
})

test('the bounded table: a sweep that arrives before its carrier retracts it while its spend is kept, and a stranger\'s sweeps cost the table and no more', async () => {
  const chain = new Chain(84000)
  const s = await setup({ chain, spendTable: 4 })
  const owner = new OwnerSim(crypt, 'table owner', chain)
  const vault = owner.vault('table', hall, group, epochOf('table', 0))
  const early = await vault.version('early', 'swept before it arrived')
  const first = await sweep(owner.secretTree, [early.vout], owner.party, chain)
  assert.deepEqual(await submit(s.engine, first.toAtomicBEEF()), [0])
  assert.equal(s.ls.tableSize, 1)
  assert.equal(s.ls.rowCount, 0)
  await put(s, early)
  assert.equal(await s.ls.status(cHex(early.tx)), 'retracted', 'the spend joined the row the carrier made')
  assert.deepEqual([s.ls.tableSize, s.ls.rowCount], [0, 1])
  assert.deepEqual(await answer(s.engine, { ...q(vault), secret: vault.secret('early'), version: '1' }), [])
  // Six sweeps of outpoints no carrier used: the table keeps four, oldest dropped first.
  const late = await vault.version('late', 'its sweep left the table')
  const sweeps: Transaction[] = [await sweep(owner.secretTree, [late.vout], owner.party, chain)]
  for (let i = 0; i < 5; i++) sweeps.push(await sweep(owner.secretTree, [owner.nextSecretVout()], owner.party, chain))
  for (const x of sweeps) assert.deepEqual(await submit(s.engine, x.toAtomicBEEF()), [0])
  assert.equal(s.ls.tableSize, 4)
  assert.equal(s.host.count('bsecret_dropped_total', { why: 'table' }), 2)
  await s.ls.flush()
  assert.equal(await s.storage.findOutput(sweeps[0]!.id('hex'), 0, topic), null, 'a sweep whose spends all left the table is deleted')
  assert.notEqual(await s.storage.findOutput(sweeps[5]!.id('hex'), 0, topic), null)
  assert.equal(s.ls.sweepCount, 5, 'four in the table and the one a row records')
  // The one place where order matters: the carrier arrives after its sweep left the table.
  await put(s, late)
  assert.equal(await s.ls.status(cHex(late.tx)), 'unlisted')
  assert.deepEqual(await answer(s.engine, { crypt, spent: `${owner.secretTree.id('hex')}.${late.vout}` }), [])
  // A restart rebuilds the table from the tombstones storage holds, and the row from the journal.
  const again = secretModule(new FakeHost(), { ...config, spendTable: 4 }, [topic], s.journal, chain.tracker).ls
  await again.restore(await s.storage.findUTXOsForTopic(topic, undefined, undefined, true), s.storage)
  assert.deepEqual([again.tableSize, again.rowCount, await again.status(cHex(early.tx))], [4, 2, 'retracted'])
})

test('retention: the floors of 31 days and 24 hours, the clock of a replaced version, and the sticky dropped winner', async () => {
  const chain = new Chain(85000)
  let now = 1_800_000_000
  const s = await setup({ chain, now: () => now })
  const owner = new OwnerSim(crypt, 'retention owner', chain)
  const e0 = epochOf('retention', 0)
  const vault = owner.vault('retention', hall, group, e0)
  const a1 = await vault.version('a', 'one')
  const b1 = await vault.version('b', 'one')
  const t0 = await vault.token({ create: [a1, b1] })
  const stray = await vault.version('stray', 'never listed')
  const swept = await vault.version('swept', 'retracted')
  const nowhere = owner.vault('never minted', hall, group, e0)
  const orphan = await nowhere.version('orphan', 'its vault has no chain here')
  await put(s, a1, b1, stray, swept, orphan)
  await mint(s, t0)
  const held = async (): Promise<boolean[]> => {
    await s.ls.prune()
    return [a1, b1, stray, swept, orphan].map((x) => s.ls.holds(cHex(x.tx)))
  }
  // 24 hours for an unlisted carrier of a vault the host holds no rooted chain of.
  now += day - 1
  assert.deepEqual(await held(), [true, true, true, true, true])
  now += 1
  assert.deepEqual(await held(), [true, true, true, true, false])
  assert.equal(await s.storage.findOutput(orphan.tx.id('hex'), 0, topic), null, 'deleted from storage')
  // Ten days in: version 2 of a is listed, and the sweep arrives.
  now += 9 * day
  const a2 = await vault.version('a', 'two')
  const t1 = await vault.token({ update: [a2] })
  await put(s, a2)
  await mint(s, t1)
  const sw = await sweep(owner.secretTree, [swept.vout], owner.party, chain)
  assert.deepEqual(await submit(s.engine, sw.toAtomicBEEF()), [0])
  // 31 days after the host first saw it, the unlisted carrier goes; the others have later clocks.
  now += 21 * day - 1
  assert.deepEqual(await held(), [true, true, true, true, false])
  now += 1
  assert.deepEqual(await held(), [true, true, false, true, false])
  // 31 days after the token that replaced it was first seen, version 1 of a goes; 31 days after its sweep, the retracted one.
  now += 10 * day - 1
  assert.deepEqual(await held(), [true, true, false, true, false])
  now += 1
  assert.deepEqual(await held(), [false, true, false, false, false])
  // A listed version the set holds is kept for as long as it is current, and so is the token trail.
  now += 3650 * day
  assert.deepEqual(await held(), [false, true, false, false, false])
  assert.ok(s.ls.holds(cHex(a2.tx)))
  assert.deepEqual(await answer(s.engine, { crypt, audit: owner.hex, vault: vault.idHex }), ids([t0, t1]))
  assert.equal(s.host.count('bsecret_dropped_total', { why: 'retention' }), 4)
  // The dropped winner closes its outpoint for good: a later carrier on it, lower or not, is never answered.
  const op = `${owner.secretTree.id('hex')}.${a1.vout}`
  assert.equal(s.ls.outpointRow(op)!.dropped, true)
  for (let i = 0; i < 4; i++) {
    vault.last.delete('a')
    const again = await vault.version('a', `on the dropped outpoint ${i}`, { vout: a1.vout })
    await put(s, again)
    assert.equal(await s.ls.status(cHex(again.tx)), 'superseded')
  }
  vault.last.set('a', a2)
  assert.deepEqual(await answer(s.engine, { ...q(vault), secret: vault.secret('a'), version: '1' }), [])
  assert.deepEqual(await submit(s.engine, a1.tx.toAtomicBEEF()), [], 'a dropped carrier offered again is a duplicate')
  // The rows outlive what they describe, across a restart.
  const again = secretModule(new FakeHost(), config, [topic], s.journal, chain.tracker, () => now).ls
  await again.restore(await s.storage.findUTXOsForTopic(topic, undefined, undefined, true), s.storage)
  assert.equal(again.outpointRow(op)!.dropped, true)
  assert.deepEqual(again.outpointRow(`${owner.secretTree.id('hex')}.${swept.vout}`)!.sweeps, [sw.id('hex')])
  assert.deepEqual((await again.lookup({ service: LookupService, query: { ...q(vault), secret: vault.secret('a'), version: '1' } })).length, 0)
  assert.deepEqual([again.holds(cHex(a1.tx)), again.holds(cHex(a2.tx)), again.holds(cHex(b1.tx))], [false, true, true])
  // A host may keep longer; it may not keep less.
  assert.throws(() => new SecretLookupService({ crypts: new Set([crypt]), host: new FakeHost(), journal: new MemoryJournal(), retentionDays: FloorDays - 1 }), /31-day floor/)
  assert.throws(() => new SecretLookupService({ crypts: new Set([crypt]), host: new FakeHost(), journal: new MemoryJournal(), unheldHours: 23 }), /24-hour floor/)
})

test('the set tree gives the root and the paths of the codec, for every size and index', () => {
  for (const n of [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 33, 100]) {
    const set: Current[] = Array.from({ length: n }, (_, i) => ({ id: sha(`tree/${n}/${i}`), version: i + 1, contentId: sha(`tree/cid/${n}/${i}`), epoch: 0, seq: 0 })).sort((a, b) => (toHex(a.id) < toHex(b.id) ? -1 : 1))
    const tree = new SetTree(set)
    assert.equal(toHex(tree.root), toHex(setRoot(set)), `root of ${n}`)
    for (const i of [0, Math.floor(n / 2), n - 1]) {
      const c = set[i]!
      const want = proveSecret(9, sha('token'), set, c.id)
      assert.equal(tree.index(toHex(c.id)), want.index)
      assert.equal(toHex(encodeContext({ seq: 9, token: sha('token'), index: i, size: tree.size, path: tree.prove(i) })), toHex(encodeContext(want)), `path ${i} of ${n}`)
    }
  }
  assert.equal(toHex(new SetTree([]).root), toHex(setRoot([])))
})

test('the journal file: rows survive a restart, a last line cut short is cut off, and any other bad line stops the load', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'bsecret-journal-'))
  try {
    const chain = new Chain(86000)
    const journal = new FileJournal(dir)
    const host = new FakeHost()
    const m = secretModule(host, config, [topic], journal, chain.tracker)
    const owner = new OwnerSim(crypt, 'journal owner', chain)
    const vault = owner.vault('journal', hall, group, epochOf('journal', 0))
    const a1 = await vault.version('a', 'one')
    const t0 = await vault.token({ create: [a1] })
    for (const [tx, vout] of [[a1.tx, 0], [t0.tx, 0]] as const) m.ls.outputAdmittedByTopic({ mode: 'whole-tx', atomicBEEF: tx.toAtomicBEEF(), outputIndex: vout, topic })
    journal.close()
    const path = join(dir, JournalFile)
    const text = readFileSync(path, 'utf8')
    assert.deepEqual(text.trim().split('\n').map((l) => (JSON.parse(l) as { k: string }).k), ['c', 't'])
    assert.equal(text.includes(owner.hex), false, 'no identity is written')
    // A crash mid-line: the cut line is dropped and the rest is read.
    writeFileSync(path, text + '{"k":"c","op":"')
    const again = new FileJournal(dir)
    assert.equal(again.load().length, 2)
    assert.equal(readFileSync(path, 'utf8'), text)
    const ls = new SecretLookupService({ crypts: new Set([crypt]), host: new FakeHost(), journal: again })
    assert.deepEqual(ls.outpointRow(`${owner.secretTree.id('hex')}.${a1.vout}`), { winner: cHex(a1.tx), others: [], more: 0, dropped: false, sweeps: [] })
    // A line that is not a row stops the load: a row skipped could answer a swept carrier.
    writeFileSync(path, text + '{"k":"z"}\n')
    assert.throws(() => new FileJournal(dir).load(), /line 3 is not a bsecret row/)
    writeFileSync(path, text + 'not json\n')
    assert.throws(() => new FileJournal(dir).load(), /line 3 is not JSON/)
    assert.equal(storedToken(Uint8Array.from(t0.tx.toAtomicBEEF())).token.vault.seq, 0)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('a class the host prices is refused through the engine, and a question for another service is an error', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'bsecret-priced-'))
  try {
    const priced = { ...config, stateDir: dir, prices: new Map([['audit', 5], ['audit-after', 5], ['history', 0]]), listen: { host: '127.0.0.1', port: 1 }, payeeKey: PrivateKey.fromHex('11'.repeat(32)) }
    const m = secretModule(new FakeHost(), priced, [topic], new MemoryJournal(), new Chain(87000).tracker)
    const org = byName(v, 'secret-carrier-api-token-v1').admits!.owner!
    await assert.rejects(m.ls.lookup({ service: LookupService, query: { crypt, audit: org, vault: v.vault } }), /audit is priced on this host/)
    await assert.rejects(m.ls.lookup({ service: LookupService, query: { crypt, audit: org, vault: v.vault, after: '0' } }), /audit-after is priced on this host/)
    assert.deepEqual(await m.ls.lookup({ service: LookupService, query: { crypt, history: org, vault: v.vault, secret: '00'.repeat(32) } }), [], 'a price of 0 charges nothing')
    await assert.rejects(m.ls.lookup({ service: 'ls_other', query: {} }), /this service is ls_bsecret/)
    assert.equal((await m.ls.getMetaData()).name, 'ls_bsecret')
    assert.match(await m.ls.getDocumentation(), /Priceable: `history`/)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
