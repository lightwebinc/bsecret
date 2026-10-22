/**
 * The exit criterion of this application, as far as a host can show it,
 * through the module's answers on the real engine: a revoke forces
 * rotation, and an auditor verifies the trail from headers.
 *
 * The vault is keyed to borg's own golden group, read from its records as a
 * member reads them: alice, bob and carol hold epoch 0; the group removes
 * bob and begins epoch 1, whose key bob never receives. Once the vault
 * acknowledges epoch 1, every host admits onto its chain only the re-keying
 * or the retirement of what it held, until nothing is stale. The members
 * who remain read the re-keyed versions from the host's answers; bob does
 * not. The audit classes then answer a trail that an auditor holding no key
 * verifies against its own headers, and whose windows say how long each
 * secret stayed under the epoch bob held.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { Engine } from '@bsv/overlay'
import { symmetricKey } from './keyed.js'
import { goldenGroup, identity, openEpoch } from './testborg.js'
import { crypt, outputs, setup, submit, topic } from './testhost.js'
import { Chain, OwnerSim, fromNowhere, type EpochRef, type Minted, type Version } from './testmint.js'
import { auditTrail, readSecret, walk, type Ask } from './testread.js'
import { readVectors } from './testutil.js'
import { fromHex, toHex } from './util.js'

const g = goldenGroup()
const derivation = readVectors<{ group: { epochs: Array<{ epoch: number; key: string; symmetricKey: string; epochId: string }> } }>('derivation-v1.json')
/** The group's epochs as the organization that sampled their keys holds them. */
const epochs: EpochRef[] = derivation.group.epochs.map((e) => ({ epoch: e.epoch, id: fromHex(e.epochId), symmetric: fromHex(e.symmetricKey) }))
const [alice, bob, carol] = [identity('alice'), identity('bob'), identity('carol')]
const askOf = (e: Engine): Ask => async (query) => await outputs(e, query)

test('the fixture is borg\'s group: three epochs, the removal at epoch 1, and each member opens exactly the epochs it held', async () => {
  assert.deepEqual(g.epochs.map((e) => [e.epoch, toHex(e.id), e.removed]), epochs.map((e) => [e.epoch, toHex(e.id), e.epoch === 1]))
  assert.equal(toHex(g.org), identity('org').toPublicKey().toString())
  for (const e of derivation.group.epochs) {
    assert.equal(toHex(symmetricKey(fromHex(e.key))), e.symmetricKey)
    for (const m of [alice, carol]) assert.equal(toHex((await openEpoch(g, e.epoch, m)).symmetric!), e.symmetricKey)
  }
  assert.equal(toHex((await openEpoch(g, 0, bob)).symmetric!), derivation.group.epochs[0]!.symmetricKey)
  assert.deepEqual([await openEpoch(g, 1, bob), await openEpoch(g, 2, bob)], [{ refused: 'entry' }, { refused: 'entry' }], 'no wrap of a later epoch names bob')
  assert.deepEqual(await openEpoch(g, 0, identity('dave')), { refused: 'entry' })
})

test('revoke forces rotation: once the vault acknowledges the new epoch its chain admits only re-keying or retirement until nothing is stale, and an auditor verifies the trail from headers', async () => {
  const chain = new Chain(91000)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'the organization', chain, { key: identity('org') })
  assert.equal(owner.hex, toHex(g.org), "the vault's owner is the group's organization")
  const vault = owner.vault('production', g.hall, g.group, epochs[0]!)
  const who = { crypt, org: owner.hex, vault: vault.idHex }
  const ask = askOf(s.engine)
  const put = async (...vs: Version[]): Promise<void> => {
    for (const x of vs) assert.deepEqual(await submit(s.engine, x.tx.toAtomicBEEF()), [0])
  }
  const mint = async (m: Minted): Promise<void> => assert.deepEqual(await submit(s.engine, m.beef), [0], `seq ${m.rec.seq}`)
  const refusedFor = async (m: Minted, reason: string): Promise<void> => {
    const before = s.host.count('bsecret_refused_total', { reason })
    assert.deepEqual(await submit(s.engine, m.beef), [], `seq ${m.rec.seq} is refused`)
    assert.equal(s.host.count('bsecret_refused_total', { reason }), before + 1, reason)
    assert.equal(await s.storage.doesAppliedTransactionExist({ txid: m.tx.id('hex'), topic }), false, 'raised: nothing is recorded')
  }
  const read = async (name: string, member: typeof alice) => await readSecret(ask, chain.tracker, who, vault.secret(name), g, member)
  // The group's tokens are borg's, mined on the same chain: the heights an auditor finds for them.
  const began = [chain.mine(fromNowhere([])).merklePath!.blockHeight]

  // Epoch 0: the vault, three secrets, and every member reads them.
  const db1 = await vault.version('db/password', 'hunter2')
  const api1 = await vault.version('api/token', 'tok_0001')
  const tls1 = await vault.version('tls/key', 'a key that cannot be replaced')
  await put(db1, api1, tls1)
  await mint(await vault.token({ create: [db1, api1, tls1] }))
  for (const m of [alice, bob, carol]) assert.deepEqual(await read('db/password', m), { value: 'hunter2', version: 1, epoch: 0 })

  // The group removes bob: epoch 1 begins, and its key is wrapped to alice and carol only.
  began.push(chain.mine(fromNowhere([])).merklePath!.blockHeight)
  // The owner acknowledges it in the vault's next token: everything it holds is stale.
  const ack = await vault.token({ epoch: epochs[1]! })
  assert.deepEqual([ack.rec.epoch, ack.rec.count, ack.rec.stale], [1, 3, 3])
  await mint(ack)
  assert.deepEqual(await read('db/password', bob), { value: 'hunter2', version: 1, epoch: 0 }, 'until it is re-keyed, the current version is one bob opens')

  // From that token on the chain admits nothing but re-keying or retirement.
  const trial = async (build: (f: typeof vault) => Promise<Minted>): Promise<Minted> => await build(vault.fork())
  // A secret created while three are stale.
  await refusedFor(await trial(async (f) => await f.token({ create: [await f.version('new/secret', 'created in debt')], mutate: (r) => (r.stale = 0) })), 'debt')
  // The debt declared cleared with nothing re-keyed.
  await refusedFor(await trial(async (f) => await f.token({ mutate: (r) => (r.stale = 0) })), 'debt')
  // One re-keyed, two declared.
  await refusedFor(await trial(async (f) => await f.token({ update: [await f.version('db/password', 'x')], mutate: (r) => (r.stale = 1) })), 'debt')
  // The epoch taken back.
  await refusedFor(await trial(async (f) => await f.token({ epoch: epochs[0]!, mutate: (r) => (r.stale = 0) })), 'epoch')

  // The rotation: a new value under a new content key for each credential.
  const db2 = await vault.version('db/password', 'correct horse battery staple')
  await put(db2)
  const rekey1 = await vault.token({ update: [db2] })
  await mint(rekey1)
  assert.equal(rekey1.rec.stale, 2)
  // Still in debt: a create is still refused, and so is an update of the secret already re-keyed that claims to clear more.
  await refusedFor(await trial(async (f) => await f.token({ create: [await f.version('new/secret', 'still in debt')], mutate: (r) => (r.stale = 0) })), 'debt')
  const api2 = await vault.version('api/token', 'tok_0002')
  await put(api2)
  // The key that cannot be replaced is re-keyed with the same value; here the owner retires it instead.
  const settle = await vault.token({ update: [api2], retire: ['tls/key'] })
  await mint(settle)
  assert.deepEqual([settle.rec.stale, settle.rec.count], [0, 2])
  // Stale is 0: the chain admits a create again.
  const new1 = await vault.version('new/secret', 'created once the vault settled')
  await put(new1)
  await mint(await vault.token({ create: [new1] }))

  // The members who remain read the re-keyed versions; bob reads none of them.
  for (const m of [alice, carol]) {
    assert.deepEqual(await read('db/password', m), { value: 'correct horse battery staple', version: 2, epoch: 1 })
    assert.deepEqual(await read('api/token', m), { value: 'tok_0002', version: 2, epoch: 1 })
    assert.deepEqual(await read('new/secret', m), { value: 'created once the vault settled', version: 1, epoch: 1 })
  }
  for (const name of ['db/password', 'api/token', 'new/secret']) assert.deepEqual(await read(name, bob), { refused: 'entry' }, `${name}: bob holds no wrap of epoch 1`)
  assert.deepEqual(await read('tls/key', alice), { refused: 'listing' }, 'retired')
  // What removal does not do: the version bob could read is still answered by version, and still opens for him.
  const old = await ask({ ...who, secret: vault.secret('db/password'), version: '1' })
  assert.equal(old.length, 1)

  // The audit: every token of the chain, verified by someone who holds no key.
  const groupEpochs = g.epochs.slice(0, 2).map((e, i) => ({ epoch: e.epoch, epochId: e.id, height: began[i]!, removed: e.removed }))
  const { report, tokens } = await auditTrail(ask, chain.tracker, who, groupEpochs)
  assert.equal(report.ok, true)
  assert.deepEqual(tokens.map((t) => t.tx.id('hex')), vault.history.map((m) => m.tx.id('hex')))
  assert.deepEqual(report.statuses, Array(5).fill('consistent'))
  assert.deepEqual(report.windows, [
    { epoch: 1, removed: true, began: began[1], late: 0, acknowledged: ack.tx.merklePath!.blockHeight, settled: settle.tx.merklePath!.blockHeight, stale: 0 },
  ])
  assert.ok(report.windows[0]!.settled - report.windows[0]!.began > 0, 'the exposure window the owner signed, in blocks')
  // The free walk gives the same chain, token by token.
  assert.deepEqual((await walk(ask, chain.tracker, who)).map((t) => t.tx.id('hex')), tokens.map((t) => t.tx.id('hex')))
  // Headers the auditor does not hold verify nothing: the audit is the auditor's, not the host's.
  const blind = await auditTrail(ask, new Chain(1).tracker, who, groupEpochs)
  assert.deepEqual([blind.report.ok, blind.tokens.length], [false, 0])
  // A trail cut at its end still passes its checks, and says what was stale where it ends.
  const cut = await auditTrail(async (query) => (query['after'] === undefined ? (await ask(query)).slice(0, 3) : []), chain.tracker, who, groupEpochs)
  assert.deepEqual([cut.report.ok, cut.tokens.length], [true, 3])
  assert.equal(cut.report.windows[0]!.stale, 2)
})

test('nothing forces the acknowledgement: an owner that goes on writing under the old epoch is admitted, and the audit counts it', async () => {
  const chain = new Chain(92000)
  const s = await setup({ chain })
  const owner = new OwnerSim(crypt, 'the organization', chain, { key: identity('org') })
  const vault = owner.vault('behind', g.hall, g.group, epochs[0]!)
  const who = { crypt, org: owner.hex, vault: vault.idHex }
  const began = [chain.mine(fromNowhere([])).merklePath!.blockHeight]
  const a1 = await vault.version('a', 'one')
  assert.deepEqual(await submit(s.engine, a1.tx.toAtomicBEEF()), [0])
  assert.deepEqual(await submit(s.engine, (await vault.token({ create: [a1] })).beef), [0])
  began.push(chain.mine(fromNowhere([])).merklePath!.blockHeight)
  // After the removal, two more tokens under epoch 0: every host admits them.
  for (const value of ['two', 'three']) {
    const next = await vault.version('a', value)
    assert.deepEqual(await submit(s.engine, next.tx.toAtomicBEEF()), [0])
    assert.deepEqual(await submit(s.engine, (await vault.token({ update: [next] })).beef), [0])
  }
  // bob, removed, still reads the current value: it was written under the key he holds.
  assert.deepEqual(await readSecret(askOf(s.engine), chain.tracker, who, vault.secret('a'), g, bob), { value: 'three', version: 3, epoch: 0 })
  const groupEpochs = g.epochs.slice(0, 2).map((e, i) => ({ epoch: e.epoch, epochId: e.id, height: began[i]!, removed: e.removed }))
  const { report } = await auditTrail(askOf(s.engine), chain.tracker, who, groupEpochs)
  assert.equal(report.ok, true)
  assert.deepEqual(report.windows, [{ epoch: 1, removed: true, began: began[1], late: 2, acknowledged: 0, settled: 0, stale: 1 }])
})
