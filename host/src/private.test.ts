/**
 * Private crypts over real HTTP: the host's own lookup refuses every
 * question about one, the terms route answers it over BRC-104 to the
 * crypt's organizations and to the members of their groups a borg host
 * names, and to nobody else; a borg host that does not answer refuses the
 * asker until one does.
 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import type { AddressInfo } from 'node:net'
import { createServer, type Server } from 'node:http'
import { AuthFetch, PrivateKey, ProtoWallet, Transaction, type WalletInterface } from '@bsv/sdk'
import { LookupFront, MemoryReceiver } from '@lightwebinc/bcommon/host'
import { MemoryJournal } from './journal.js'
import { parseConfig, secretModule } from './module.js'
import { bsecretRoute, parsePrices } from './paid.js'
import { listenGated, parseHallURLs, parsePrivate } from './private.js'
import { config, crypt, engineOf, topic } from './testhost.js'
import { Chain, OwnerSim, Party, epochOf } from './testmint.js'
import { FakeHost, MemoryStorage } from './testutil.js'
import { fromHex } from './util.js'

const servers: Server[] = []
after(() => {
  for (const s of servers) s.close()
})

const hall = 'example_hall_vkqzmtrwxp'

/** A borg host's lookup: member-of answers one output for each key in members, none otherwise; down answers 503. */
async function borgHost(members: Set<string>, seen: Array<Record<string, string>>): Promise<{ url: string; down: (v: boolean) => void }> {
  let isDown = false
  const s = createServer((req, res) => {
    let body = ''
    req.on('data', (c: Buffer) => (body += c.toString()))
    req.on('end', () => {
      if (isDown) {
        res.writeHead(503).end()
        return
      }
      const q = (JSON.parse(body) as { query: Record<string, string> }).query
      seen.push(q)
      const outputs = members.has(q['memberOf']!) && q['hall'] === hall ? [{ beef: [1], outputIndex: 0 }] : []
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ type: 'output-list', outputs }))
    })
  })
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r))
  servers.push(s)
  return { url: `http://127.0.0.1:${(s.address() as AddressInfo).port}`, down: (v) => (isDown = v) }
}

const quietly = async <T>(f: () => Promise<T>): Promise<T> => {
  const saved = { warn: console.warn, info: console.info, error: console.error }
  console.warn = console.info = console.error = () => {}
  try {
    return await f()
  } finally {
    Object.assign(console, saved)
  }
}

test('BSECRET_PRIVATE and BSECRET_HALL_URL: every mistake refused', () => {
  const org = new Party('org').hex
  assert.deepEqual([...parsePrivate(`${crypt}=${org}`, [crypt]).get(crypt)!], [org])
  assert.equal(parsePrivate('', [crypt]).size, 0)
  assert.throws(() => parsePrivate(`other_crypt_abcdefghij=${org}`, [crypt]), /does not carry/)
  assert.throws(() => parsePrivate(`${crypt}=${org};${crypt}=${org}`, [crypt]), /twice/)
  assert.throws(() => parsePrivate(`${crypt}=`, [crypt]), /not an identity key/)
  assert.throws(() => parsePrivate(`${crypt}=${org.toUpperCase()}`, [crypt]), /not an identity key/)
  assert.throws(() => parsePrivate(`Bad=${org}`, [crypt]), /not a crypt identifier/)
  assert.deepEqual(parseHallURLs('http://127.0.0.1:8080/, https://hall.example'), ['http://127.0.0.1:8080', 'https://hall.example'])
  assert.throws(() => parseHallURLs('ftp://x'), /not an http or https base URL/)
  const env = { BSECRET_CRYPTS: crypt, BSECRET_STATE_DIR: '/tmp/x', BSECRET_HEADERS_URL: 'http://127.0.0.1:1', BSECRET_PRIVATE: `${crypt}=${org}` }
  assert.throws(() => parseConfig(env), /BSECRET_LISTEN .* and BSECRET_PAYEE_KEY .* are required/)
  const routed = { ...env, BSECRET_LISTEN: '127.0.0.1:8443', BSECRET_PAYEE_KEY: '11'.repeat(32) }
  assert.throws(() => parseConfig(routed), /BSECRET_HALL_URL/)
  const c = parseConfig({ ...routed, BSECRET_HALL_URL: 'http://127.0.0.1:2', BSECRET_MEMBER_TTL: '5' })
  assert.equal(c.memberTTL, 5)
  assert.deepEqual([...c.private!.keys()], [crypt])
  assert.throws(() => parseConfig({ ...routed, BSECRET_HALL_URL: 'http://127.0.0.1:2', BSECRET_MEMBER_TTL: '0' }), /BSECRET_MEMBER_TTL/)
})

test('a private crypt: the host\'s own lookup refuses it; the route answers its organization and its groups\' members, and nobody else', async () => {
  const host = new FakeHost()
  const chain = new Chain(96000)
  const owner = new OwnerSim(crypt, 'private owner', chain)
  const member = new Party('private member')
  const stranger = new Party('private stranger')
  const seen: Array<Record<string, string>> = []
  const borg = await borgHost(new Set([member.hex]), seen)
  const prices = parsePrices('audit=20,audit-after=20')
  const m = secretModule(host, { ...config, prices, private: parsePrivate(`${crypt}=${owner.hex}`, [crypt]), hallURLs: [borg.url], memberTTL: 1 }, [topic], new MemoryJournal(), chain.tracker)
  const storage = new MemoryStorage()
  await m.ls.restore([], storage)
  const engine = engineOf(m.module, storage, chain.tracker)
  const vault = owner.vault('private', hall, fromHex('406504d3fbe1ae098f09a49dffa12222'), epochOf('private', 0))
  const x = await vault.version('a', 'one')
  await engine.submit({ beef: x.tx.toAtomicBEEF(), topics: [topic] })
  const t = await vault.token({ create: [x] })
  await engine.submit({ beef: Array.from(t.beef), topics: [topic] })
  assert.deepEqual(m.ls.hallsOf(crypt, owner.hex), [hall])

  const q = { crypt, org: owner.hex, vault: vault.idHex }
  // The engine's own lookup: no asker, refused.
  await assert.rejects(engine.lookup({ service: 'ls_bsecret', query: q }), /ask over BRC-104: crypt .* is private on this host/)

  const wallet = new ProtoWallet(PrivateKey.fromHex('11'.repeat(32)))
  const front = new LookupFront({ ...bsecretRoute(m.ls), host, prices, wallet, receiver: new MemoryReceiver(), headers: chain.tracker, budget: { perSec: 100, burst: 100, perAddressPerSec: 100, addressBurst: 100 } })
  const server = await listenGated(front, m.members!, 0, '127.0.0.1')
  servers.push(server)
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/lookup`
  const post = { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: 'ls_bsecret', query: q }) }
  const clients = new Map<Party, AuthFetch>()
  const client = (who: Party): AuthFetch => {
    if (!clients.has(who)) clients.set(who, new AuthFetch(who.wallet as unknown as WalletInterface))
    return clients.get(who)!
  }
  const ask = async (who: Party | undefined, body = post): Promise<{ status: number; text: string }> => {
    const res = who === undefined ? await fetch(url, body) : await quietly(async () => await client(who).fetch(url, body))
    return { status: res.status, text: await res.text() }
  }

  // Without BRC-104: refused, and no borg host is asked.
  let r = await ask(undefined)
  assert.equal(r.status, 400)
  assert.match(r.text, /ask over BRC-104: crypt .* is private on this host/)
  assert.equal(seen.length, 0)
  // The organization itself, with no borg host asked; then a member of its group.
  for (const who of [owner.party, member]) {
    r = await ask(who)
    assert.equal(r.status, 200, r.text)
    const outs = (JSON.parse(r.text) as { outputs: Array<{ beef: number[] }> }).outputs
    assert.deepEqual(
      outs.map((o) => Transaction.fromBEEF(o.beef).id('hex')),
      [t.tx.id('hex')],
    )
  }
  assert.deepEqual(seen, [{ hall, org: owner.hex, memberOf: member.hex }])
  // A key that is in none of its groups.
  r = await ask(stranger)
  assert.equal(r.status, 400)
  assert.match(r.text, /not served to this key/)
  // A priced class is refused before any price is asked: a stranger pays nothing for a refusal.
  const auditQ = { ...post, body: JSON.stringify({ service: 'ls_bsecret', query: { crypt, audit: owner.hex, vault: vault.idHex } }) }
  assert.equal((await ask(stranger, auditQ)).status, 400)
  // A member is asked the price: the SDK's client, whose wallet here cannot pay, tries to.
  await assert.rejects(ask(member, auditQ), /not implemented/)
  // A borg host that does not answer: the asker is refused until one does.
  borg.down(true)
  await new Promise((res) => setTimeout(res, 1100))
  r = await ask(member)
  assert.equal(r.status, 400)
  assert.match(r.text, /membership unknown/)
  borg.down(false)
  assert.equal((await ask(member)).status, 200)
  assert.equal(host.counters.get('bsecret_private_total{result="unauthenticated"}'), 2)
  assert.ok((host.counters.get('bsecret_private_total{result="served"}') ?? 0) >= 4)
  assert.equal(host.counters.get('bsecret_private_total{result="unknown"}'), 1)
  assert.ok((host.counters.get('bsecret_private_total{result="refused"}') ?? 0) >= 2)
})
