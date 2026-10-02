/**
 * The terms route over real HTTP: the terms document, free questions with
 * and without BRC-104, each of the four priceable classes answered 402 and
 * then answered once paid by the SDK's own AuthFetch client, every refusal
 * of a payment, the bound on sessions and the handshake budget.
 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import type { AddressInfo } from 'node:net'
import { createServer, request, type IncomingHttpHeaders, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  AuthFetch,
  P2PKH,
  PrivateKey,
  ProtoWallet,
  PublicKey,
  Random,
  Transaction,
  Utils,
  createNonce,
  type CreateActionArgs,
  type CreateActionResult,
  type PeerSession,
  type WalletInterface,
} from '@bsv/sdk'
import type { BudgetConfig, ResponseBudgetConfig } from './budget.js'
import { MemoryJournal } from './journal.js'
import { decodeContext } from './merkle.js'
import { secretModule } from './module.js'
import { BoundedSessions, LedgerReceiver, LookupFront, MemoryReceiver, PaymentProtocol, parsePrices, spentOutpoints, termsDocument, type ReceivedPayment } from './paid.js'
import { config, crypt, engineOf, topic } from './testhost.js'
import { Chain, OwnerSim, Party, PayingWallet, epochOf, fromNowhere } from './testmint.js'
import { FakeHost, MemoryStorage } from './testutil.js'
import { fromHex } from './util.js'

const payee = PrivateKey.fromHex('11'.repeat(32))
const payeeWallet = new ProtoWallet(payee)
const payeeKey = payee.toPublicKey().toString()

interface Rig {
  url: string
  server: Server
  receiver: MemoryReceiver
  wallet: PayingWallet
  client: Party
  chain: Chain
  /** The owner, its vault, a secret of it, and what the priced classes answer for them. */
  org: string
  vault: string
  secret: string
  tokens: string[]
  versions: string[]
  front: LookupFront
  host: FakeHost
  /** Signatures the payee's wallet made. */
  signatures: () => number
}

const servers: Server[] = []
after(() => {
  for (const s of servers) s.close()
})

/** A module with one vault of three tokens and a secret of three versions, engine and storage, and its terms route on a free port. */
async function rig(prices: string, sessions?: { max: number; ttlSeconds: number }, budget?: BudgetConfig, responses?: ResponseBudgetConfig): Promise<Rig> {
  const host = new FakeHost()
  const chain = new Chain(95000)
  const m = secretModule(host, { ...config, prices: parsePrices(prices) }, [topic], new MemoryJournal(), chain.tracker)
  const storage = new MemoryStorage()
  await m.ls.restore([], storage)
  const engine = engineOf(m.module, storage, chain.tracker)
  const owner = new OwnerSim(crypt, 'paid owner', chain)
  const client = new Party('client')
  const vault = owner.vault('paid', 'example_hall_vkqzmtrwxp', fromHex('406504d3fbe1ae098f09a49dffa12222'), epochOf('paid', 0))
  const versions: string[] = []
  for (const [i, value] of ['one', 'two', 'three'].entries()) {
    const x = await vault.version('a', value)
    versions.push(x.tx.id('hex'))
    await engine.submit({ beef: x.tx.toAtomicBEEF(), topics: [topic] })
    const t = await vault.token(i === 0 ? { create: [x] } : { update: [x] })
    await engine.submit({ beef: Array.from(t.beef), topics: [topic] })
  }
  const receiver = new MemoryReceiver()
  let signatures = 0
  const wallet = new ProtoWallet(payee)
  const sign = wallet.createSignature.bind(wallet)
  wallet.createSignature = async (args) => {
    signatures++
    return await sign(args)
  }
  const front = new LookupFront({ ls: m.ls, host, prices: parsePrices(prices), wallet, receiver, headers: chain.tracker, sessions, budget, responses })
  const server = await front.listen(0, '127.0.0.1')
  servers.push(server)
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    server,
    receiver,
    wallet: new PayingWallet(client.key, chain),
    client,
    chain,
    org: owner.hex,
    vault: vault.idHex,
    secret: vault.secret('a'),
    tokens: vault.history.map((t) => t.tx.id('hex')),
    versions,
    front,
    host,
    signatures: () => signatures,
  }
}

const free = (r: Rig): Record<string, string> => ({ crypt, org: r.org, vault: r.vault })
const audit = (r: Rig): Record<string, string> => ({ crypt, audit: r.org, vault: r.vault })
const history = (r: Rig): Record<string, string> => ({ crypt, history: r.org, vault: r.vault, secret: r.secret })

const post = (body: unknown, headers: Record<string, string> = {}): { method: string; headers: Record<string, string>; body: string } => ({
  method: 'POST',
  headers: { 'content-type': 'application/json', ...headers },
  body: JSON.stringify(body),
})

const txids = (a: { outputs: Array<{ beef: number[] }> }): string[] => a.outputs.map((o) => Transaction.fromBEEF(o.beef).id('hex'))

/** AuthFetch prints each payment attempt; the tests read the responses instead. */
async function quietly<T>(f: () => Promise<T>): Promise<T> {
  const saved = { warn: console.warn, info: console.info, error: console.error }
  console.warn = () => {}
  console.info = () => {}
  console.error = () => {}
  try {
    return await f()
  } finally {
    Object.assign(console, saved)
  }
}

interface Seen402 {
  required: unknown
  version: unknown
  prefix: unknown
}

/** Runs f and returns, beside its result, the payment headers of every 402 the route answered while it ran. */
async function watching<T>(r: Rig, f: () => Promise<T>): Promise<{ result: T; seen: Seen402[] }> {
  const seen: Seen402[] = []
  const watch = (_req: IncomingMessage, res: ServerResponse): void => {
    const writeHead = res.writeHead.bind(res) as (status: number, headers: Record<string, string>) => ServerResponse
    res.writeHead = ((status: number, headers: Record<string, string>) => {
      if (status === 402) seen.push({ required: headers['x-bsv-payment-satoshis-required'], version: headers['x-bsv-payment-version'], prefix: headers['x-bsv-payment-derivation-prefix'] })
      return writeHead(status, headers)
    }) as typeof res.writeHead
  }
  r.server.on('request', watch)
  try {
    return { result: await f(), seen }
  } finally {
    r.server.off('request', watch)
  }
}

test('prices: priceable classes only, once each, 0 to 2^53 - 1; the terms document lists them in class order', () => {
  assert.deepEqual([...parsePrices('audit-after=7, audit=20')], [['audit-after', 7], ['audit', 20]])
  assert.deepEqual(parsePrices(undefined).size, 0)
  for (const bad of ['vault=1', 'secret=1', 'sweep=1', 'history', 'history=-1', 'history=01', 'history=1.5', 'history=1,history=2', 'nosuch=1', 'audit=9007199254740992']) {
    assert.throws(() => parsePrices(bad), bad)
  }
  assert.deepEqual(termsDocument(parsePrices('audit-after=7,audit=20,history=0')), {
    service: 'ls_bsecret',
    terms: 1,
    classes: [
      { class: 'history', satoshis: 0 },
      { class: 'audit', satoshis: 20 },
      { class: 'audit-after', satoshis: 7 },
    ],
  })
})

test('the terms document, free questions without authentication, and refusals as errors', async () => {
  const r = await rig('history=5,history-after=5,audit=20,audit-after=20')
  const terms = await fetch(`${r.url}/ls_bsecret/terms`)
  assert.equal(terms.status, 200)
  assert.deepEqual(await terms.json(), termsDocument(parsePrices('history=5,history-after=5,audit=20,audit-after=20')))
  const answered = await fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: free(r) }))
  assert.equal(answered.status, 200)
  assert.deepEqual(txids((await answered.json()) as never), [r.tokens[2]])
  for (const [q, status] of [
    [{ crypt: 'other_crypt_abcdefghij', org: r.org, vault: r.vault }, 400],
    [{ ...free(r), extra: 'x' }, 400],
    [{ crypt, org: r.org }, 400],
  ] as const) {
    assert.equal((await fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: q }))).status, status)
  }
  assert.equal((await fetch(`${r.url}/lookup`, { method: 'POST', body: 'nope' })).status, 400)
  assert.equal((await fetch(`${r.url}/nosuch`)).status, 404)
  for (const q of [audit(r), history(r)]) assert.equal((await fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: q }))).status, 401, 'a priced class is asked over BRC-104')
  // No spelling turns a free question into a priced one, or a priced one into a free one.
  assert.equal((await fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: { ...audit(r), org: r.org } }))).status, 400)
  assert.equal((await fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: free(r) }, { 'x-bsv-auth-nonce': 'x' }))).status, 400)
  // A class and its -after form are priced together: the walk cannot be had page by page for nothing.
  assert.equal((await fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: { ...audit(r), after: '0' } }))).status, 401)

  const none = await rig('')
  assert.equal((await fetch(`${none.url}/ls_bsecret/terms`)).status, 404, 'a host that prices nothing serves no terms')
  const unpriced = await fetch(`${none.url}/lookup`, post({ service: 'ls_bsecret', query: audit(none) }))
  assert.equal(unpriced.status, 200)
  assert.deepEqual(txids((await unpriced.json()) as never), none.tokens)
})

test('each of the four priceable classes is answered 402 over BRC-104 with the price and a prefix, and answered once paid', async () => {
  const r = await rig('history=5,history-after=6,audit=20,audit-after=21')
  const af = new AuthFetch(r.wallet as unknown as WalletInterface)
  const cases: Array<[string, Record<string, string>, number, string[]]> = [
    ['history', history(r), 5, r.versions],
    ['history-after', { ...history(r), after: '1' }, 6, r.versions.slice(1)],
    ['audit', audit(r), 20, r.tokens],
    ['audit-after', { ...audit(r), after: '1' }, 21, r.tokens.slice(2)],
  ]
  for (const [cls, query, price, want] of cases) {
    // The route first answers 402 with the price and a prefix to pay against; the client pays and asks again.
    const { result: paid, seen } = await watching(r, async () => await quietly(async () => await af.fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query }))))
    assert.equal(seen.length, 1, cls)
    assert.deepEqual([seen[0]!.required, seen[0]!.version], [String(price), '1.0'], cls)
    assert.ok(typeof seen[0]!.prefix === 'string' && seen[0]!.prefix.length > 0, `${cls}: a derivation prefix`)
    assert.equal(paid.status, 200, cls)
    assert.equal(paid.headers.get('x-bsv-payment-satoshis-paid'), String(price), cls)
    assert.deepEqual(txids((await paid.json()) as never), want, cls)
  }
  assert.deepEqual(r.receiver.payments.map((p) => [p.class, p.satoshis]), [['history', 5], ['history-after', 6], ['audit', 20], ['audit-after', 21]])
  assert.equal(r.host.count('bsecret_payments_total', { result: 'requested' }), 4)
  assert.equal(r.host.count('bsecret_payments_total', { result: 'accepted' }), 4)
})

test('over BRC-104: a free question is answered and signed; a priced one is answered 402, paid, and answered', async () => {
  const r = await rig('history=5,history-after=5')
  const af = new AuthFetch(r.wallet as unknown as WalletInterface)
  const signed = await af.fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: free(r) }))
  assert.equal(signed.status, 200)
  assert.equal(signed.headers.get('x-bsv-auth-identity-key'), payeeKey, 'signed by the payee')
  const paid = await quietly(async () => await af.fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: history(r) })))
  assert.equal(paid.status, 200)
  assert.equal(paid.headers.get('x-bsv-payment-satoshis-paid'), '5')
  assert.deepEqual(txids((await paid.json()) as never), r.versions)
  assert.equal(r.receiver.payments.length, 1)
  const p = r.receiver.payments[0]!
  assert.equal(p.senderIdentityKey, r.client.hex)
  assert.equal(p.class, 'history')
  assert.equal(p.satoshis, 5)
  // What the payee's wallet internalizes: output 0 pays the key it derives for the remittance.
  const { publicKey } = await payeeWallet.getPublicKey({ protocolID: PaymentProtocol, keyID: `${p.derivationPrefix} ${p.derivationSuffix}`, counterparty: p.senderIdentityKey, forSelf: true })
  const tx = Transaction.fromAtomicBEEF(p.beef)
  assert.equal(tx.outputs[0]!.lockingScript.toHex(), new P2PKH().lock(PublicKey.fromString(publicKey).toAddress()).toHex())
  // A second question is a second payment.
  const again = await quietly(async () => await af.fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: history(r) })))
  assert.equal(again.status, 200)
  assert.equal(r.receiver.payments.length, 2)
})

test('a payment is refused unless the prefix is the server\'s, output 0 pays the price to the derived key, and it verifies; it buys one question', async () => {
  const r = await rig('history=5,history-after=5')
  const af = new AuthFetch(r.wallet as unknown as WalletInterface)
  const ask = async (payment: string): Promise<{ status: number; code?: string }> => {
    const res = await af.fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: history(r) }, { 'x-bsv-payment': payment }))
    const body = (await res.json()) as { code?: string }
    return { status: res.status, code: body.code }
  }
  const prefix = await createNonce(payeeWallet as unknown as WalletInterface)
  const suffix = Utils.toBase64(Random(32))
  const derived = async (counterparty: string): Promise<string> => {
    const { publicKey } = await r.wallet.getPublicKey({ protocolID: PaymentProtocol, keyID: `${prefix} ${suffix}`, counterparty })
    return new P2PKH().lock(PublicKey.fromString(publicKey).toAddress()).toHex()
  }
  const header = (tx: Transaction, pre = prefix): string => JSON.stringify({ derivationPrefix: pre, derivationSuffix: suffix, transaction: Utils.toBase64(tx.toAtomicBEEF()) })
  const good = await r.wallet.pay([{ satoshis: 5, lockingScript: await derived(payeeKey) }])

  assert.deepEqual(await ask('not json'), { status: 400, code: 'ERR_MALFORMED_PAYMENT' })
  assert.deepEqual(await ask(JSON.stringify({ derivationPrefix: prefix, derivationSuffix: suffix })), { status: 400, code: 'ERR_MALFORMED_PAYMENT' })
  assert.deepEqual(await ask(header(good, Utils.toBase64(Random(32)))), { status: 400, code: 'ERR_INVALID_DERIVATION_PREFIX' })
  assert.deepEqual(await ask(header(await r.wallet.pay([{ satoshis: 4, lockingScript: await derived(payeeKey) }]))), { status: 400, code: 'ERR_INVALID_PAYMENT' })
  const other = PrivateKey.fromRandom().toPublicKey().toString()
  assert.deepEqual(await ask(header(await r.wallet.pay([{ satoshis: 5, lockingScript: await derived(other) }]))), { status: 400, code: 'ERR_INVALID_PAYMENT' })
  // Paid from a coin whose block the host's headers do not hold.
  const stray = fromNowhere([{ satoshis: 100000, lockingScript: new P2PKH().lock(r.client.key.toAddress()) }])
  new Chain(99000).mine(stray)
  assert.deepEqual(await ask(header(await r.wallet.pay([{ satoshis: 5, lockingScript: await derived(payeeKey) }], stray))), { status: 400, code: 'ERR_PAYMENT_SPV' })
  assert.equal(r.receiver.payments.length, 0, 'nothing refused was taken')
  assert.equal((await ask(header(good))).status, 200)
  assert.deepEqual(await ask(header(good)), { status: 409, code: 'ERR_PAYMENT_REPLAYED' })
  assert.equal(r.receiver.payments.length, 1)
})

test('the payment ledger keeps every accepted payment across a restart and refuses its txids again', () => {
  const dir = mkdtempSync(join(tmpdir(), 'bsecret-ledger-'))
  try {
    const p: ReceivedPayment = { txid: 'ab'.repeat(32), beef: [1, 1, 1, 1], outputIndex: 0, satoshis: 5, derivationPrefix: 'AA==', derivationSuffix: 'AQ==', senderIdentityKey: payeeKey, class: 'history', inputs: [`${'dd'.repeat(32)}.0`] }
    const a = new LedgerReceiver(dir)
    assert.equal(a.claim(p), 'accepted')
    assert.equal(a.claim(p), 'replayed')
    a.close()
    const b = new LedgerReceiver(dir)
    assert.equal(b.claim(p), 'replayed', 'claimed before the restart')
    assert.equal(b.claim({ ...p, txid: 'cd'.repeat(32) }), 'conflict', 'another transaction spending the coin the first one spent')
    assert.equal(b.claim({ ...p, txid: 'cd'.repeat(32), inputs: [`${'ee'.repeat(32)}.1`] }), 'accepted')
    assert.equal(b.claim({ ...p, txid: 'ef'.repeat(32), inputs: [] }), 'conflict', 'a payment that names no coin is not one')
    b.close()
    const c = new LedgerReceiver(dir)
    assert.equal(c.claim({ ...p, txid: '12'.repeat(32), inputs: [`${'ee'.repeat(32)}.1`, `${'ff'.repeat(32)}.0`] }), 'conflict', 'the coins are remembered across a restart')
    c.close()
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

const session = (nonce: string, key: string, lastUpdate = 0): PeerSession => ({ isAuthenticated: true, sessionNonce: nonce, peerIdentityKey: key, lastUpdate })

test('the BRC-104 session store is bounded: a cap that forgets the least recently used, and an idle life', () => {
  let now = 1_000
  const evicted: string[] = []
  const s = new BoundedSessions(2, 60_000, () => now, (why) => evicted.push(why))
  s.addSession(session('n1', 'k1'))
  s.addSession(session('n2', 'k2'))
  assert.equal(s.getSession('n1')?.sessionNonce, 'n1', 'a lookup touches n1, so n2 is now the least recently used')
  s.addSession(session('n3', 'k3'))
  assert.equal(s.size, 2)
  assert.equal(s.hasSession('n2'), false, 'the least recently used went at the cap')
  assert.deepEqual(evicted, ['cap'])
  assert.equal(s.getSession('k3')?.sessionNonce, 'n3', 'looked up by identity key too')
  s.updateSession(session('n3', 'k3', 5))
  assert.equal(s.size, 2)
  now += 60_000
  assert.equal(s.getSession('n1'), undefined, 'idle for the whole life: forgotten')
  assert.equal(s.getSession('k3'), undefined)
  assert.equal(s.size, 0)
  assert.deepEqual(evicted, ['cap', 'idle', 'idle'])
  s.addSession(session('n4', 'k4'))
  s.removeSession(session('n4', 'k4'))
  assert.equal(s.hasSession('k4'), false)
  assert.throws(() => new BoundedSessions(0, 1), /max/)
  assert.throws(() => s.addSession({ isAuthenticated: false, lastUpdate: 0 }), /sessionNonce/)
})

test('the terms route keeps at most its bound of sessions; a client whose session went shakes hands again', async () => {
  const r = await rig('history=5,history-after=5', { max: 2, ttlSeconds: 600 }, { perSec: 100, burst: 100, perAddressPerSec: 100, addressBurst: 100 })
  const ask = { service: 'ls_bsecret', query: free(r) }
  const clients = [0, 1, 2].map(() => new AuthFetch(new ProtoWallet(PrivateKey.fromRandom()) as unknown as WalletInterface))
  for (const c of clients) assert.equal((await c.fetch(`${r.url}/lookup`, post(ask))).status, 200)
  assert.equal(r.front.sessions.size, 2, 'three handshakes, two sessions kept')
  assert.equal(r.host.count('bsecret_sessions_evicted_total', { why: 'cap' }), 1)
  assert.equal(r.host.gauges.get('bsecret_sessions')?.(), 2)
  // The first client's session went: its client finds its request refused
  // and shakes hands again, which the bound admits in place of the oldest.
  const res = await quietly(async () => await clients[0]!.fetch(`${r.url}/lookup`, post(ask)))
  assert.equal(res.status, 200)
  assert.equal(r.host.count('bsecret_sessions_evicted_total', { why: 'cap' }), 2, 'its new session took the place of the oldest')
  const again = new AuthFetch(new ProtoWallet(PrivateKey.fromRandom()) as unknown as WalletInterface)
  assert.equal((await again.fetch(`${r.url}/lookup`, post(ask))).status, 200, 'a new handshake is answered')
  assert.equal(r.front.sessions.size, 2)
})

/** One BRC-104 initial request, raw, from a fresh identity, sent from localAddress. */
async function shake(url: string, localAddress: string): Promise<{ status: number; retryAfter?: string }> {
  const body = JSON.stringify({
    version: '0.1',
    messageType: 'initialRequest',
    identityKey: PrivateKey.fromRandom().toPublicKey().toString(),
    initialNonce: Utils.toBase64(Random(32)),
    requestedCertificates: { certifiers: [], types: {} },
  })
  return await new Promise((resolve, reject) => {
    const req = request(`${url}/.well-known/auth`, { method: 'POST', localAddress, headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (res) => {
      res.resume()
      res.on('end', () => resolve({ status: res.statusCode ?? 0, retryAfter: res.headers['retry-after'] as string | undefined }))
    })
    req.on('error', reject)
    req.end(body)
  })
}

test('a handshake flood is refused 429 before any signature; a real client still pays its 402 within the budget', async () => {
  const r = await rig('history=5,history-after=5', undefined, { perSec: 0.2, burst: 5, perAddressPerSec: 0.1, addressBurst: 2 })
  // One address floods: its own burst is answered, the rest refused at once.
  const started = Date.now()
  const flood = await Promise.all(Array.from({ length: 50 }, () => shake(r.url, '127.0.0.2')))
  const ok = flood.filter((x) => x.status === 200).length
  const limited = flood.filter((x) => x.status === 429)
  assert.equal(ok, 2, 'the address burst')
  assert.equal(limited.length, 48)
  assert.ok(limited.every((x) => Number(x.retryAfter) >= 1), 'each refusal says when to come back')
  assert.equal(r.signatures(), 2, 'one signature per answered handshake, none for a refused one')
  assert.ok(Date.now() - started < 5000, 'refused cheaply')
  assert.equal(r.host.count('bsecret_handshakes_total', { result: 'accepted' }), 2)
  assert.equal(r.host.count('bsecret_handshakes_total', { result: 'limited_address' }), 48)
  // Other addresses take the rest of the route's burst, then the route refuses.
  const others = await Promise.all(['127.0.0.3', '127.0.0.3', '127.0.0.4', '127.0.0.5'].map((a) => shake(r.url, a)))
  assert.deepEqual(others.map((x) => x.status).sort(), [200, 200, 200, 429])
  assert.equal(r.host.count('bsecret_handshakes_total', { result: 'limited_global' }), 1)
  // The route refills; a real client from its own address shakes hands
  // once, is answered 402, pays, and is answered.
  const wait = Number(others.find((x) => x.status === 429)!.retryAfter)
  assert.ok(wait >= 1 && wait <= 5)
  await new Promise((resolve) => setTimeout(resolve, wait * 1000 + 100))
  const af = new AuthFetch(r.wallet as unknown as WalletInterface)
  const paid = await quietly(async () => await af.fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: history(r) })))
  assert.equal(paid.status, 200)
  assert.equal(paid.headers.get('x-bsv-payment-satoshis-paid'), '5')
  assert.deepEqual(txids((await paid.json()) as never), r.versions)
  assert.equal(r.receiver.payments.length, 1)
  assert.equal(r.host.count('bsecret_handshakes_total', { result: 'accepted' }), 6, 'the client shook hands once')
  // The route spent that token too: the next handshake waits.
  assert.equal((await shake(r.url, '127.0.0.6')).status, 429)
})

test('a malformed handshake inside the budget is counted failed and costs no signature', async () => {
  const r = await rig('history=5,history-after=5')
  const bad = await fetch(`${r.url}/.well-known/auth`, post({ messageType: 'general' }))
  assert.equal(bad.status, 400)
  assert.equal(r.host.count('bsecret_handshakes_total', { result: 'failed' }), 1)
  assert.equal(r.signatures(), 0)
})

test('the terms route answers as the engine does: a secret answer carries its inclusion path as context', async () => {
  const r = await rig('history=5,history-after=5')
  const res = await fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: { ...free(r), secret: r.secret } }))
  assert.equal(res.status, 200)
  const body = (await res.json()) as { outputs: Array<{ beef: number[]; context?: number[] }> }
  assert.deepEqual(txids(body), [r.versions[2]])
  const ctx = decodeContext(Uint8Array.from(body.outputs[0]!.context!))
  assert.deepEqual([ctx.seq, ctx.index, ctx.size], [2, 0, 1])
})

test('one coin pays once: conflicting unbroadcast payments that spend it buy one answer, not one each', async () => {
  const r = await rig('audit=20,audit-after=20')
  // A wallet that pays every question from the same coin: each payment is a
  // different transaction, each verifies, and at most one can ever be mined.
  class OneCoin extends PayingWallet {
    readonly same = this.coin()
    override async createAction(args: CreateActionArgs): Promise<CreateActionResult> {
      const tx = await this.pay((args.outputs ?? []).map((o) => ({ satoshis: o.satoshis, lockingScript: o.lockingScript })), this.same)
      return { tx: tx.toAtomicBEEF(), txid: tx.id('hex') }
    }
  }
  const af = new AuthFetch(new OneCoin(r.client.key, r.chain) as unknown as WalletInterface)
  const statuses: number[] = []
  const codes: Array<string | undefined> = []
  for (let i = 0; i < 4; i++) {
    const res = await quietly(async () => await af.fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: audit(r) })))
    statuses.push(res.status)
    codes.push(res.status === 200 ? undefined : ((await res.json()) as { code?: string }).code)
  }
  assert.deepEqual(statuses, [200, 409, 409, 409])
  assert.deepEqual(codes, [undefined, 'ERR_PAYMENT_CONFLICT', 'ERR_PAYMENT_CONFLICT', 'ERR_PAYMENT_CONFLICT'])
  assert.equal(r.receiver.payments.length, 1)
  assert.equal(new Set(r.receiver.payments.flatMap((p) => p.inputs)).size, 1)
  assert.equal(r.host.count('bsecret_payments_total', { result: 'replayed' }), 3)
})

test('the ledger reads the coins of a line written before lines carried them, from its transaction', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'bsecret-ledger-'))
  try {
    const chain = new Chain(96000)
    const wallet = new PayingWallet(PrivateKey.fromRandom(), chain)
    const coin = wallet.coin()
    const lock = new P2PKH().lock(payee.toAddress()).toHex()
    const first = await wallet.pay([{ satoshis: 5, lockingScript: lock }], coin)
    const second = await wallet.pay([{ satoshis: 6, lockingScript: lock }], coin)
    const line = { txid: first.id('hex'), beef: Utils.toBase64(first.toAtomicBEEF()), outputIndex: 0, satoshis: 5, derivationPrefix: 'AA==', derivationSuffix: 'AQ==', senderIdentityKey: payeeKey, class: 'history', at: 1 }
    writeFileSync(join(dir, 'payments.jsonl'), JSON.stringify(line) + '\n')
    const ledger = new LedgerReceiver(dir)
    const p: ReceivedPayment = { txid: second.id('hex'), beef: second.toAtomicBEEF(), outputIndex: 0, satoshis: 6, derivationPrefix: 'AA==', derivationSuffix: 'AQ==', senderIdentityKey: payeeKey, class: 'history', inputs: spentOutpoints(second) }
    assert.deepEqual(spentOutpoints(second), [`${coin.id('hex')}.0`])
    assert.equal(ledger.claim(p), 'conflict')
    ledger.close()
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

/** A server in front of the route that keeps each request as it arrived, to send it again. */
async function recording(r: Rig): Promise<{ url: string; port: number; requests: Array<{ method: string; url: string; headers: IncomingHttpHeaders; body: Buffer[] }> }> {
  const requests: Array<{ method: string; url: string; headers: IncomingHttpHeaders; body: Buffer[] }> = []
  const server = createServer((req, res) => {
    const body: Buffer[] = []
    requests.push({ method: req.method ?? 'GET', url: req.url ?? '/', headers: { ...req.headers }, body })
    req.on('data', (c: Buffer) => body.push(c))
    r.front.handler(req, res)
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  servers.push(server)
  const port = (server.address() as AddressInfo).port
  return { url: `http://127.0.0.1:${port}`, port, requests }
}

test('a signed request sent again byte for byte is refused before any signature', async () => {
  const r = await rig('history=5,history-after=5')
  const rec = await recording(r)
  const af = new AuthFetch(r.wallet as unknown as WalletInterface)
  assert.equal((await af.fetch(`${rec.url}/lookup`, post({ service: 'ls_bsecret', query: free(r) }))).status, 200)
  const sent = rec.requests.find((x) => x.url === '/lookup' && x.headers['x-bsv-auth-request-id'] !== undefined)!
  const before = r.signatures()
  const replay = async (): Promise<number> =>
    await new Promise((resolve, reject) => {
      const q = request({ host: '127.0.0.1', port: rec.port, path: sent.url, method: sent.method, headers: sent.headers }, (res) => {
        res.resume()
        res.on('end', () => resolve(res.statusCode ?? 0))
      })
      q.on('error', reject)
      q.end(Buffer.concat(sent.body))
    })
  const statuses = new Set<number>()
  for (let i = 0; i < 50; i++) statuses.add(await replay())
  // And at once, while none of them is yet answered.
  for (const s of await Promise.all(Array.from({ length: 20 }, replay))) statuses.add(s)
  assert.deepEqual([...statuses], [401])
  assert.equal(r.signatures(), before, 'no signature for a replay')
  assert.equal(r.host.count('bsecret_requests_total', { result: 'replayed' }), 70)
  // The session itself goes on.
  assert.equal((await af.fetch(`${rec.url}/lookup`, post({ service: 'ls_bsecret', query: free(r) }))).status, 200)
})

test('a session has a budget of signed responses: over it a request is refused 429 and nothing is signed', async () => {
  const r = await rig('history=5,history-after=5', undefined, undefined, { perSec: 0.5, burst: 3 })
  const af = new AuthFetch(r.wallet as unknown as WalletInterface)
  const ask = async (): Promise<number> => {
    try {
      return (await quietly(async () => await af.fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: free(r) })))).status
    } catch {
      // The SDK's client raises on a response the server did not sign.
      return 429
    }
  }
  const statuses: number[] = []
  for (let i = 0; i < 6; i++) statuses.push(await ask())
  assert.deepEqual(statuses, [200, 200, 200, 429, 429, 429])
  assert.equal(r.signatures(), 4, 'the handshake and three responses')
  assert.equal(r.host.count('bsecret_requests_total', { result: 'limited' }), 3)
  // Another session has its own budget.
  const other = new AuthFetch(new ProtoWallet(PrivateKey.fromRandom()) as unknown as WalletInterface)
  assert.equal((await other.fetch(`${r.url}/lookup`, post({ service: 'ls_bsecret', query: free(r) }))).status, 200)
  // It refills.
  await new Promise((resolve) => setTimeout(resolve, 2100))
  assert.equal(await ask(), 200)
})

test('a class and its -after form are priced together or not at all', () => {
  for (const bad of ['history=5', 'audit=20', 'audit-after=20', 'history=5,history-after=0', 'history=5,history-after=5,audit=20']) {
    assert.throws(() => parsePrices(bad), /priced together/, bad)
  }
  for (const good of ['history=5,history-after=6', 'audit=0', 'audit=0,audit-after=0', 'history=5,history-after=5,audit=20,audit-after=20']) parsePrices(good)
})
