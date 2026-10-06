/**
 * The host module end to end on a local reference overlay host, loaded
 * from the bundle (bundle/bsecret-module.js) through OVERLAY_MODULES.
 *
 *   node dist/e2e.js /path/to/reference-host
 *
 * The reference host directory holds its compiled dist/index.js and its
 * node_modules. The bundle is staged as a deployment places it: copied into
 * a modules/ directory whose only node_modules is the host's, so it loads
 * with nothing but what the host provides, and the SDK it imports is the
 * host's own copy. The run needs Docker, for a throwaway MySQL (the host's
 * only store), and serves block headers itself in the host's native shape
 * (/v1/root/<height>, /v1/tip) for a local chain it mines on; the module
 * reads the same source through OVERLAY_CHAIN_TRACKER_URL.
 *
 * The vault is keyed to borg's golden group (testborg.ts): alice, bob and
 * carol hold epoch 0, and the removal of bob begins epoch 1. The run creates
 * the vault, puts two secrets, reads them as each member from the host's
 * answers, removes bob, acknowledges the new epoch, shows the chain refusing
 * a create while it is in debt, re-keys, reads the new versions as the
 * members who remain and fails to as bob, sweeps the old versions, asks the
 * audit class through the terms route and pays its 402, verifies the trail
 * as an auditor, restarts the host, and asks everything again of the
 * restored index. Everything it starts, it stops.
 */
import { execFileSync, spawn, type ChildProcess } from 'node:child_process'
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import { TestNetwork, serveNetwork } from './testnetwork.js'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { AuthFetch, PrivateKey, Transaction, type WalletInterface } from '@bsv/sdk'
import { goldenGroup, identity } from './testborg.js'
import { Chain, OwnerSim, PayingWallet, fromNowhere, sweep, type EpochRef } from './testmint.js'
import { auditTrail, readSecret, type Ask, type AskedOutput } from './testread.js'
import { readVectors } from './testutil.js'
import { fromHex } from './util.js'

const crypt = 'example_crypt_hmqzvtkwrx'
const topic = `tm_bsecret_${crypt}`
const password = 'bsecret-e2e'
const payeeKey = '11'.repeat(32)
const prices = 'history=5,history-after=5,audit=20,audit-after=20'
const bundle = fileURLToPath(new URL('../bundle/bsecret-module.js', import.meta.url))

function fail(msg: string): never {
  throw new Error(`e2e: ${msg}`)
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms))

/** Stages the bundle beside the reference host's node_modules; returns the module's path and the root to remove. */
function stage(dir: string): { file: string; root: string } {
  const root = mkdtempSync(join(tmpdir(), 'bsecret-e2e-'))
  symlinkSync(resolve(dir, 'node_modules'), join(root, 'node_modules'))
  mkdirSync(join(root, 'modules', 'bsecret'), { recursive: true })
  mkdirSync(join(root, 'state'))
  const file = join(root, 'modules', 'bsecret', 'bsecret-module.js')
  copyFileSync(bundle, file)
  return { file, root }
}

/** The chain's headers, served in the reference host's native shape, read at each request. */
async function headers(chain: Chain, net: TestNetwork): Promise<Server> {
  const server = createServer((req, res) => {
    void serveNetwork(net, req, res).then((served) => {
      if (served) return
        const m = /^\/v1\/root\/(\d+)$/.exec(req.url ?? '')
        const body = req.url === '/v1/tip' ? { height: chain.tip } : m !== null && chain.roots.has(Number(m[1])) ? { merkleRoot: chain.roots.get(Number(m[1])) } : undefined
        res.writeHead(body === undefined ? 404 : 200, { 'content-type': 'application/json' })
        res.end(JSON.stringify(body ?? {}))
    })
  })
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r))
  return server
}

function docker(...args: string[]): string {
  return execFileSync('docker', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
}

async function mysql(): Promise<{ id: string; port: number }> {
  const id = docker('run', '-d', '--rm', '-e', `MYSQL_ROOT_PASSWORD=${password}`, '-e', 'MYSQL_DATABASE=overlay', '-p', '127.0.0.1::3306', '--tmpfs', '/var/lib/mysql', 'mysql:9')
  const port = Number(docker('port', id, '3306/tcp').split('\n')[0]!.split(':').pop())
  for (let i = 0; i < 120; i++) {
    try {
      // Over TCP, which the image's initialisation server does not listen on.
      docker('exec', id, 'mysql', '-h127.0.0.1', '-uroot', `-p${password}`, '-e', 'select 1')
      return { id, port }
    } catch {
      await sleep(1000)
    }
  }
  docker('rm', '-f', id)
  fail('MySQL did not come up')
}

async function freePort(): Promise<number> {
  return await new Promise<number>((r) => {
    const s = createServer().listen(0, '127.0.0.1', () => {
      const p = (s.address() as AddressInfo).port
      s.close(() => r(p))
    })
  })
}

interface Host {
  proc: ChildProcess
  url: string
  terms: string
  out: string[]
}

interface Ports {
  db: number
  headers: number
  host: number
  terms: number
}

async function startHost(dir: string, staged: { file: string; root: string }, p: Ports): Promise<Host> {
  const out: string[] = []
  const proc = spawn(process.execPath, [resolve(dir, 'dist/index.js')], {
    env: {
      PATH: process.env['PATH'] ?? '',
      OVERLAY_TOPICS: topic,
      OVERLAY_MODULES: staged.file,
      OVERLAY_KNEX_URL: `mysql://root:${password}@127.0.0.1:${p.db}/overlay`,
      OVERLAY_CHAIN_TRACKER_URL: `http://127.0.0.1:${p.headers}`,
      OVERLAY_ADMIN_TOKEN: 'bsecret-e2e',
      OVERLAY_LISTEN: '127.0.0.1',
      OVERLAY_PORT: String(p.host),
      BSECRET_CRYPTS: crypt,
      BSECRET_STATE_DIR: join(staged.root, 'state'),
      BSECRET_LISTEN: `127.0.0.1:${p.terms}`,
      BSECRET_PRICES: prices,
      BSECRET_PAYEE_KEY: payeeKey,
      BSECRET_ARCADE_URL: `http://127.0.0.1:${p.headers}/arcade`,
      BSECRET_ASSET_URL: `http://127.0.0.1:${p.headers}`,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  proc.stdout!.on('data', (b: Buffer) => out.push(b.toString()))
  proc.stderr!.on('data', (b: Buffer) => out.push(b.toString()))
  const url = `http://127.0.0.1:${p.host}`
  for (let i = 0; i < 60; i++) {
    if (proc.exitCode !== null) fail(`the host exited ${proc.exitCode}:\n${out.join('')}`)
    try {
      if ((await fetch(`${url}/readyz`)).status === 200) return { proc, url, terms: `http://127.0.0.1:${p.terms}`, out }
    } catch {
      // not listening yet
    }
    await sleep(500)
  }
  proc.kill('SIGKILL')
  fail(`the host did not become ready:\n${out.join('')}`)
}

async function stopHost(h: Host): Promise<void> {
  if (h.proc.exitCode !== null) return
  const done = new Promise((r) => h.proc.once('exit', r))
  h.proc.kill('SIGTERM')
  await done
}

async function submit(h: Host, beef: number[] | Uint8Array, what: string): Promise<number[]> {
  const res = await fetch(`${h.url}/submit`, {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream', 'x-topics': topic },
    body: Uint8Array.from(beef),
  })
  const body = (await res.json()) as Record<string, { outputsToAdmit?: number[] }>
  if (res.status !== 200) fail(`submit ${what}: ${res.status} ${JSON.stringify(body)}`)
  return body[topic]?.outputsToAdmit ?? []
}

interface Answer {
  outputs?: Array<{ beef: number[]; outputIndex: number; context?: number[] }>
  error?: string
}

const asked = (body: Answer): AskedOutput[] => (body.outputs ?? []).map((o) => ({ tx: Transaction.fromBEEF(o.beef), beef: o.beef, context: o.context }))

/** A question to a /lookup route: the answer's outputs, or its error. */
async function query(base: string, q: Record<string, string>): Promise<AskedOutput[] | string> {
  const res = await fetch(`${base}/lookup`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ service: 'ls_bsecret', query: q }) })
  const body = (await res.json()) as Answer
  if (res.status !== 200) return `${res.status} ${body.error ?? ''}`
  return asked(body)
}

const askAt =
  (base: string): Ask =>
  async (q) => {
    const a = await query(base, q)
    if (typeof a === 'string') fail(`${JSON.stringify(q)}: ${a}`)
    return a
  }

function expect(what: string, got: unknown, want: unknown): void {
  const g = JSON.stringify(got)
  const w = JSON.stringify(want)
  if (g !== w) fail(`${what}: got ${g}, want ${w}`)
  console.log(`ok  ${what}`)
}

function metric(text: string, name: string, ...labels: string[]): string | undefined {
  return text
    .split('\n')
    .find((l) => l.startsWith(name) && labels.every((x) => l.includes(x)))
    ?.trim()
    .split(' ')
    .pop()
}

async function main(): Promise<void> {
  const dir = process.argv[2]
  if (dir === undefined) fail('usage: node dist/e2e.js /path/to/reference-host')
  const chain = new Chain(30000)
  const group = goldenGroup()
  const derivation = readVectors<{ group: { epochs: Array<{ epoch: number; symmetricKey: string; epochId: string }> } }>('derivation-v1.json')
  // The group's epochs as the organisation that sampled their keys holds them.
  const epochs: EpochRef[] = derivation.group.epochs.map((e) => ({ epoch: e.epoch, id: fromHex(e.epochId), symmetric: fromHex(e.symmetricKey) }))
  // The owner's trees are mined before the host starts, so its header source has a tip.
  const owner = new OwnerSim(crypt, 'the organisation', chain, { key: identity('org') })
  const [alice, bob, carol] = [identity('alice'), identity('bob'), identity('carol')]
  // The group's own tokens are borg's; the blocks stand for where an auditor finds them.
  const began = [chain.mine(fromNowhere([])).merklePath!.blockHeight]
  const net = new TestNetwork(chain)
  const hdr = await headers(chain, net)
  const db = await mysql()
  const ports: Ports = { db: db.port, headers: (hdr.address() as AddressInfo).port, host: await freePort(), terms: await freePort() }
  const staged = stage(dir)
  let host: Host | undefined
  try {
    host = await startHost(dir, staged, ports)
    const mounted = host.out.join('').split('\n').find((l) => l.includes('bsecret module mounted'))
    if (mounted === undefined || !mounted.includes('with @lightwebinc/bcommon')) fail(`the bundle's mount line is missing:\n${host.out.join('')}`)
    console.log("ok  the bundle mounts from beside the host's node_modules, reading the host's header source")

    // Create a vault on the group at epoch 0, and put two secrets.
    const vault = owner.vault('production', group.hall, group.group, epochs[0]!)
    const who = { crypt, org: owner.hex, vault: vault.idHex }
    const db1 = await vault.version('db/password', 'hunter2')
    const api1 = await vault.version('api/token', 'tok_0001', { label: 'confidential' })
    expect('submit the carrier of db/password', await submit(host, db1.tx.toAtomicBEEF(), 'db 1'), [0])
    expect('submit the carrier of api/token', await submit(host, api1.tx.toAtomicBEEF(), 'api 1'), [0])
    expect('a carrier before its token is pending', (await askAt(host.url)({ ...who, pending: vault.secret('db/password') })).map((o) => o.tx.id('hex')), [db1.tx.id('hex')])
    const t0 = await vault.token({ create: [db1, api1] })
    // A worse BEEF of the same token first: refused, raising, nothing recorded.
    expect('the first token as Atomic BEEF admits nothing', await submit(host, t0.tx.toAtomicBEEF(), 'worse token'), [])
    expect('the first token with its parent is admitted after it', await submit(host, t0.beef, 'vault 0'), [0])
    const ask = askAt(host.url)
    const txids = async (q: Record<string, string>): Promise<string[]> => (await ask(q)).map((o) => o.tx.id('hex'))
    expect('vault: the latest token', await txids(who), [t0.tx.id('hex')])
    expect('vaults: the owner has one', await txids({ crypt, vaultsOf: owner.hex }), [t0.tx.id('hex')])
    expect('secrets: both, each with its inclusion path', (await ask({ crypt, org: owner.hex, secretsOf: vault.idHex })).map((o) => (o.context?.length ?? 0) > 0), [true, true])
    expect('label: one confidential', await txids({ ...who, label: 'confidential' }), [api1.tx.id('hex')])

    // Every member of epoch 0 reads both, from the host's answers and its own headers.
    const read = async (name: string, member: PrivateKey) => await readSecret(askAt(host!.url), chain.tracker, who, vault.secret(name), group, member)
    for (const [name, m] of [['alice', alice], ['bob', bob], ['carol', carol]] as const) {
      expect(`${name} reads db/password under epoch 0`, await read('db/password', m), { value: 'hunter2', version: 1, epoch: 0 })
    }
    expect('carol reads api/token under epoch 0', await read('api/token', carol), { value: 'tok_0001', version: 1, epoch: 0 })

    // The group removes bob: epoch 1, whose key bob never receives.
    began.push(chain.mine(fromNowhere([])).merklePath!.blockHeight)
    // The vault acknowledges it: everything it holds is stale.
    const ack = await vault.token({ epoch: epochs[1]! })
    expect('acknowledge epoch 1: two secrets stale', [ack.rec.epoch, ack.rec.stale, await submit(host, ack.beef, 'ack')], [1, 2, [0]])
    // In debt, the chain admits only re-keying or retirement.
    const trial = vault.fork()
    const sneaked = await trial.token({ create: [await trial.version('new/secret', 'created in debt')], mutate: (r) => (r.stale = 0) })
    expect('a create while in debt is refused', await submit(host, sneaked.beef, 'create in debt'), [])
    const db2 = await vault.version('db/password', 'correct horse battery staple')
    const api2 = await vault.version('api/token', 'tok_0002', { label: 'confidential' })
    expect('submit the re-keyed db/password', await submit(host, db2.tx.toAtomicBEEF(), 'db 2'), [0])
    expect('submit the re-keyed api/token', await submit(host, api2.tx.toAtomicBEEF(), 'api 2'), [0])
    const settle = await vault.token({ update: [db2, api2] })
    expect('re-key both: nothing stale', [settle.rec.stale, await submit(host, settle.beef, 'settle')], [0, [0]])
    const new1 = await vault.version('new/secret', 'created once the vault settled')
    expect('submit a new secret', await submit(host, new1.tx.toAtomicBEEF(), 'new 1'), [0])
    const t3 = await vault.token({ create: [new1] })
    expect('settled, the chain admits a create again', await submit(host, t3.beef, 'create'), [0])

    // The members who remain read the new versions; the removed member cannot.
    for (const [name, m] of [['alice', alice], ['carol', carol]] as const) {
      expect(`${name} reads the re-keyed db/password`, await read('db/password', m), { value: 'correct horse battery staple', version: 2, epoch: 1 })
    }
    expect('carol reads the re-keyed api/token', await read('api/token', carol), { value: 'tok_0002', version: 2, epoch: 1 })
    for (const name of ['db/password', 'api/token', 'new/secret']) expect(`bob cannot read ${name}: no wrap of epoch 1 names him`, await read(name, bob), { refused: 'entry' })

    // The versions under the ended epoch are swept: honest hosts stop answering them.
    expect('version: the old db/password is still answered until it is swept', await txids({ ...who, secret: vault.secret('db/password'), version: '1' }), [db1.tx.id('hex')])
    const sw = await sweep(owner.secretTree, [db1.vout, api1.vout], owner.party, chain)
    expect('submit the sweep', await submit(host, sw.toAtomicBEEF(), 'sweep'), [0])
    expect('version: the swept version is answered no more', await txids({ ...who, secret: vault.secret('db/password'), version: '1' }), [])
    expect('sweep: the spend of its funding outpoint', await txids({ crypt, spent: `${owner.secretTree.id('hex')}.${db1.vout}` }), [sw.id('hex')])

    const metrics = await (await fetch(`${host.url}/metrics`)).text()
    expect('the refusals are counted by reason', [metric(metrics, 'bsecret_refused_total', 'reason="beef"'), metric(metrics, 'bsecret_refused_total', 'reason="debt"')], ['1', '1'])
    expect('the host counts them as failed topic admissions', metric(metrics, 'overlay_host_topic_failures_total', topic), '2')
    expect('every token is consistent', metric(metrics, 'bsecret_token_status_total', 'status="consistent"'), '4')
    expect('two carriers were retracted', metric(metrics, 'bsecret_retractions_total'), '2')

    // Priced: refused on the host's own route, 402 then answered on the terms route.
    const auditQ = { crypt, audit: owner.hex, vault: vault.idHex }
    const refused = await query(host.url, auditQ)
    if (typeof refused !== 'string' || !refused.includes('priced')) fail(`audit on the host route: ${JSON.stringify(refused)}`)
    console.log('ok  audit on the host route is refused: it is priced')
    const terms = (await (await fetch(`${host.terms}/ls_bsecret/terms`)).json()) as unknown
    expect('the terms document', terms, {
      service: 'ls_bsecret',
      terms: 1,
      classes: [
        { class: 'history', satoshis: 5 },
        { class: 'history-after', satoshis: 5 },
        { class: 'audit', satoshis: 20 },
        { class: 'audit-after', satoshis: 20 },
      ],
    })
    expect('a free class on the terms route', (await askAt(host.terms)(who)).map((o) => o.tx.id('hex')), [t3.tx.id('hex')])
    expect('audit on the terms route without BRC-104', await query(host.terms, auditQ), '401 ')
    const wallet = new PayingWallet(PrivateKey.fromHex('22'.repeat(32)), chain)
    let paidTotal = 0
    // One BRC-104 session per host process: a client shakes hands once.
    let client = new AuthFetch(wallet as unknown as WalletInterface)
    /** A priced question through its 402, paid by the SDK's own client. */
    const paid: Ask = async (q) => {
      const saved = { warn: console.warn, info: console.info }
      console.warn = () => {}
      console.info = () => {}
      try {
        const res = await client.fetch(`${host!.terms}/lookup`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ service: 'ls_bsecret', query: q }),
        })
        if (res.status !== 200) fail(`paid ${JSON.stringify(q)}: ${res.status}`)
        paidTotal += Number(res.headers.get('x-bsv-payment-satoshis-paid') ?? 0)
        return asked((await res.json()) as Answer)
      } finally {
        Object.assign(console, saved)
      }
    }
    const trail = vault.history.map((m) => m.tx.id('hex'))
    expect("audit paid through its 402: the vault's whole chain", (await paid(auditQ)).map((o) => o.tx.id('hex')), trail)
    expect('history paid through its 402: the versions of db/password the host still answers', (await paid({ crypt, history: owner.hex, vault: vault.idHex, secret: vault.secret('db/password') })).map((o) => o.tx.id('hex')), [db2.tx.id('hex')])
    // The auditor: no key, its own headers, the tokens the audit class answers.
    const groupEpochs = group.epochs.slice(0, 2).map((e, i) => ({ epoch: e.epoch, epochId: e.id, height: began[i]!, removed: e.removed }))
    const audited = await auditTrail(paid, chain.tracker, who, groupEpochs)
    expect('an auditor verifies the trail from headers', [audited.report.ok, audited.tokens.map((t) => t.tx.id('hex')), audited.report.statuses], [true, trail, Array(4).fill('consistent')])
    expect(
      'the window of the removal: began, acknowledged, settled',
      audited.report.windows,
      [{ epoch: 1, removed: true, began: began[1], late: 0, acknowledged: ack.tx.merklePath!.blockHeight, settled: settle.tx.merklePath!.blockHeight, stale: 0 }],
    )
    const ledger = (): number => readFileSync(join(staged.root, 'state', 'payments.jsonl'), 'utf8').trim().split('\n').length
    // Two questions, then the audit's first page and the empty page that ends it.
    expect('the payments are in the ledger', [ledger(), paidTotal], [4, 65])
    {
      const lines = readFileSync(join(staged.root, 'state', 'payments.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l) as { txid: string; decision?: string })
      expect('every payment was taken fast', lines.every((l) => l.decision === 'fast'), true)
      expect('the host broadcast every payment before answering', lines.every((l) => net.sent.includes(l.txid)), true)
    }

    // Restart: the index is rebuilt from storage and the rows.
    const snapshot = async (h: Host): Promise<Record<string, string[]>> => {
      const a = async (q: Record<string, string>): Promise<string[]> => (await askAt(h.url)(q)).map((o) => o.tx.id('hex'))
      return {
        vault: await a(who),
        seq0: await a({ ...who, seq: '0' }),
        vaults: await a({ crypt, vaultsOf: owner.hex }),
        secrets: await a({ crypt, org: owner.hex, secretsOf: vault.idHex }),
        secret: await a({ ...who, secret: vault.secret('api/token') }),
        old: await a({ ...who, secret: vault.secret('api/token'), version: '1' }),
        label: await a({ ...who, label: 'confidential' }),
        sweep: await a({ crypt, spent: `${owner.secretTree.id('hex')}.${api1.vout}` }),
      }
    }
    const before = await snapshot(host)
    await stopHost(host)
    host = await startHost(dir, staged, ports)
    client = new AuthFetch(wallet as unknown as WalletInterface)
    const restored = host.out.join('').split('\n').find((l) => l.includes('module lookup restored from storage'))
    if (restored === undefined) fail(`no restore line:\n${host.out.join('')}`)
    console.log('ok  the module restored from storage')
    expect('restored: the same answers, spent tokens included', await snapshot(host), before)
    expect('restored: the set is the re-keyed one', before['secrets']!.length, 3)
    expect('restored: alice reads the re-keyed db/password', await read('db/password', alice), { value: 'correct horse battery staple', version: 2, epoch: 1 })
    expect('restored: bob still cannot', await read('db/password', bob), { refused: 'entry' })
    expect('restored: the swept version stays swept', before['old'], [])
    const again = await auditTrail(paid, chain.tracker, who, groupEpochs)
    expect('restored: the audit paid again, and verified again', [again.report.ok, again.tokens.length, again.report.windows[0]!.settled], [true, 4, settle.tx.merklePath!.blockHeight])
    expect('restored: a replayed token is a duplicate', await submit(host, settle.beef, 'settle again'), [])
    expect('restored: the create in debt is still refused', await submit(host, sneaked.beef, 'create in debt again'), [])
    const m2 = await (await fetch(`${host.url}/metrics`)).text()
    expect('restored: every token folded consistent again, none pending', [metric(m2, 'bsecret_token_status_total', 'status="consistent"'), metric(m2, 'bsecret_token_status_total', 'status="pending"')], ['4', '0'])
    expect('restored: the ledger went on', ledger(), 6)
    console.log('e2e: PASS')
  } finally {
    if (host !== undefined) await stopHost(host)
    docker('rm', '-f', db.id)
    hdr.close()
    rmSync(staged.root, { recursive: true, force: true })
  }
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e)
  process.exit(1)
})
