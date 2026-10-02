/**
 * The compiled module as a reference host loads it: imported by absolute
 * path, its default export called with the host's logger and metrics, the
 * result held to the loader's shape rules, and its configuration refused
 * rather than guessed.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import type { Module, ModuleHost } from '@lightwebinc/bcommon'
import { TokenStatuses, parseConfig, parseCrypts } from './module.js'
import { FakeHost } from './testutil.js'
import { Reasons } from './tm_bsecret.js'

const crypt = 'example_crypt_hmqzvtkwrx'
const other = 'support_mkvbqzxtrw'
const headers = { BSECRET_HEADERS_URL: 'http://127.0.0.1:1' }

test('BSECRET_CRYPTS: crypt identifiers, once each; anything else refused', () => {
  assert.deepEqual(parseCrypts(` ${crypt},${other} `), [crypt, other])
  for (const bad of [undefined, '', 'example_crypt', `${crypt},${crypt}`, 'Example_crypt_hmqzvtkwrx', `${crypt},`, 'a__b_abcdefghij', `${'x'.repeat(29)}_abcdefghij`]) {
    assert.throws(() => parseCrypts(bad), JSON.stringify(bad))
  }
})

test('the configuration: a state directory and a native header source are required, floors hold, and a price needs its route and payee', () => {
  const base = { BSECRET_CRYPTS: crypt, BSECRET_STATE_DIR: '/var/lib/bsecret', ...headers }
  const c = parseConfig(base)
  assert.deepEqual([c.retentionDays, c.unheldHours, c.maxBEEF, c.maxSweepInputs, c.spendTable, c.prices.size, c.listen, c.headersURL], [31, 24, 262144, 1024, 65536, 0, undefined, 'http://127.0.0.1:1'])
  assert.throws(() => parseConfig({ BSECRET_CRYPTS: crypt, ...headers }), /BSECRET_STATE_DIR/)
  assert.throws(() => parseConfig({ ...base, BSECRET_STATE_DIR: 'relative' }), /BSECRET_STATE_DIR/)
  // The header source: the module's own, or the host's when it is a native URL.
  assert.equal(parseConfig({ BSECRET_CRYPTS: crypt, BSECRET_STATE_DIR: '/x', OVERLAY_CHAIN_TRACKER_URL: 'https://headers.example' }).headersURL, 'https://headers.example')
  assert.equal(parseConfig({ ...base, OVERLAY_CHAIN_TRACKER_URL: 'https://headers.example' }).headersURL, 'http://127.0.0.1:1', "the module's own setting wins")
  assert.throws(() => parseConfig({ BSECRET_CRYPTS: crypt, BSECRET_STATE_DIR: '/x', OVERLAY_CHAIN_TRACKER_URL: 'woc:main' }), /BSECRET_HEADERS_URL is required/)
  assert.throws(() => parseConfig({ BSECRET_CRYPTS: crypt, BSECRET_STATE_DIR: '/x' }), /BSECRET_HEADERS_URL is required/)
  assert.throws(() => parseConfig({ ...base, BSECRET_HEADERS_URL: 'ftp://x' }), /BSECRET_HEADERS_URL/)
  assert.throws(() => parseConfig({ ...base, BSECRET_RETENTION_DAYS: '30' }), /at least 31/)
  assert.throws(() => parseConfig({ ...base, BSECRET_UNHELD_HOURS: '23' }), /at least 24/)
  assert.throws(() => parseConfig({ ...base, BSECRET_MAX_BEEF: '1000' }), /at least 262144/)
  assert.throws(() => parseConfig({ ...base, BSECRET_MAX_SWEEP_INPUTS: '1023' }), /at least 1024/)
  assert.throws(() => parseConfig({ ...base, BSECRET_SPEND_TABLE: '100' }), /at least 65536/)
  assert.throws(() => parseConfig({ ...base, BSECRET_LISTEN: 'nowhere' }), /host:port/)
  assert.throws(() => parseConfig({ ...base, BSECRET_PAYEE_KEY: 'AB'.repeat(32) }), /64 lowercase hex/)
  assert.throws(() => parseConfig({ ...base, BSECRET_PRICES: 'audit=5,audit-after=5' }), /BSECRET_LISTEN/)
  assert.throws(() => parseConfig({ ...base, BSECRET_PRICES: 'audit=5', BSECRET_LISTEN: '127.0.0.1:1', BSECRET_PAYEE_KEY: '11'.repeat(32) }), /audit and audit-after are priced together/)
  assert.throws(() => parseConfig({ ...base, BSECRET_PRICES: 'audit=0' }), /BSECRET_LISTEN/)
  assert.throws(() => parseConfig({ ...base, BSECRET_PRICES: 'audit=5,audit-after=5', BSECRET_LISTEN: '127.0.0.1:1' }), /BSECRET_PAYEE_KEY/)
  assert.throws(() => parseConfig({ ...base, BSECRET_PRICES: 'vault=1', BSECRET_LISTEN: '127.0.0.1:1' }), /free class/)
  const priced = parseConfig({ ...base, BSECRET_PRICES: 'history=5,history-after=5,audit=20,audit-after=20', BSECRET_LISTEN: '[::1]:8081', BSECRET_PAYEE_KEY: '11'.repeat(32) })
  assert.deepEqual([priced.listen, priced.prices.get('history'), priced.prices.get('audit')], [{ host: '::1', port: 8081 }, 5, 20])
  assert.deepEqual(
    (({ retentionDays, unheldHours, maxBEEF, spendTable }) => [retentionDays, unheldHours, maxBEEF, spendTable])(parseConfig({ ...base, BSECRET_RETENTION_DAYS: '90', BSECRET_UNHELD_HOURS: '48', BSECRET_MAX_BEEF: '1048576', BSECRET_SPEND_TABLE: '100000' })),
    [90, 48, 1048576, 100000],
  )
  assert.deepEqual(c.sessions, { max: 10000, ttlSeconds: 600 }, 'the BRC-104 session bound has a default')
  assert.deepEqual(parseConfig({ ...base, BSECRET_SESSIONS: '50', BSECRET_SESSION_TTL: '60' }).sessions, { max: 50, ttlSeconds: 60 })
  assert.throws(() => parseConfig({ ...base, BSECRET_SESSIONS: '0' }), /BSECRET_SESSIONS/)
  assert.deepEqual(c.handshakes, { perSec: 4, burst: 8, perAddressPerSec: 1, addressBurst: 4 }, 'the handshake budget has a default')
  assert.deepEqual(
    parseConfig({ ...base, BSECRET_HANDSHAKES_PER_SEC: '2.5', BSECRET_HANDSHAKE_BURST: '5', BSECRET_HANDSHAKES_PER_ADDR_PER_SEC: '0.5', BSECRET_HANDSHAKE_ADDR_BURST: '2' }).handshakes,
    { perSec: 2.5, burst: 5, perAddressPerSec: 0.5, addressBurst: 2 },
  )
  assert.deepEqual(c.responses, { perSec: 5, burst: 20 }, 'the budget of signed responses a session has a default')
  assert.deepEqual(parseConfig({ ...base, BSECRET_RESPONSES_PER_SEC: '0.5', BSECRET_RESPONSE_BURST: '3' }).responses, { perSec: 0.5, burst: 3 })
  assert.throws(() => parseConfig({ ...base, BSECRET_RESPONSE_BURST: '0' }), /BSECRET_RESPONSE_BURST/)
  for (const [k, v] of [['BSECRET_HANDSHAKES_PER_SEC', '0'], ['BSECRET_HANDSHAKES_PER_ADDR_PER_SEC', 'fast'], ['BSECRET_HANDSHAKE_BURST', '0'], ['BSECRET_HANDSHAKE_ADDR_BURST', '1.5']]) {
    assert.throws(() => parseConfig({ ...base, [k!]: v }), new RegExp(k!))
  }
})

/** The reference loader's checks on what a factory returned. */
function loaderShape(m: unknown): Module {
  assert.ok(typeof m === 'object' && m !== null)
  const mod = m as Module
  assert.ok(Object.keys(mod.topics ?? {}).length + Object.keys(mod.lookups ?? {}).length > 0, 'mounts something')
  for (const tm of Object.values(mod.topics ?? {})) assert.equal(typeof tm.identifyAdmissibleOutputs, 'function')
  for (const ls of Object.values(mod.lookups ?? {})) {
    assert.equal(typeof ls.lookup, 'function')
    assert.equal(typeof ls.outputAdmittedByTopic, 'function')
    assert.equal(typeof ls.admissionMode, 'string')
    assert.equal(typeof (ls as { restore?: unknown }).restore, 'function', 'the index is in memory, so the module must restore')
  }
  return mod
}

test('dist/module.js loads by absolute path, as OVERLAY_MODULES names it, and mounts each crypt and ls_bsecret', async () => {
  const path = fileURLToPath(new URL('./module.js', import.meta.url))
  const imported = (await import(pathToFileURL(path).href)) as { default: (h: ModuleHost) => Promise<Module> }
  assert.equal(typeof imported.default, 'function')
  const keys = ['BSECRET_CRYPTS', 'BSECRET_STATE_DIR', 'BSECRET_HEADERS_URL', 'OVERLAY_TOPICS', 'OVERLAY_SYNC_PEERS'] as const
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]))
  const dir = mkdtempSync(join(tmpdir(), 'bsecret-module-'))
  try {
    process.env['BSECRET_CRYPTS'] = `${crypt},${other}`
    process.env['BSECRET_STATE_DIR'] = dir
    process.env['BSECRET_HEADERS_URL'] = 'http://127.0.0.1:1'
    process.env['OVERLAY_TOPICS'] = `tm_anytx,tm_bsecret_${crypt},tm_bsecret_${other}`
    const host = new FakeHost()
    const mod = loaderShape(await imported.default(host))
    assert.deepEqual(Object.keys(mod.topics!).sort(), [`tm_bsecret_${crypt}`, `tm_bsecret_${other}`])
    assert.deepEqual(Object.keys(mod.lookups!), ['ls_bsecret'])
    for (const reason of Reasons) assert.ok(host.counters.has(`bsecret_refused_total{reason="${reason}"}`), `${reason} is preset`)
    for (const status of TokenStatuses) assert.ok(host.counters.has(`bsecret_token_status_total{status="${status}"}`), `${status} is preset`)
    for (const g of ['bsecret_crypts', 'bsecret_vaults', 'bsecret_tokens', 'bsecret_tokens_pending', 'bsecret_carriers', 'bsecret_sweeps', 'bsecret_outpoint_rows', 'bsecret_spend_table']) assert.ok(host.gauges.has(g), g)
    assert.equal(host.gauges.get('bsecret_crypts')!(), 2)
    const mounted = host.lines.find((l) => l.msg === 'bsecret module mounted')
    assert.deepEqual([mounted?.extra?.['lookup'], mounted?.extra?.['build'], mounted?.extra?.['terms']], ['ls_bsecret', 'unbundled', 'none'])
    // A tm_bsecret_ topic the host carries but the module does not configure
    // would fall to the admit-everything default: refused.
    process.env['OVERLAY_TOPICS'] = `tm_bsecret_${crypt},tm_bsecret_third_mkvbqzxtrw`
    await assert.rejects(imported.default(new FakeHost()), /tm_bsecret_third_mkvbqzxtrw/)
    // A crypt is joined by replay: a host that would synchronise one as unspent outputs does not start.
    process.env['OVERLAY_TOPICS'] = `tm_anytx,tm_bsecret_${crypt},tm_bsecret_${other}`
    process.env['OVERLAY_SYNC_PEERS'] = `tm_anytx=https://peer.example;tm_bsecret_${crypt}=https://peer.example`
    await assert.rejects(imported.default(new FakeHost()), /OVERLAY_SYNC_PEERS names tm_bsecret_example_crypt_hmqzvtkwrx/)
    process.env['OVERLAY_SYNC_PEERS'] = 'tm_anytx=https://peer.example'
    loaderShape(await imported.default(new FakeHost()))
    delete process.env['BSECRET_CRYPTS']
    await assert.rejects(imported.default(new FakeHost()), /BSECRET_CRYPTS/)
  } finally {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k]
      else process.env[k] = saved[k]
    }
    rmSync(dir, { recursive: true, force: true })
  }
})
