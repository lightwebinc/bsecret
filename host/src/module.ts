/**
 * The bsecret host module: `tm_bsecret_<name>_<suffix>` for each configured
 * crypt and `ls_bsecret` for all of them, loaded into a reference overlay
 * host by path (`OVERLAY_MODULES=/abs/path/to/bsecret-module.js`). The host
 * carries no bsecret code; this file's default export is the factory it
 * calls.
 *
 * Configuration is read from the environment when the host calls the
 * factory (docs/host.md):
 *
 *   BSECRET_CRYPTS           required: the crypt identifiers, a comma list
 *   BSECRET_STATE_DIR        required: an absolute directory kept for the
 *                            host's life, for the outpoint rows and the
 *                            payment ledger
 *   BSECRET_HEADERS_URL      the native header source (/v1/root/<height>,
 *                            /v1/tip) admission checks proofs against;
 *                            OVERLAY_CHAIN_TRACKER_URL when that is one
 *   BSECRET_RETENTION_DAYS   how long a carrier no longer answered is kept;
 *                            at least and by default 31
 *   BSECRET_UNHELD_HOURS     the same for a carrier of a vault whose chain
 *                            the host does not hold; at least and by
 *                            default 24
 *   BSECRET_MAX_BEEF         the host's BEEF bound; at least and by default
 *                            262144
 *   BSECRET_MAX_SWEEP_INPUTS the inputs of a sweep the host accepts; at
 *                            least and by default 1024
 *   BSECRET_SPEND_TABLE      spends of outpoints no carrier used that the
 *                            host keeps; at least and by default 65536
 *   BSECRET_LISTEN           host:port of the terms route (paid.ts)
 *   BSECRET_PRICES           the classes priced, e.g.
 *                            history=5,history-after=5,audit=20,audit-after=20;
 *                            a class and its -after form together
 *   BSECRET_PAYEE_KEY        the payee's private key, 64 hex characters
 *   BSECRET_SESSIONS         the most BRC-104 sessions the terms route
 *                            keeps; default 10000
 *   BSECRET_SESSION_TTL      seconds an idle BRC-104 session is kept;
 *                            default 600
 *   BSECRET_HANDSHAKES_PER_SEC, BSECRET_HANDSHAKE_BURST
 *                            the BRC-104 handshakes a second the terms
 *                            route answers, and at once; default 4 and 8
 *                            (budget.ts)
 *   BSECRET_HANDSHAKES_PER_ADDR_PER_SEC, BSECRET_HANDSHAKE_ADDR_BURST
 *                            the same for one remote address; default 1
 *                            and 4
 *   BSECRET_RESPONSES_PER_SEC, BSECRET_RESPONSE_BURST
 *                            the signed responses a second one BRC-104
 *                            session is given, and at once; default 5 and
 *                            20
 *
 * Every `tm_bsecret_` topic in OVERLAY_TOPICS must be a crypt named here,
 * because a bsecret topic left to the host's default manager would admit
 * anything, and none may be named in OVERLAY_SYNC_PEERS. Every mistake
 * throws, and the host refuses to start.
 */
import { isAbsolute } from 'node:path'
import type { Server } from 'node:http'
import { PrivateKey, ProtoWallet, type ChainTracker } from '@bsv/sdk'
import type { Module, ModuleHost } from '@lightwebinc/bcommon'
import { DefaultMaxBEEF, DefaultMaxSweepInputs } from './admit.js'
import { DefaultBudget, DefaultResponseBudget, type BudgetConfig, type ResponseBudgetConfig } from './budget.js'
import { HeaderTracker, isNativeSource } from './headers.js'
import { FileJournal, type Journal } from './journal.js'
import { FloorDays, FloorUnheldHours, MinSpendTable, SecretLookupService } from './ls_bsecret.js'
import { DefaultMaxSessions, DefaultSessionTTL, LedgerReceiver, LookupFront, parsePrices } from './paid.js'
import { LookupService, TopicPrefix, checkCrypt, topic } from './secrec.js'
import { AdmitKinds, Reasons, SecretTopicManager } from './tm_bsecret.js'

/**
 * The bundle's banner, which the bundle step defines (scripts/bundle.js):
 * the package and library versions the host is running. The tsc tree
 * leaves it undefined.
 */
declare const BSECRET_BUILD: string | undefined

/** How often retention runs, seconds. */
const PruneEvery = 3600

/** The token statuses the index reports (spec section 11.2), each counted. */
export const TokenStatuses = ['consistent', 'pending', 'set-mismatch', 'stale-mismatch', 'commitment-reuse'] as const

export interface Config {
  crypts: string[]
  stateDir: string
  headersURL: string
  retentionDays: number
  unheldHours: number
  maxBEEF: number
  maxSweepInputs: number
  spendTable: number
  listen?: { host: string; port: number }
  prices: Map<string, number>
  payeeKey?: PrivateKey
  sessions: { max: number; ttlSeconds: number }
  handshakes: BudgetConfig
  responses: ResponseBudgetConfig
}

/** Parses BSECRET_CRYPTS. Throws on anything it cannot take exactly. */
export function parseCrypts(raw: string | undefined): string[] {
  if (raw === undefined || raw.trim() === '') throw new Error('BSECRET_CRYPTS is required: name each crypt this host carries')
  const out: string[] = []
  for (const entry of raw.split(',')) {
    const crypt = entry.trim()
    try {
      checkCrypt(crypt)
    } catch {
      throw new Error(`BSECRET_CRYPTS: "${crypt}" is not a crypt identifier <name>_<suffix>`)
    }
    if (out.includes(crypt)) throw new Error(`BSECRET_CRYPTS names ${crypt} twice`)
    out.push(crypt)
  }
  return out
}

function integer(name: string, raw: string | undefined, def: number, min: number): number {
  if (raw === undefined || raw.trim() === '') return def
  const v = raw.trim()
  if (!/^[0-9]+$/.test(v) || !Number.isSafeInteger(Number(v)) || Number(v) < min) throw new Error(`${name}: "${raw}" is not an integer of at least ${min}`)
  return Number(v)
}

/** A positive rate, decimals allowed, at most 1e6. */
function rate(name: string, raw: string | undefined, def: number): number {
  if (raw === undefined || raw.trim() === '') return def
  const v = raw.trim()
  if (!/^[0-9]+(\.[0-9]+)?$/.test(v) || !(Number(v) > 0) || Number(v) > 1e6) throw new Error(`${name}: "${raw}" is not a positive number of at most 1000000`)
  return Number(v)
}

/** Reads the whole configuration from env. */
export function parseConfig(env: NodeJS.ProcessEnv): Config {
  const crypts = parseCrypts(env['BSECRET_CRYPTS'])
  const stateDir = env['BSECRET_STATE_DIR']
  if (stateDir === undefined || !isAbsolute(stateDir)) {
    throw new Error("BSECRET_STATE_DIR is required: an absolute directory kept for the host's life, where the outpoint rows live")
  }
  const own = env['BSECRET_HEADERS_URL']?.trim()
  const host = env['OVERLAY_CHAIN_TRACKER_URL']?.trim()
  let headersURL: string
  if (own !== undefined && own !== '') {
    if (!isNativeSource(own)) throw new Error(`BSECRET_HEADERS_URL: "${own}" is not an http or https URL`)
    headersURL = own
  } else if (host !== undefined && isNativeSource(host)) {
    headersURL = host
  } else {
    throw new Error('BSECRET_HEADERS_URL is required: a native header source (/v1/root/<height>, /v1/tip) that token and sweep proofs are checked against; OVERLAY_CHAIN_TRACKER_URL is not one')
  }
  const c: Config = {
    crypts,
    stateDir,
    headersURL,
    retentionDays: integer('BSECRET_RETENTION_DAYS', env['BSECRET_RETENTION_DAYS'], FloorDays, FloorDays),
    unheldHours: integer('BSECRET_UNHELD_HOURS', env['BSECRET_UNHELD_HOURS'], FloorUnheldHours, FloorUnheldHours),
    maxBEEF: integer('BSECRET_MAX_BEEF', env['BSECRET_MAX_BEEF'], DefaultMaxBEEF, DefaultMaxBEEF),
    maxSweepInputs: integer('BSECRET_MAX_SWEEP_INPUTS', env['BSECRET_MAX_SWEEP_INPUTS'], DefaultMaxSweepInputs, DefaultMaxSweepInputs),
    spendTable: integer('BSECRET_SPEND_TABLE', env['BSECRET_SPEND_TABLE'], MinSpendTable, MinSpendTable),
    prices: parsePrices(env['BSECRET_PRICES']),
    sessions: {
      max: integer('BSECRET_SESSIONS', env['BSECRET_SESSIONS'], DefaultMaxSessions, 1),
      ttlSeconds: integer('BSECRET_SESSION_TTL', env['BSECRET_SESSION_TTL'], DefaultSessionTTL, 1),
    },
    handshakes: {
      perSec: rate('BSECRET_HANDSHAKES_PER_SEC', env['BSECRET_HANDSHAKES_PER_SEC'], DefaultBudget.perSec),
      burst: integer('BSECRET_HANDSHAKE_BURST', env['BSECRET_HANDSHAKE_BURST'], DefaultBudget.burst, 1),
      perAddressPerSec: rate('BSECRET_HANDSHAKES_PER_ADDR_PER_SEC', env['BSECRET_HANDSHAKES_PER_ADDR_PER_SEC'], DefaultBudget.perAddressPerSec),
      addressBurst: integer('BSECRET_HANDSHAKE_ADDR_BURST', env['BSECRET_HANDSHAKE_ADDR_BURST'], DefaultBudget.addressBurst, 1),
    },
    responses: {
      perSec: rate('BSECRET_RESPONSES_PER_SEC', env['BSECRET_RESPONSES_PER_SEC'], DefaultResponseBudget.perSec),
      burst: integer('BSECRET_RESPONSE_BURST', env['BSECRET_RESPONSE_BURST'], DefaultResponseBudget.burst, 1),
    },
  }
  const listen = env['BSECRET_LISTEN']?.trim()
  if (listen !== undefined && listen !== '') {
    const m = /^(.+):([0-9]{1,5})$/.exec(listen)
    const port = m === null ? NaN : Number(m[2])
    if (m === null || port < 1 || port > 65535) throw new Error(`BSECRET_LISTEN: "${listen}" is not host:port`)
    c.listen = { host: m[1]!.replace(/^\[(.*)\]$/, '$1'), port }
  }
  const key = env['BSECRET_PAYEE_KEY']?.trim()
  if (key !== undefined && key !== '') {
    if (!/^[0-9a-f]{64}$/.test(key)) throw new Error('BSECRET_PAYEE_KEY is not 64 lowercase hex characters')
    c.payeeKey = PrivateKey.fromHex(key)
  }
  const charged = [...c.prices.values()].some((p) => p > 0)
  if (charged && (c.listen === undefined || c.payeeKey === undefined)) {
    throw new Error('BSECRET_PRICES prices a class: BSECRET_LISTEN and BSECRET_PAYEE_KEY are required')
  }
  if (c.prices.size > 0 && c.listen === undefined) throw new Error('BSECRET_PRICES needs BSECRET_LISTEN, where the terms document is served')
  return c
}

export interface Mounted {
  module: Module
  ls: SecretLookupService
  /** The terms route, when configured. */
  front?: LookupFront
  /** Starts the terms route (when configured) and retention; resolves when the route listens. */
  start: () => Promise<Server | undefined>
}

/**
 * The module for this configuration. `overlayTopics` is OVERLAY_TOPICS,
 * when known; `journal` replaces the state directory's, `headers` the
 * configured header source and `now` the host's clock, for tests.
 */
export function secretModule(host: ModuleHost, c: Config, overlayTopics?: readonly string[], journal?: Journal, headers?: ChainTracker, now?: () => number): Mounted {
  const names = new Set(c.crypts.map(topic))
  for (const t of overlayTopics ?? []) {
    if (t.startsWith(TopicPrefix) && !names.has(t)) {
      throw new Error(`OVERLAY_TOPICS names ${t} but BSECRET_CRYPTS does not configure it; it would be admitted by the default manager`)
    }
  }
  for (const kind of AdmitKinds) host.metrics.preset('bsecret_admitted_total', { kind })
  for (const kind of AdmitKinds) host.metrics.preset('bsecret_admitted_repeats_total', { kind })
  for (const reason of Reasons) host.metrics.preset('bsecret_refused_total', { reason })
  for (const status of TokenStatuses) host.metrics.preset('bsecret_token_status_total', { status })
  for (const why of ['evidence', 'retention', 'table']) host.metrics.preset('bsecret_dropped_total', { why })
  for (const why of ['cap', 'idle']) host.metrics.preset('bsecret_sessions_evicted_total', { why })
  for (const result of ['requested', 'accepted', 'refused', 'replayed']) host.metrics.preset('bsecret_payments_total', { result })
  host.metrics.preset('bsecret_retractions_total')
  host.metrics.preset('bsecret_equivocations_total')
  const priced = new Set([...c.prices].filter(([, p]) => p > 0).map(([name]) => name))
  const tracker = headers ?? new HeaderTracker(c.headersURL)
  const ls = new SecretLookupService({
    crypts: new Set(c.crypts),
    host,
    journal: journal ?? new FileJournal(c.stateDir),
    priced,
    retentionDays: c.retentionDays,
    unheldHours: c.unheldHours,
    spendTable: c.spendTable,
    headers: tracker,
    now,
  })
  host.metrics.gauge('bsecret_crypts', () => c.crypts.length)
  host.metrics.gauge('bsecret_vaults', () => ls.vaultCount)
  host.metrics.gauge('bsecret_tokens', () => ls.tokenCount)
  host.metrics.gauge('bsecret_tokens_pending', () => ls.pendingTokens)
  host.metrics.gauge('bsecret_carriers', () => ls.carrierCount)
  host.metrics.gauge('bsecret_sweeps', () => ls.sweepCount)
  host.metrics.gauge('bsecret_outpoint_rows', () => ls.rowCount)
  host.metrics.gauge('bsecret_spend_table', () => ls.tableSize)
  const topics: Record<string, SecretTopicManager> = {}
  for (const crypt of c.crypts) topics[topic(crypt)] = new SecretTopicManager(topic(crypt), host, tracker, c.maxBEEF, c.maxSweepInputs)
  let front: LookupFront | undefined
  if (c.listen !== undefined) {
    front = new LookupFront({
      ls,
      host,
      prices: c.prices,
      wallet: c.payeeKey === undefined ? undefined : new ProtoWallet(c.payeeKey),
      receiver: priced.size > 0 ? new LedgerReceiver(c.stateDir) : undefined,
      headers: tracker,
      sessions: c.sessions,
      budget: c.handshakes,
      responses: c.responses,
    })
  }
  const start = async (): Promise<Server | undefined> => {
    const timer = setInterval(() => {
      if (!ls.restored) return
      ls.prune().catch((e: unknown) => host.log('ls_bsecret retention failed', { err: String(e) }))
    }, PruneEvery * 1000)
    timer.unref()
    if (front === undefined || c.listen === undefined) return undefined
    const server = await front.listen(c.listen.port, c.listen.host)
    server.unref()
    return server
  }
  const build = typeof BSECRET_BUILD === 'string' ? BSECRET_BUILD : 'unbundled'
  host.log('bsecret module mounted', {
    topics: [...names].join(','),
    lookup: LookupService,
    headers: headers === undefined ? c.headersURL : 'supplied',
    terms: c.listen === undefined ? 'none' : `${c.listen.host}:${c.listen.port}`,
    priced: [...priced].join(',') || 'none',
    sessions: c.listen === undefined ? 'none' : `${c.sessions.max}, idle ${c.sessions.ttlSeconds}s`,
    handshakes: c.listen === undefined ? 'none' : `${c.handshakes.perSec}/s burst ${c.handshakes.burst}, per address ${c.handshakes.perAddressPerSec}/s burst ${c.handshakes.addressBurst}`,
    responses: c.listen === undefined ? 'none' : `${c.responses.perSec}/s burst ${c.responses.burst} a session`,
    build,
  })
  return { module: { topics, lookups: { [LookupService]: ls } }, ls, front, start }
}

/**
 * Refuses a host configured to synchronise a `tm_bsecret_` topic with a
 * peer (OVERLAY_SYNC_PEERS, `topic=url,...;topic=...`). That
 * synchronisation carries only unspent outputs, so it never carries a
 * chain's spent tokens, and it drops what a topic manager refuses without
 * retrying it: a crypt is joined by replay (spec section 11.6).
 */
export function checkNoSync(raw: string | undefined): void {
  for (const entry of (raw ?? '').split(';')) {
    const t = entry.split('=')[0]!.trim()
    if (t.startsWith(TopicPrefix)) {
      throw new Error(`OVERLAY_SYNC_PEERS names ${t}: a tm_bsecret_ topic is never synchronised as unspent outputs; a host joins a crypt by replay`)
    }
  }
}

/** The factory the host calls: the configuration from the environment, checked against OVERLAY_TOPICS. */
export default async function create(host: ModuleHost): Promise<Module> {
  const overlay = process.env['OVERLAY_TOPICS']
  const topics = overlay === undefined ? undefined : overlay.split(',').map((t) => t.trim()).filter((t) => t !== '')
  checkNoSync(process.env['OVERLAY_SYNC_PEERS'])
  const m = secretModule(host, parseConfig(process.env), topics)
  await m.start()
  return m.module
}

export { Refused, SecretTopicManager } from './tm_bsecret.js'
export { SecretLookupService } from './ls_bsecret.js'
export { LookupFront, termsDocument } from './paid.js'
