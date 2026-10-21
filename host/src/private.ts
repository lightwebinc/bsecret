/**
 * Private crypts (docs/host.md, "Private crypts"): a crypt this host serves
 * only to the organizations BSECRET_PRIVATE names for it and to the members
 * of their groups, every class through the terms route over BRC-104. The
 * host's own /lookup refuses every question about such a crypt, and so does
 * the route for an asker it cannot place.
 *
 * Who is a member is borg's: the hosts of the halls the organization's
 * vaults in the crypt name (BSECRET_HALL_URL) are asked borg's `member-of`
 * class for the asker. Their word is taken as it is answered, so name hosts
 * you run, such as this host itself when it carries the hall. An answer is
 * kept for BSECRET_MEMBER_TTL seconds; a host that does not answer refuses
 * the asker until one does.
 *
 * The asker is the identity key a BRC-104 request was verified under. The
 * shared route (bcommon's LookupFront) verifies a request before it asks the
 * lookup service anything, and gives the service only the question, so the
 * request's identity is carried to it in an AsyncLocalStorage set around the
 * route's handler: it is read only once the route has verified the request
 * under that same key.
 */
import { AsyncLocalStorage } from 'node:async_hooks'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { strictPublicKey } from '@lightwebinc/bcommon'
import type { ModuleHost } from '@lightwebinc/bcommon'
import type { LookupFront } from '@lightwebinc/bcommon/host'
import { checkCrypt, isAnyone } from './secrec.js'
import { fromHex, isLowerHex } from './util.js'

/** How long a membership answer is kept, seconds, by default and at least. */
export const DefaultMemberTTL = 60
export const MinMemberTTL = 1
/** The most askers whose membership is kept at once. */
export const MaxMembers = 10000
/** How long a hall host is given to answer, milliseconds. */
export const HallTimeout = 5000
/** The most bytes of a hall host's answer read. */
export const MaxHallAnswer = 16 << 20
/** The route's bound on request headers, as bcommon's own listener sets it. */
const MaxHeaders = 256 << 10

/** The asker of the request being answered, when the route verified one. */
export const caller = new AsyncLocalStorage<{ identity?: string }>()

function keyHex(s: string): boolean {
  return isLowerHex(s, 66) && strictPublicKey(fromHex(s)) !== undefined && !isAnyone(fromHex(s))
}

/**
 * Parses BSECRET_PRIVATE: `<crypt>=<org>[,<org>...]` entries separated by
 * `;`, each crypt one this host carries, each organization an identity key.
 */
export function parsePrivate(raw: string | undefined, carried: readonly string[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>()
  if (raw === undefined || raw.trim() === '') return out
  for (const entry of raw.split(';')) {
    if (entry.trim() === '') continue
    const at = entry.indexOf('=')
    const c = entry.slice(0, at < 0 ? entry.length : at).trim()
    try {
      checkCrypt(c)
    } catch {
      throw new Error(`BSECRET_PRIVATE: "${c}" is not a crypt identifier <name>_<suffix>`)
    }
    if (!carried.includes(c)) throw new Error(`BSECRET_PRIVATE names ${c}, which BSECRET_CRYPTS does not carry`)
    if (out.has(c)) throw new Error(`BSECRET_PRIVATE names ${c} twice`)
    const orgs = new Set<string>()
    for (const o of (at < 0 ? '' : entry.slice(at + 1)).split(',')) {
      const k = o.trim()
      if (!keyHex(k)) throw new Error(`BSECRET_PRIVATE: ${c}: "${k}" is not an identity key, 66 lowercase hex digits`)
      orgs.add(k)
    }
    out.set(c, orgs)
  }
  return out
}

/** Parses BSECRET_HALL_URL: a comma list of http or https base URLs. */
export function parseHallURLs(raw: string | undefined): string[] {
  const out: string[] = []
  for (const u of (raw ?? '').split(',')) {
    const s = u.trim().replace(/\/+$/, '')
    if (s === '') continue
    let ok = false
    try {
      const p = new URL(s)
      ok = (p.protocol === 'http:' || p.protocol === 'https:') && p.search === '' && p.hash === ''
    } catch {
      ok = false
    }
    if (!ok) throw new Error(`BSECRET_HALL_URL: "${s}" is not an http or https base URL`)
    out.push(s)
  }
  return out
}

/** What is known of one asker. */
interface Known {
  /** The private crypts it is served. */
  crypts: Set<string>
  /** The private crypts no hall host could say. */
  unknown: Set<string>
  at: number
}

export interface MembersOptions {
  /** The private crypts and the organizations each is served to. */
  crypts: ReadonlyMap<string, ReadonlySet<string>>
  /** borg hosts, asked `member-of`. */
  hallURLs: readonly string[]
  /** The halls an organization's vaults in a crypt name, from the index. */
  halls: (crypt: string, org: string) => string[]
  host: ModuleHost
  ttlSeconds?: number
  fetch?: typeof fetch
  now?: () => number
}

/** The results the gate counts in bsecret_private_total. */
export const PrivateResults = ['served', 'unauthenticated', 'refused', 'unknown'] as const

/** Who a private crypt is served to. */
export class Members {
  private readonly o: MembersOptions
  private readonly ttl: number
  private readonly known = new Map<string, Known>()
  private readonly now: () => number
  private readonly fetch: typeof fetch

  constructor(o: MembersOptions) {
    this.o = o
    this.ttl = (o.ttlSeconds ?? DefaultMemberTTL) * 1000
    this.now = o.now ?? Date.now
    this.fetch = o.fetch ?? fetch
    for (const r of PrivateResults) o.host.metrics.preset('bsecret_private_total', { result: r })
  }

  get size(): number {
    return this.known.size
  }

  /** Whether the host has any private crypt. */
  get any(): boolean {
    return this.o.crypts.size > 0
  }

  isPrivate(crypt: string): boolean {
    return this.o.crypts.has(crypt)
  }

  /**
   * Settles which private crypts identity is served, unless what is known
   * of it is younger than the TTL.
   */
  async prime(identity: string): Promise<void> {
    if (!this.any || !keyHex(identity)) return
    const k = this.known.get(identity)
    if (k !== undefined && this.now() - k.at < this.ttl) return
    const crypts = new Set<string>()
    const unknown = new Set<string>()
    for (const [c, orgs] of this.o.crypts) {
      if (orgs.has(identity)) {
        crypts.add(c)
        continue
      }
      let failed = false
      search: for (const org of orgs) {
        for (const hall of this.o.halls(c, org)) {
          for (const url of this.o.hallURLs) {
            const r = await this.memberOf(url, hall, org, identity)
            if (r === true) {
              crypts.add(c)
              failed = false
              break search
            }
            if (r === undefined) failed = true
          }
        }
      }
      if (failed && !crypts.has(c)) unknown.add(c)
    }
    this.known.delete(identity)
    if (this.known.size >= MaxMembers) this.known.delete(this.known.keys().next().value!)
    this.known.set(identity, { crypts, unknown, at: unknown.size > 0 ? 0 : this.now() })
  }

  /** Whether a hall host says identity is a member of a group of org: undefined when it could not say. */
  private async memberOf(url: string, hall: string, org: string, identity: string): Promise<boolean | undefined> {
    try {
      const res = await this.fetch(`${url}/lookup`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ service: 'ls_borg', query: { hall, org, memberOf: identity } }),
        signal: AbortSignal.timeout(HallTimeout),
      })
      const text = await res.text()
      if (!res.ok || text.length > MaxHallAnswer) return undefined
      const a = JSON.parse(text) as { type?: unknown; outputs?: unknown }
      if (a.type !== 'output-list' || !Array.isArray(a.outputs)) return undefined
      return a.outputs.length > 0
    } catch (e) {
      this.o.host.log('bsecret private crypt: a hall host could not be asked', { url, err: String(e) })
      return undefined
    }
  }

  /**
   * Refuses a question about a private crypt from anyone it is not served
   * to: by the host's own /lookup (no asker), and by the route for an asker
   * that is neither one of the crypt's organizations nor a member of their
   * groups.
   */
  check(crypt: string): void {
    if (!this.o.crypts.has(crypt)) return
    const identity = caller.getStore()?.identity
    const count = (result: (typeof PrivateResults)[number]): void => this.o.host.metrics.inc('bsecret_private_total', { result })
    if (identity === undefined) {
      count('unauthenticated')
      throw new Error(`ls_bsecret: ask over BRC-104: crypt ${crypt} is private on this host; its terms route's /lookup answers the crypt's organizations and the members of their groups`)
    }
    const k = this.known.get(identity)
    if (k?.crypts.has(crypt) === true) {
      count('served')
      return
    }
    if (k?.unknown.has(crypt) === true) {
      count('unknown')
      throw new Error(`ls_bsecret: membership unknown: crypt ${crypt} is private on this host, and no hall host could say whether this key is a member; ask again later`)
    }
    count('refused')
    throw new Error(`ls_bsecret: not served to this key: crypt ${crypt} is private on this host`)
  }
}

function header(req: IncomingMessage, name: string): string | undefined {
  const v = req.headers[name]
  return Array.isArray(v) ? v[0] : v
}

/**
 * The route's handler with the asker carried: a request that names a BRC-104
 * session the route holds, under the identity key it names, has that key's
 * membership settled first and its identity carried to the lookup service.
 * The route itself still verifies the request; an asker whose request does
 * not verify is never answered.
 */
export function gated(front: LookupFront, members: Members): (req: IncomingMessage, res: ServerResponse) => void {
  return (req, res) => {
    const run = (identity: string | undefined): void => {
      caller.run({ identity }, () => front.handler(req, res))
    }
    const id = header(req, 'x-bsv-auth-identity-key')
    const nonce = header(req, 'x-bsv-auth-your-nonce')
    if (header(req, 'x-bsv-auth-request-id') === undefined || id === undefined || nonce === undefined || !members.any) {
      run(undefined)
      return
    }
    const s = front.sessions.getSession(nonce)
    if (s === undefined || s.peerIdentityKey !== id) {
      // The route refuses it; nothing is asked of a hall host for it.
      run(undefined)
      return
    }
    members
      .prime(id)
      .catch(() => {})
      .finally(() => run(id))
  }
}

/** Listens on host:port with the gated handler, as LookupFront.listen does with its own. */
export async function listenGated(front: LookupFront, members: Members, port: number, hostname: string): Promise<Server> {
  const server = createServer({ maxHeaderSize: MaxHeaders }, gated(front, members))
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, hostname, () => {
      server.off('error', reject)
      resolve()
    })
  })
  return server
}
