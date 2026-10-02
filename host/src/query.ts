/**
 * The lookup question classes of ls_bsecret (spec section 10.2), validated
 * as parsed: the twin of the Go internal/secrec/query.go.
 */
import { strictPublicKey } from '@lightwebinc/bcommon'
import { MaxEpoch, MaxSafe, Refusal, checkCrypt, checkLabel, isAnyone } from './secrec.js'
import { fromHex, isLowerHex } from './util.js'

export interface Class {
  name: string
  /** Sorted. */
  members: string[]
  free: boolean
  /** The most outputs one answer holds. */
  limit: number
}

export const Classes: Class[] = [
  { name: 'vault', members: ['crypt', 'org', 'vault'], free: true, limit: 8 },
  { name: 'vault-seq', members: ['crypt', 'org', 'seq', 'vault'], free: true, limit: 8 },
  { name: 'vaults', members: ['crypt', 'vaultsOf'], free: true, limit: 64 },
  { name: 'vaults-after', members: ['after', 'crypt', 'vaultsOf'], free: true, limit: 64 },
  { name: 'secret', members: ['crypt', 'org', 'secret', 'vault'], free: true, limit: 8 },
  { name: 'version', members: ['crypt', 'org', 'secret', 'vault', 'version'], free: true, limit: 8 },
  { name: 'pending', members: ['crypt', 'org', 'pending', 'vault'], free: true, limit: 8 },
  { name: 'secrets', members: ['crypt', 'org', 'secretsOf'], free: true, limit: 16 },
  { name: 'secrets-after', members: ['after', 'crypt', 'org', 'secretsOf'], free: true, limit: 16 },
  { name: 'label', members: ['crypt', 'label', 'org', 'vault'], free: true, limit: 16 },
  { name: 'label-after', members: ['after', 'crypt', 'label', 'org', 'vault'], free: true, limit: 16 },
  { name: 'sweep', members: ['crypt', 'spent'], free: true, limit: 8 },
  { name: 'history', members: ['crypt', 'history', 'secret', 'vault'], free: false, limit: 16 },
  { name: 'history-after', members: ['after', 'crypt', 'history', 'secret', 'vault'], free: false, limit: 16 },
  { name: 'audit', members: ['audit', 'crypt', 'vault'], free: false, limit: 64 },
  { name: 'audit-after', members: ['after', 'audit', 'crypt', 'vault'], free: false, limit: 64 },
]

export interface Question {
  class: Class
  members: Record<string, string>
}

function keyHex(s: string): boolean {
  if (!isLowerHex(s, 66)) return false
  const b = fromHex(s)
  return strictPublicKey(b) !== undefined && !isAnyone(b)
}

/** A decimal from lo to hi, no sign, no leading zero, at most 16 digits. */
function decimal(s: string, lo: number, hi: number): boolean {
  if (s === '' || s.length > 16 || (s.length > 1 && s[0] === '0') || !/^[0-9]+$/.test(s)) return false
  const v = BigInt(s)
  return v >= BigInt(lo) && v <= BigInt(hi)
}

const passes = (f: () => void): boolean => {
  try {
    f()
    return true
  } catch {
    return false
  }
}

function member(cls: string, name: string, v: string): boolean {
  switch (name) {
    case 'crypt':
      return passes(() => checkCrypt(v))
    case 'org':
    case 'vaultsOf':
    case 'history':
    case 'audit':
      return keyHex(v)
    case 'vault':
    case 'secretsOf':
    case 'secret':
    case 'pending':
      return isLowerHex(v, 64)
    case 'label':
      return passes(() => checkLabel(v))
    case 'seq':
      return decimal(v, 0, MaxSafe)
    case 'version':
      return decimal(v, 1, MaxSafe)
    case 'spent': {
      const at = v.indexOf('.')
      return at >= 0 && isLowerHex(v.slice(0, at), 64) && decimal(v.slice(at + 1), 0, MaxEpoch)
    }
    case 'after':
      if (cls === 'vaults-after' || cls === 'secrets-after' || cls === 'label-after') return isLowerHex(v, 64)
      if (cls === 'history-after') return decimal(v, 1, MaxSafe)
      if (cls === 'audit-after') return decimal(v, 0, MaxSafe)
      return false
  }
  return false
}

/**
 * Validates a BRC-24 query object as parsed: a JSON object whose members are
 * all strings (a member given twice takes its last value), whose member set
 * is exactly one class's, and whose values meet their rules.
 */
export function parseQuery(raw: string | unknown): Question {
  let q: unknown = raw
  if (typeof raw === 'string') {
    try {
      q = JSON.parse(raw)
    } catch {
      throw new Refusal('query', 'not a JSON object')
    }
  }
  if (q === null || typeof q !== 'object' || Array.isArray(q)) throw new Refusal('query', 'not a JSON object')
  // No prototype: a member named __proto__ is a member like any other, and
  // is refused as one, never dropped.
  const vals = Object.create(null) as Record<string, string>
  for (const [k, v] of Object.entries(q)) {
    if (typeof v !== 'string') throw new Refusal('query', `member ${JSON.stringify(k)} is not a string`)
    vals[k] = v
  }
  const names = Object.keys(vals).sort()
  for (const c of Classes) {
    if (c.members.join(',') !== names.join(',')) continue
    for (const n of names) if (!member(c.name, n, vals[n]!)) throw new Refusal('query', `member ${JSON.stringify(n)}`)
    return { class: c, members: vals }
  }
  throw new Refusal('query', 'no class has these members')
}
