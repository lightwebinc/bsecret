/**
 * What the index computes from admitted objects (spec section 11.2), the
 * twin of the Go internal/secrec/fold.go and index.go: the fold of a vault's
 * chain from seq 0 with each token's status, what a branch's tokens list,
 * a funding outpoint's row, and each carrier's status. Never an admission
 * verdict.
 */
import { bytesEqual, compareBytes } from '@lightwebinc/bcommon'
import { verifySecret, setRoot, type Current, type InclusionContext } from './merkle.js'
import { Refusal, contentID, type Entry, type Secret, type Vault } from './secrec.js'
import { toHex } from './util.js'

export type TokenStatus = 'consistent' | 'pending' | 'set-mismatch' | 'stale-mismatch' | 'commitment-reuse'
export type CarrierStatus = 'retracted' | 'superseded' | 'mismatched' | 'listed' | 'unlisted'

/**
 * A vault's chain folded from seq 0: the current set after each token, the
 * last version every identifier ever had, and every commitment any token
 * listed. Once a token breaks the fold the chain is unusable from it on.
 */
export class VaultFold {
  private set = new Map<string, Current>()
  private last = new Map<string, number>()
  private commitments = new Set<string>()
  private epoch = 0
  private broken: TokenStatus | undefined
  private ended = new Map<string, number>()

  /**
   * Folds the next token, in seq order along spends, and returns its status.
   * A token that breaks the fold changes nothing: the set stays that of the
   * last token before it, which is the set a host goes on answering.
   */
  apply(v: Vault): TokenStatus {
    if (this.broken !== undefined) return this.broken
    const set = new Map(this.set)
    const last = new Map<string, number>()
    const ended: string[] = []
    const lastOf = (id: string): number => last.get(id) ?? this.last.get(id) ?? 0
    let reuse = false
    const put = (e: Entry): void => {
      const id = toHex(e.id)
      const was = set.get(id)
      if (was !== undefined) ended.push(`${id}@${was.version}`)
      set.set(id, { id: e.id, version: e.version, contentId: e.contentId, epoch: v.epoch, seq: v.seq })
      last.set(id, e.version)
      if (this.commitments.has(toHex(e.commitment))) reuse = true
    }
    for (const id of v.retire) {
      const was = set.get(toHex(id))
      if (was === undefined) return this.fail('set-mismatch')
      set.delete(toHex(id))
      ended.push(`${toHex(id)}@${was.version}`)
    }
    for (const e of v.update) {
      if (!set.has(toHex(e.id)) || e.version <= lastOf(toHex(e.id))) return this.fail('set-mismatch')
      put(e)
    }
    for (const e of v.create) {
      if (set.has(toHex(e.id)) || e.version <= lastOf(toHex(e.id))) return this.fail('set-mismatch')
      put(e)
    }
    const now = [...set.values()]
    if (set.size !== v.count || !bytesEqual(setRoot(now), v.root)) return this.fail('set-mismatch')
    if (now.filter((c) => c.epoch < v.epoch).length !== v.stale) return this.fail('stale-mismatch')
    this.set = set
    this.epoch = v.epoch
    for (const [id, n] of last) this.last.set(id, n)
    for (const e of [...v.create, ...v.update]) this.commitments.add(toHex(e.commitment))
    for (const k of ended) this.ended.set(k, v.seq)
    return reuse ? 'commitment-reuse' : 'consistent'
  }

  private fail(s: TokenStatus): TokenStatus {
    this.broken = s
    return s
  }

  /** A fold that goes on from here on its own: a branch. */
  clone(): VaultFold {
    const f = new VaultFold()
    f.set = new Map(this.set)
    f.last = new Map(this.last)
    f.commitments = new Set(this.commitments)
    f.epoch = this.epoch
    f.broken = this.broken
    f.ended = new Map(this.ended)
    return f
  }

  /** The current set after the last token that did not break the fold, ascending by identifier. */
  setNow(): Current[] {
    return [...this.set.values()].sort((a, b) => compareBytes(a.id, b.id))
  }

  /** The version of id (hex) the set holds, when it holds one. */
  current(id: string): Current | undefined {
    return this.set.get(id)
  }

  /** How many secrets the set holds. */
  get size(): number {
    return this.set.size
  }

  /** The seq of the token that replaced or retired version of id (hex), when one did. */
  endedAt(id: string, version: number): number | undefined {
    return this.ended.get(`${id}@${version}`)
  }

  /** How many secrets of the set are keyed under an epoch before the last token's. */
  stale(): number {
    let n = 0
    for (const c of this.set.values()) if (c.epoch < this.epoch) n++
    return n
  }

  /** How many secrets of the set are keyed under an epoch before e. */
  under(e: number): number {
    let n = 0
    for (const c of this.set.values()) if (c.epoch < e) n++
    return n
  }
}

/**
 * What a record says about itself that a listing is checked against: the
 * record without its wraps and ciphertext, with its content id. An index
 * keeps this of each carrier rather than the record.
 */
export interface Listed {
  crypt: string
  org: Uint8Array
  vault: Uint8Array
  group: Uint8Array
  label: string
  id: Uint8Array
  version: number
  contentId: Uint8Array
  commitment: Uint8Array
  epoch: number
  epochId: Uint8Array
}

export const listedOf = (rec: Secret): Listed => ({
  crypt: rec.crypt,
  org: rec.org,
  vault: rec.vault,
  group: rec.group,
  label: rec.label,
  id: rec.id,
  version: rec.version,
  contentId: contentID(rec),
  commitment: rec.commitment,
  epoch: rec.epoch,
  epochId: rec.epochId,
})

/** Whether rec names the token's crypt, owner, vault and group and carries one of the vault's labels. */
function sameVault(token: Vault, rec: Pick<Listed, 'crypt' | 'org' | 'vault' | 'group' | 'label'>): boolean {
  return rec.crypt === token.crypt && bytesEqual(rec.org, token.org) && bytesEqual(rec.vault, token.vault) && bytesEqual(rec.group, token.group) && token.labels.includes(rec.label)
}

/** Whether token lists rec as checkListed holds it. */
function lists(token: Vault, rec: Listed): boolean {
  let entry: Entry | undefined
  for (const e of [...token.create, ...token.update]) if (bytesEqual(e.id, rec.id)) entry = e
  if (entry === undefined || entry.version !== rec.version || !bytesEqual(entry.contentId, rec.contentId) || !bytesEqual(entry.commitment, rec.commitment)) return false
  return sameVault(token, rec) && rec.epoch === token.epoch && bytesEqual(rec.epochId, token.epochId)
}

/**
 * The check of a record against the token that listed it: the token creates
 * or updates the record's identifier at its version, with its content id and
 * commitment; the record names the token's crypt, owner, vault and group and
 * one of its labels; and it is keyed under the token's epoch and epoch id.
 */
export function checkListed(token: Vault, rec: Secret): void {
  if (!lists(token, listedOf(rec))) throw new Refusal('listing')
}

/**
 * A reader's first check on a record a host answered for a vault's latest
 * token, whose txid is latestTxid (hash byte order): the inclusion path
 * names that token and takes the record's leaf to its root; the record
 * names the token's vault and one of its labels; and it is keyed under the
 * token's epoch, or, only while the token counts something stale, under an
 * earlier one with another epoch id.
 */
export function checkInSet(latest: Vault, latestTxid: Uint8Array, rec: Secret, path: InclusionContext | undefined): void {
  const cid = contentID(rec)
  if (path === undefined || path.seq !== latest.seq || !bytesEqual(path.token, latestTxid) || !verifySecret(path, rec.id, rec.version, cid, latest.root)) throw new Refusal('listing')
  if (!sameVault(latest, rec)) throw new Refusal('listing')
  const sameId = bytesEqual(rec.epochId, latest.epochId)
  if (rec.epoch > latest.epoch || (rec.epoch === latest.epoch && !sameId) || (rec.epoch < latest.epoch && (latest.stale === 0 || sameId))) throw new Refusal('listing')
}

/** What the rooted tokens of one branch of one vault list: for each identifier and version, the token that listed it. */
export class Listings {
  private first: Vault | undefined
  private listed = new Map<string, Vault>()
  private byCID = new Map<string, Vault>()

  /** Records what a rooted token lists; a branch's tokens in seq order. */
  apply(v: Vault): void {
    this.first ??= v
    for (const e of [...v.create, ...v.update]) {
      this.listed.set(`${toHex(e.id)}@${e.version}`, v)
      this.byCID.set(toHex(e.contentId), v)
    }
  }

  /** Listings that go on from here on their own: a branch. */
  clone(): Listings {
    const l = new Listings()
    l.first = this.first
    l.listed = new Map(this.listed)
    l.byCID = new Map(this.byCID)
    return l
  }

  /** mismatched, listed or unlisted: a carrier's status once its outpoint row gives none. */
  status(rec: Secret | Listed): CarrierStatus {
    if (this.first === undefined) return 'unlisted'
    const r = 'contentId' in rec ? rec : listedOf(rec)
    if (!this.first.labels.includes(r.label)) return 'mismatched'
    const t = this.listed.get(`${toHex(r.id)}@${r.version}`)
    if (t !== undefined) return lists(t, r) ? 'listed' : 'mismatched'
    const other = this.byCID.get(toHex(r.contentId))
    return other !== undefined && !lists(other, r) ? 'mismatched' : 'unlisted'
  }
}

/** How many commitments beside the winner a row keeps. */
export const MaxOthers = 8

/**
 * One funding outpoint's row: its winner, the lowest commitment ever
 * admitted on it, kept as a running minimum; the lowest of the rest, at most
 * MaxOthers, and a count of what was not kept; whether a winner of the
 * outpoint was ever dropped, which nothing clears; and whether an admitted
 * sweep the host holds spends the outpoint.
 */
export class OutpointRow {
  winner: Uint8Array | undefined
  others: Uint8Array[] = []
  more = 0
  dropped = false
  swept = false

  /** Whether the row keeps c: its winner, or one of the others. */
  keeps(c: Uint8Array): boolean {
    return (this.winner !== undefined && bytesEqual(c, this.winner)) || this.others.some((o) => bytesEqual(o, c))
  }

  /**
   * Records a carrier admitted on the outpoint, by its commitment (hash byte
   * order). It returns the commitment the row stopped keeping, if any: c
   * itself when the row is full of lower ones.
   */
  add(c: Uint8Array): Uint8Array | undefined {
    if (this.winner === undefined) {
      this.winner = c
      return undefined
    }
    if (this.keeps(c)) return undefined
    // dropped stays as it is: once an outpoint's winner was dropped, every
    // carrier on it is superseded, a lower one that arrives later included.
    if (compareBytes(c, this.winner) < 0) [c, this.winner] = [this.winner, c]
    const at = this.others.findIndex((o) => compareBytes(c, o) < 0)
    this.others.splice(at < 0 ? this.others.length : at, 0, c)
    if (this.others.length <= MaxOthers) return undefined
    const out = this.others.pop()
    this.more++
    return out
  }

  /** retracted, then superseded; undefined when neither applies and the listing decides. */
  status(c: Uint8Array): CarrierStatus | undefined {
    if (this.swept) return 'retracted'
    if (this.winner === undefined || !bytesEqual(this.winner, c) || this.dropped) return 'superseded'
    return undefined
  }
}

/** A carrier's status, the first that applies of retracted, superseded, mismatched, listed and unlisted. */
export const carrierStatus = (row: OutpointRow, commitment: Uint8Array, l: Listings, rec: Secret | Listed): CarrierStatus => row.status(commitment) ?? l.status(rec)
