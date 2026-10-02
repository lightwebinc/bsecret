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
  private readonly set = new Map<string, Current>()
  private readonly last = new Map<string, number>()
  private readonly commitments = new Set<string>()
  private epoch = 0
  private broken: TokenStatus | undefined

  /** Folds the next token, in seq order along spends, and returns its status. */
  apply(v: Vault): TokenStatus {
    if (this.broken !== undefined) return this.broken
    let reuse = false
    const seen = (c: Uint8Array): void => {
      if (this.commitments.has(toHex(c))) reuse = true
      this.commitments.add(toHex(c))
    }
    const put = (e: Entry): void => {
      this.set.set(toHex(e.id), { id: e.id, version: e.version, contentId: e.contentId, epoch: v.epoch, seq: v.seq })
      this.last.set(toHex(e.id), e.version)
      seen(e.commitment)
    }
    for (const id of v.retire) {
      if (!this.set.delete(toHex(id))) return this.fail('set-mismatch')
    }
    for (const e of v.update) {
      if (!this.set.has(toHex(e.id)) || e.version <= (this.last.get(toHex(e.id)) ?? 0)) return this.fail('set-mismatch')
      put(e)
    }
    for (const e of v.create) {
      if (this.set.has(toHex(e.id)) || e.version <= (this.last.get(toHex(e.id)) ?? 0)) return this.fail('set-mismatch')
      put(e)
    }
    this.epoch = v.epoch
    if (this.set.size !== v.count || !bytesEqual(setRoot(this.setNow()), v.root)) return this.fail('set-mismatch')
    if (this.stale() !== v.stale) return this.fail('stale-mismatch')
    return reuse ? 'commitment-reuse' : 'consistent'
  }

  private fail(s: TokenStatus): TokenStatus {
    this.broken = s
    return s
  }

  /** The current set after the last token folded, ascending by identifier. */
  setNow(): Current[] {
    return [...this.set.values()].sort((a, b) => compareBytes(a.id, b.id))
  }

  /** How many secrets of the set are keyed under an epoch before the last token's. */
  stale(): number {
    let n = 0
    for (const c of this.set.values()) if (c.epoch < this.epoch) n++
    return n
  }
}

/** Whether rec names the token's crypt, owner, vault and group and carries one of the vault's labels. */
function sameVault(token: Vault, rec: Secret): boolean {
  return rec.crypt === token.crypt && bytesEqual(rec.org, token.org) && bytesEqual(rec.vault, token.vault) && bytesEqual(rec.group, token.group) && token.labels.includes(rec.label)
}

/**
 * The check of a record against the token that listed it: the token creates
 * or updates the record's identifier at its version, with its content id and
 * commitment; the record names the token's crypt, owner, vault and group and
 * one of its labels; and it is keyed under the token's epoch and epoch id.
 */
export function checkListed(token: Vault, rec: Secret): void {
  const cid = contentID(rec)
  let entry: Entry | undefined
  for (const e of [...token.create, ...token.update]) if (bytesEqual(e.id, rec.id)) entry = e
  if (entry === undefined || entry.version !== rec.version || !bytesEqual(entry.contentId, cid) || !bytesEqual(entry.commitment, rec.commitment)) throw new Refusal('listing')
  if (!sameVault(token, rec) || rec.epoch !== token.epoch || !bytesEqual(rec.epochId, token.epochId)) throw new Refusal('listing')
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
  private readonly listed = new Map<string, Vault>()
  private readonly byCID = new Map<string, Vault>()

  /** Records what a rooted token lists; a branch's tokens in seq order. */
  apply(v: Vault): void {
    this.first ??= v
    for (const e of [...v.create, ...v.update]) {
      this.listed.set(`${toHex(e.id)}@${e.version}`, v)
      this.byCID.set(toHex(e.contentId), v)
    }
  }

  /** mismatched, listed or unlisted: a carrier's status once its outpoint row gives none. */
  status(rec: Secret): CarrierStatus {
    if (this.first === undefined) return 'unlisted'
    if (!this.first.labels.includes(rec.label)) return 'mismatched'
    const passes = (t: Vault): boolean => {
      try {
        checkListed(t, rec)
        return true
      } catch {
        return false
      }
    }
    const t = this.listed.get(`${toHex(rec.id)}@${rec.version}`)
    if (t !== undefined) return passes(t) ? 'listed' : 'mismatched'
    const other = this.byCID.get(toHex(contentID(rec)))
    return other !== undefined && !passes(other) ? 'mismatched' : 'unlisted'
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

  /** Records a carrier admitted on the outpoint, by its commitment (hash byte order). */
  add(c: Uint8Array): void {
    if (this.winner === undefined) {
      this.winner = c
      return
    }
    if (bytesEqual(c, this.winner) || this.others.some((o) => bytesEqual(o, c))) return
    // dropped stays as it is: once an outpoint's winner was dropped, every
    // carrier on it is superseded, a lower one that arrives later included.
    if (compareBytes(c, this.winner) < 0) [c, this.winner] = [this.winner, c]
    const at = this.others.findIndex((o) => compareBytes(c, o) < 0)
    this.others.splice(at < 0 ? this.others.length : at, 0, c)
    if (this.others.length > MaxOthers) {
      this.others.length = MaxOthers
      this.more++
    }
  }

  /** retracted, then superseded; undefined when neither applies and the listing decides. */
  status(c: Uint8Array): CarrierStatus | undefined {
    if (this.swept) return 'retracted'
    if (this.winner === undefined || !bytesEqual(this.winner, c) || this.dropped) return 'superseded'
    return undefined
  }
}

/** A carrier's status, the first that applies of retracted, superseded, mismatched, listed and unlisted. */
export const carrierStatus = (row: OutpointRow, commitment: Uint8Array, l: Listings, rec: Secret): CarrierStatus => row.status(commitment) ?? l.status(rec)
