/**
 * `ls_bsecret`: one lookup service for every crypt a host carries (spec
 * sections 10.2, 11.2 to 11.5).
 *
 * Two stores back it. The engine's storage holds the outputs the host
 * keeps: vault tokens, secret carriers and sweep tombstones, which this
 * service indexes in memory and rebuilds from storage on start. The journal
 * (journal.ts) holds what the host keeps for its life beside them: one row
 * per funding outpoint any admitted carrier spent, and the first sight of
 * every token. Spends of outpoints no carrier used live only in a bounded
 * table, oldest dropped first, so a stranger's chain of mined sweeps costs
 * the host that table and nothing more.
 *
 * Every status is a function of what the host holds, never of arrival
 * order, with the one exception the contract states (a sweep that left the
 * bounded table before its carrier arrived):
 *
 * - a token is **rooted** when the host holds every token from it back to
 *   the vault's first by spends, and `pending` until then. Only rooted
 *   tokens are a vault's chain: only they are answered as latest, only
 *   their fold makes a set, and only they list a carrier. A rooted token
 *   takes the status the fold of its own branch gives it (chain.ts);
 * - a carrier is `retracted` when an admitted sweep spends its funding
 *   outpoint, `superseded` when it is not its outpoint's winner (the lowest
 *   C in hash byte order) or the winner was dropped, and otherwise
 *   `mismatched`, `listed` or `unlisted` against the branch of the token an
 *   answer uses.
 *
 * The answers that use a set (`secret`, `secrets`, `label`, `pending`) use
 * the set of the highest rooted token at or below which, on its own branch,
 * nothing broke the fold; where two share that seq, the one whose proof
 * verifies against the host's headers, else the lowest txid.
 */
import { createHash } from 'node:crypto'
import { Transaction, type ChainTracker } from '@bsv/sdk'
import type {
  LookupFormula,
  LookupQuestion,
  LookupService,
  LookupServiceMetaData,
  ModuleHost,
  Output,
  OutputAdmittedByTopic,
  RestoreStorage,
} from '@lightwebinc/bcommon'
import { compareBytes } from '@lightwebinc/bcommon'
import { readVaultOutput, storedToken } from './admit.js'
import { Listings, MaxOthers, OutpointRow, VaultFold, listedOf, type CarrierStatus, type Listed, type TokenStatus } from './chain.js'
import type { Journal, Line } from './journal.js'
import { encodeContext, type Current, type Step } from './merkle.js'
import { parseQuery, type Question } from './query.js'
import { classify, firstPush, isFundingShape } from './script.js'
import { LookupService as ServiceName, Refusal, TopicPrefix, checkVaultTransition, decodeSecret, leaf, topic, vaultID, type Vault } from './secrec.js'
import { displayTxid, fromHex, hashOrder, toHex } from './util.js'

/** The retention floor of a carrier of a vault whose rooted chain the host holds, in days (spec section 11.3). */
export const FloorDays = 31
/** The retention floor of a carrier of a vault the host holds no rooted chain of, in hours. */
export const FloorUnheldHours = 24
/** Tokens kept at one seq of one vault: rooted before others, then the lowest txids. */
export const MaxPerSeq = 8
/** The floor of the bounded table of spends of outpoints no carrier used. */
export const MinSpendTable = 65536
/** Carriers answered for one version of one secret. */
const PerVersion = 8
/** How long a choice between two rooted tokens at one seq is reused, milliseconds. */
const ChoiceTTL = 60_000

/** A vault token the host holds. */
interface TokenEntry {
  txid: string
  vout: number
  seq: number
  /** The predecessor's txid in display order; empty at seq 0. */
  prev: string
  rec: Vault
  /** Every outpoint the transaction's inputs spend. */
  inputs: string[]
  /** At seq 0: an input's outpoint hashes to the vault identifier. */
  first: boolean
  /** Its stored proof: the block's height and the root the path gives, empty when it has none. */
  height: number
  root: string
  rooted: boolean
  status: TokenStatus
}

/** One branch of a vault's rooted chain, folded: the state after its last token. */
interface Branch {
  fold: VaultFold
  listings: Listings
  /** The last token on the branch at or below which nothing broke the fold. */
  good: TokenEntry | undefined
  /** The set tree of good, built when a path is first asked for. */
  tree?: SetTree
}

/** One vault's tokens. */
interface VaultIdx {
  key: string
  crypt: string
  org: string
  vault: string
  bySeq: Map<number, TokenEntry[]>
  byTxid: Map<string, TokenEntry>
  /** prev txid -> the txids of tokens naming it. */
  children: Map<string, Set<string>>
  /** By the txid of each branch's last rooted token. */
  branches: Map<string, Branch>
  /** The highest seq a rooted token holds; -1 when none is rooted. */
  top: number
  choice?: { among: string; txid: string; at: number }
}

/** A secret carrier the host holds. */
interface CarrierEntry {
  c: string
  txid: string
  crypt: string
  vkey: string
  id: string
  version: number
  op: string
  at: number
  /** What its record says of itself, without the wraps and the ciphertext. */
  view: Listed
}

/** A sweep tombstone the host holds. */
interface SweepEntry {
  txid: string
  crypt: string
  spent: string[]
  height: number
  offset: number
  score: number
}

interface Spend {
  crypt: string
  h: number
  at: number
}

/** One funding outpoint's row, for the host's life. */
interface Row {
  row: OutpointRow
  /** Admitted sweeps that spend it. */
  sweeps: Map<string, Spend>
  /** Commitments the row keeps whose carriers the host dropped. */
  gone: Set<string>
}

/** What restore and retention need from the engine's storage. */
export interface Storage extends RestoreStorage {
  findOutput: (txid: string, outputIndex: number, topic?: string, spent?: boolean, includeBEEF?: boolean) => Promise<Output | null>
  deleteOutput?: (txid: string, outputIndex: number, topic: string) => Promise<void>
}

/** The engine's lookup answer. */
export interface OutputList {
  type: 'output-list'
  outputs: Array<{ beef: number[]; outputIndex: number; context?: number[] }>
}

export interface Options {
  /** The crypt identifiers the host carries. */
  crypts: ReadonlySet<string>
  host: ModuleHost
  journal: Journal
  /** Priceable classes this host prices: asked through the engine, they are refused. */
  priced?: ReadonlySet<string>
  /** How long a host keeps a carrier it no longer answers, in days; at least 31. */
  retentionDays?: number
  /** The same for a carrier of a vault the host holds no rooted chain of, in hours; at least 24. */
  unheldHours?: number
  /** The bound on spends of outpoints no carrier used; at least 65536. */
  spendTable?: number
  /** The host's block headers: they choose between two rooted tokens at one seq. */
  headers?: ChainTracker
  /** The host's clock, Unix seconds. */
  now?: () => number
}

const outpoint = (txid: string, vout: number): string => `${txid}.${vout}`
const cmp = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0)
const srcTxid = (i: Transaction['inputs'][number]): string | undefined => i.sourceTXID ?? i.sourceTransaction?.id('hex')
const bin = (s: { toBinary(): number[] }): Uint8Array => Uint8Array.from(s.toBinary())
const good = (s: TokenStatus): boolean => s === 'consistent' || s === 'commitment-reuse'

function addTo<K>(m: Map<K, Set<string>>, k: K, v: string): void {
  let s = m.get(k)
  if (s === undefined) m.set(k, (s = new Set()))
  s.add(v)
}

function removeFrom<K>(m: Map<K, Set<string>>, k: K, v: string): void {
  const s = m.get(k)
  s?.delete(v)
  if (s?.size === 0) m.delete(k)
}

/** A proof's block height, the txid's position in its block, and the root the path gives. */
function place(tx: Transaction): { height: number; offset: number; root: string } {
  const mp = tx.merklePath
  if (mp === undefined) return { height: 0, offset: 0, root: '' }
  const txid = tx.id('hex')
  const at = mp.path[0]?.find((l) => l.txid === true && l.hash === txid)
  let root = ''
  try {
    root = mp.computeRoot(txid)
  } catch {
    // A path that does not hold the txid proves nothing.
  }
  return { height: mp.blockHeight, offset: at?.offset ?? 0, root }
}

const sha = (...parts: Uint8Array[]): Uint8Array => {
  const h = createHash('sha256')
  for (const p of parts) h.update(p)
  return Uint8Array.from(h.digest())
}

/**
 * The RFC 6962 tree over one set, kept so that a page of answers costs one
 * tree and a path a walk down it: the same root and the same paths as
 * merkle.ts gives, which hashes a whole tree for every path.
 */
export class SetTree {
  private readonly at = new Map<string, number>()
  private readonly leaves: Uint8Array[]
  private readonly nodes = new Map<string, Uint8Array>()

  /** set is ascending by identifier, as a fold returns it. */
  constructor(set: Current[]) {
    this.leaves = set.map((c) => sha(Uint8Array.of(0), leaf(c.id, c.version, c.contentId)))
    for (const [i, c] of set.entries()) this.at.set(toHex(c.id), i)
  }

  get size(): number {
    return this.leaves.length
  }

  /** The leaf index of the secret id (hex). */
  index(id: string): number | undefined {
    return this.at.get(id)
  }

  private static split(n: number): number {
    let k = 1
    while (k * 2 < n) k *= 2
    return k
  }

  private subtree(start: number, n: number): Uint8Array {
    if (n === 1) return this.leaves[start]!
    const key = `${start}:${n}`
    let h = this.nodes.get(key)
    if (h === undefined) {
      const k = SetTree.split(n)
      h = sha(Uint8Array.of(1), this.subtree(start, k), this.subtree(start + k, n - k))
      this.nodes.set(key, h)
    }
    return h
  }

  get root(): Uint8Array {
    return this.leaves.length === 0 ? sha() : this.subtree(0, this.leaves.length)
  }

  /** The inclusion path of leaf index, from the leaf upward. */
  prove(index: number): Step[] {
    const walk = (start: number, n: number, i: number): Step[] => {
      if (n === 1) return []
      const k = SetTree.split(n)
      if (i < k) return [...walk(start, k, i), { hash: this.subtree(start + k, n - k), left: false }]
      return [...walk(start + k, n - k, i - k), { hash: this.subtree(start, k), left: true }]
    }
    return walk(0, this.leaves.length, index)
  }
}

export class SecretLookupService implements LookupService {
  /** The whole transaction: a carrier's funding outpoint, a token's predecessor and a sweep's spends are its inputs. */
  readonly admissionMode = 'whole-tx' as const
  /** Spends are read from admitted transactions, never from the engine's notices. */
  readonly spendNotificationMode = 'none' as const

  readonly crypts: ReadonlySet<string>
  private readonly host: ModuleHost
  private readonly journal: Journal
  private readonly priced: ReadonlySet<string>
  private readonly retention: number
  private readonly unheld: number
  private readonly tableCap: number
  private readonly headers: ChainTracker | undefined
  private readonly now: () => number

  // What the journal holds.
  private readonly rows = new Map<string, Row>()
  /** First sight of each commitment a row keeps. */
  private readonly seen = new Map<string, { op: string; crypt: string; at: number }>()
  private readonly tokenSeen = new Map<string, { vout: number; crypt: string; at: number }>()

  // What the host holds, from storage.
  private readonly vaults = new Map<string, VaultIdx>()
  private readonly vaultsByOrg = new Map<string, Set<string>>()
  private readonly tokenVault = new Map<string, string>()
  private readonly carriers = new Map<string, CarrierEntry>()
  /** vault key | secret id -> version -> commitments. */
  private readonly versions = new Map<string, Map<number, Set<string>>>()
  private readonly sweeps = new Map<string, SweepEntry>()
  private readonly sweepsByOp = new Map<string, Set<string>>()
  /** Spends of outpoints no carrier used: outpoint -> sweep txid -> spend, oldest first. */
  private readonly table = new Map<string, Map<string, Spend>>()

  /** Outputs dropped from the index and still to be deleted from storage. */
  private readonly pending = new Map<string, { txid: string; vout: number; topic: string }>()
  private storage: Storage | undefined
  /** While restoring, a seq's bound is applied once at the end, when every token's descent is known. */
  private restoring = false

  constructor(o: Options) {
    this.crypts = o.crypts
    this.host = o.host
    this.journal = o.journal
    this.priced = o.priced ?? new Set()
    const days = o.retentionDays ?? FloorDays
    if (!Number.isSafeInteger(days) || days < FloorDays) throw new Error(`ls_bsecret: retention of ${days} days is under the ${FloorDays}-day floor`)
    this.retention = days * 86400
    const hours = o.unheldHours ?? FloorUnheldHours
    if (!Number.isSafeInteger(hours) || hours < FloorUnheldHours) throw new Error(`ls_bsecret: ${hours} hours for a carrier of a vault not held is under the ${FloorUnheldHours}-hour floor`)
    this.unheld = hours * 3600
    // The table's floor is held where an operator sets it (module.ts); a
    // test may name a smaller one to watch it fill.
    const cap = o.spendTable ?? MinSpendTable
    if (!Number.isSafeInteger(cap) || cap < 1) throw new Error(`ls_bsecret: a spend table of ${cap}`)
    this.tableCap = cap
    this.headers = o.headers
    this.now = o.now ?? (() => Math.floor(Date.now() / 1000))
    for (const l of this.journal.load()) this.apply(l)
  }

  // ---- gauges

  get vaultCount(): number {
    return this.vaults.size
  }
  get tokenCount(): number {
    return this.tokenVault.size
  }
  get pendingTokens(): number {
    let n = 0
    for (const v of this.vaults.values()) for (const t of v.byTxid.values()) if (!t.rooted) n++
    return n
  }
  get carrierCount(): number {
    return this.carriers.size
  }
  get sweepCount(): number {
    return this.sweeps.size
  }
  get rowCount(): number {
    return this.rows.size
  }
  get tableSize(): number {
    return this.table.size
  }
  get pendingDeletes(): number {
    return this.pending.size
  }

  // ---- the journal, and the outpoint rows it rebuilds (spec section 11.2)

  private row(op: string): Row {
    let r = this.rows.get(op)
    if (r === undefined) this.rows.set(op, (r = { row: new OutpointRow(), sweeps: new Map(), gone: new Set() }))
    return r
  }

  private apply(l: Line): void {
    switch (l.k) {
      case 'c': {
        const out = this.row(l.op).row.add(fromHex(l.c))
        this.seen.set(l.c, { op: l.op, crypt: l.crypt, at: l.at })
        if (out !== undefined) this.unkept(toHex(out))
        break
      }
      case 'm': {
        this.row(l.op).row.more++
        break
      }
      case 'd': {
        const r = this.row(l.op)
        r.gone.add(l.c)
        if (l.w) r.row.dropped = true
        break
      }
      case 's': {
        const r = this.row(l.op)
        if (!r.sweeps.has(l.s)) r.sweeps.set(l.s, { crypt: l.crypt, h: l.h, at: l.at })
        r.row.swept = true
        break
      }
      case 't': {
        if (!this.tokenSeen.has(l.txid)) this.tokenSeen.set(l.txid, { vout: l.vout, crypt: l.crypt, at: l.at })
        break
      }
    }
  }

  private write(l: Line): void {
    this.journal.append(l)
    this.apply(l)
  }

  /** A commitment its row stopped keeping: its carrier leaves the index and storage, and its commitment goes with it. */
  private unkept(c: string): void {
    const crypt = this.seen.get(c)?.crypt
    this.seen.delete(c)
    const e = this.carriers.get(c)
    if (e === undefined) return
    this.forgetCarrier(e)
    this.pending.set(`${e.txid}.0`, { txid: e.txid, vout: 0, topic: topic(crypt ?? e.crypt) })
    this.host.metrics.inc('bsecret_dropped_total', { why: 'evidence' })
  }

  /** The outpoint row of op as the contract describes it, when the host has one. */
  outpointRow(op: string): { winner: string; others: string[]; more: number; dropped: boolean; sweeps: string[] } | undefined {
    const r = this.rows.get(op)
    if (r === undefined) return undefined
    return { winner: r.row.winner === undefined ? '' : toHex(r.row.winner), others: r.row.others.map(toHex), more: r.row.more, dropped: r.row.dropped, sweeps: [...r.sweeps.keys()] }
  }

  // ---- the vault's chain (spec section 11.2)

  private vaultKey(crypt: string, org: string, vault: string): string {
    return `${crypt}|${org}|${vault}`
  }

  /** Whether next descends from prev by a spend of its token output, under the transition rules (admit.ts checkNextToken, on what the index keeps). */
  private descends(prev: TokenEntry, next: TokenEntry): boolean {
    const spent = next.inputs.filter((op) => op === outpoint(prev.txid, prev.vout))
    if (spent.length !== 1 || next.prev !== prev.txid || prev.seq + 1 !== next.seq) return false
    try {
      checkVaultTransition(prev.rec, hashOrder(prev.txid), next.rec)
      return true
    } catch {
      return false
    }
  }

  /** The branch after t, folded again from seq 0: a second token on one predecessor begins a branch of its own. */
  private rebuild(v: VaultIdx, t: TokenEntry): Branch {
    const path: TokenEntry[] = []
    for (let cur: TokenEntry | undefined = t; cur !== undefined; cur = cur.seq === 0 ? undefined : v.byTxid.get(cur.prev)) path.push(cur)
    const b: Branch = { fold: new VaultFold(), listings: new Listings(), good: undefined }
    for (const x of path.reverse()) this.fold(b, x)
    return b
  }

  /** Folds t onto its branch and returns its status. A token that breaks the fold lists nothing, and nor does any after it. */
  private fold(b: Branch, t: TokenEntry): TokenStatus {
    const s = b.fold.apply(t.rec)
    if (good(s)) {
      b.listings.apply(t.rec)
      b.good = t
      b.tree = undefined
    }
    return s
  }

  /** Roots t if it descends from the vault's first token, and then every held token that descends from it. */
  private rootFrom(v: VaultIdx, t: TokenEntry, count: boolean): void {
    const work = [t]
    while (work.length > 0) {
      const x = work.pop()!
      if (x.rooted) continue
      let b: Branch
      if (x.seq === 0) {
        if (!x.first) continue
        b = { fold: new VaultFold(), listings: new Listings(), good: undefined }
      } else {
        const p = v.byTxid.get(x.prev)
        if (p === undefined || !p.rooted || !this.descends(p, x)) continue
        const held = v.branches.get(p.txid)
        if (held !== undefined) {
          v.branches.delete(p.txid)
          b = held
        } else {
          b = this.rebuild(v, p)
        }
      }
      x.rooted = true
      x.status = this.fold(b, x)
      v.branches.set(x.txid, b)
      v.top = Math.max(v.top, x.seq)
      v.choice = undefined
      if (count) this.counted(v, x)
      for (const c of v.children.get(x.txid) ?? []) {
        const child = v.byTxid.get(c)
        if (child !== undefined) work.push(child)
      }
    }
  }

  private counted(v: VaultIdx, t: TokenEntry): void {
    this.host.metrics.inc('bsecret_token_status_total', { status: t.status })
    if (t.status !== 'consistent' && t.status !== 'pending') {
      this.host.log('ls_bsecret token status', { crypt: v.crypt, org: v.org, vault: v.vault, seq: t.seq, txid: t.txid, status: t.status })
    }
  }

  /** Decides every token of the vault again: after one that others descend from left the index. */
  private reroot(v: VaultIdx): void {
    v.branches.clear()
    v.top = -1
    v.choice = undefined
    for (const t of v.byTxid.values()) {
      t.rooted = false
      t.status = 'pending'
    }
    for (const t of v.bySeq.get(0) ?? []) this.rootFrom(v, t, false)
  }

  /** Holds a seq to its bound: rooted tokens before others, then the lowest txids. */
  private bound(v: VaultIdx, seq: number): void {
    const at = v.bySeq.get(seq)
    if (at === undefined || at.length <= MaxPerSeq) return
    const order = [...at].sort((a, b) => Number(b.rooted) - Number(a.rooted) || cmp(a.txid, b.txid))
    let again = false
    for (const t of order.slice(MaxPerSeq)) {
      this.host.log('ls_bsecret kept no more tokens at this seq', { crypt: v.crypt, vault: v.vault, txid: t.txid, seq })
      again = again || t.rooted
      this.forgetToken(v, t, false)
    }
    if (again) this.reroot(v)
  }

  /** The status of the token with txid (display order), when the host holds it. */
  tokenStatus(txid: string): TokenStatus | undefined {
    const key = this.tokenVault.get(txid)
    return key === undefined ? undefined : this.vaults.get(key)?.byTxid.get(txid)?.status
  }

  /** Whether the token with txid (display order) is rooted. */
  rooted(txid: string): boolean {
    const key = this.tokenVault.get(txid)
    return key !== undefined && this.vaults.get(key)?.byTxid.get(txid)?.rooted === true
  }

  /**
   * The branch an answer uses: that of the highest rooted token at or below
   * which nothing broke the fold; of two at that seq, the one whose proof
   * verifies against the host's headers, else the lowest txid.
   */
  private async answerBranch(v: VaultIdx | undefined): Promise<Branch | undefined> {
    if (v === undefined) return undefined
    let best: Branch[] = []
    for (const b of v.branches.values()) {
      if (b.good === undefined) continue
      if (best.length === 0 || b.good.seq > best[0]!.good!.seq) best = [b]
      else if (b.good.seq === best[0]!.good!.seq && !best.some((x) => x.good === b.good)) best.push(b)
    }
    if (best.length <= 1) return best[0]
    best.sort((a, b) => cmp(a.good!.txid, b.good!.txid))
    const among = best.map((b) => b.good!.txid).join(',')
    const now = Date.now()
    if (v.choice !== undefined && v.choice.among === among && now - v.choice.at < ChoiceTTL) return best.find((b) => b.good!.txid === v.choice!.txid)
    let pick = best[0]!
    if (this.headers !== undefined) {
      const mined: Branch[] = []
      for (const b of best) {
        const t = b.good!
        try {
          if (t.root !== '' && (await this.headers.isValidRootForHeight(t.root, t.height))) mined.push(b)
        } catch {
          // A header source that cannot answer leaves the lowest txid.
        }
      }
      if (mined.length > 0) pick = mined[0]!
    }
    v.choice = { among, txid: pick.good!.txid, at: now }
    return pick
  }

  // ---- carrier statuses (spec section 11.2)

  /** The status of the carrier with commitment c (hash byte order hex), when the host holds it. */
  async status(c: string): Promise<CarrierStatus | undefined> {
    const e = this.carriers.get(c)
    if (e === undefined) return undefined
    return this.statusOf(e, await this.answerBranch(this.vaults.get(e.vkey)))
  }

  private statusOf(e: CarrierEntry, b: Branch | undefined): CarrierStatus {
    return this.rows.get(e.op)!.row.status(fromHex(e.c)) ?? (b === undefined ? 'unlisted' : b.listings.status(e.view))
  }

  /** Whether the host holds the carrier with commitment c (hash byte order hex). */
  holds(c: string): boolean {
    return this.carriers.has(c)
  }

  // ---- admission

  outputAdmittedByTopic(payload: OutputAdmittedByTopic): void {
    if (payload.mode !== 'whole-tx') return
    const crypt = this.cryptOf(payload.topic)
    if (crypt === undefined) return
    let tx: Transaction
    try {
      tx = Transaction.fromAtomicBEEF(payload.atomicBEEF)
    } catch {
      this.host.log('ls_bsecret ignored an admission whose BEEF did not parse', { topic: payload.topic })
      return
    }
    this.index(crypt, tx, payload.outputIndex, 0)
    this.enforceTable()
  }

  outputEvicted(txid: string, outputIndex: number): void {
    this.forget(txid, outputIndex)
  }

  outputNoLongerRetainedInHistory(txid: string, outputIndex: number, t: string): void {
    if (this.cryptOf(t) !== undefined) this.forget(txid, outputIndex)
  }

  private cryptOf(t: string): string | undefined {
    if (!t.startsWith(TopicPrefix)) return undefined
    const crypt = t.slice(TopicPrefix.length)
    return this.crypts.has(crypt) ? crypt : undefined
  }

  /**
   * Indexes output vout of an admitted transaction on crypt, writing its
   * rows the first time it is seen. A carrier its row does not keep, or
   * says was dropped, is not indexed, and its output is deleted. Returns
   * whether it indexed.
   */
  private index(crypt: string, tx: Transaction, vout: number, score: number): boolean {
    const out = tx.outputs[vout]
    if (out === undefined) return false
    const script = bin(out.lockingScript)
    const kind = classify(script)
    if (kind === 'secret') return this.indexCarrier(crypt, tx, script)
    if (kind === 'vault-token') return this.indexToken(crypt, tx, vout)
    if (vout === 0 && isFundingShape(script)) return this.indexSweep(crypt, tx, score)
    this.host.log('ls_bsecret indexed an output of no known kind', { crypt, txid: tx.id('hex'), vout })
    return false
  }

  private indexCarrier(crypt: string, tx: Transaction, script: Uint8Array): boolean {
    const input = tx.inputs[0]
    const src = input === undefined ? undefined : srcTxid(input)
    if (input === undefined || src === undefined) return false
    const op = outpoint(src, input.sourceOutputIndex)
    const txid = tx.id('hex')
    const cb = Uint8Array.from(tx.hash() as number[])
    const c = toHex(cb)
    if (this.carriers.has(c)) return true
    const rec = decodeSecret(firstPush(script)!)
    const known = this.rows.get(op)
    if (known === undefined) {
      // Spends seen before any carrier used the outpoint join its row.
      const early = this.table.get(op)
      if (early !== undefined) {
        this.table.delete(op)
        for (const [s, sp] of early) {
          this.write({ k: 's', op, s, crypt: sp.crypt, h: sp.h, at: sp.at })
          this.host.metrics.inc('bsecret_retractions_total')
        }
      }
    }
    const r = this.row(op)
    if (!r.row.keeps(cb)) {
      // While restoring, a carrier the row does not keep is one it stopped
      // keeping, unless the row never turned one away: then its line was lost.
      const full = r.row.others.length >= MaxOthers
      const takes = !full || compareBytes(cb, r.row.others[MaxOthers - 1]!) < 0
      const counted = this.restoring && r.row.more > 0
      if (!this.restoring && r.row.winner !== undefined) this.host.metrics.inc('bsecret_equivocations_total')
      if (!takes || counted) {
        if (!counted) {
          this.write({ k: 'm', op })
          this.host.metrics.inc('bsecret_dropped_total', { why: 'evidence' })
        }
        this.pending.set(`${txid}.0`, { txid, vout: 0, topic: topic(crypt) })
        return false
      }
      this.write({ k: 'c', op, c, crypt, at: this.now() })
    }
    if (r.gone.has(c)) {
      this.pending.set(`${txid}.0`, { txid, vout: 0, topic: topic(crypt) })
      return false
    }
    const vkey = this.vaultKey(crypt, toHex(rec.org), toHex(rec.vault))
    const e: CarrierEntry = { c, txid, crypt, vkey, id: toHex(rec.id), version: rec.version, op, at: this.seen.get(c)?.at ?? this.now(), view: listedOf(rec) }
    this.carriers.set(c, e)
    const k = `${vkey}|${e.id}`
    let byVersion = this.versions.get(k)
    if (byVersion === undefined) this.versions.set(k, (byVersion = new Map()))
    addTo(byVersion, e.version, c)
    return true
  }

  private forgetCarrier(e: CarrierEntry): void {
    this.carriers.delete(e.c)
    const k = `${e.vkey}|${e.id}`
    const byVersion = this.versions.get(k)
    if (byVersion !== undefined) {
      removeFrom(byVersion, e.version, e.c)
      if (byVersion.size === 0) this.versions.delete(k)
    }
  }

  private indexToken(crypt: string, tx: Transaction, vout: number): boolean {
    const out = tx.outputs[vout]!
    const t = readVaultOutput(bin(out.lockingScript), out.satoshis, vout)
    const txid = tx.id('hex')
    if (t === undefined || t.vault.crypt !== crypt) {
      this.host.log('ls_bsecret could not read a token', { crypt, txid, vout })
      return false
    }
    const rec = t.vault
    const org = toHex(rec.org)
    const vault = toHex(rec.vault)
    const key = this.vaultKey(crypt, org, vault)
    let v = this.vaults.get(key)
    if (v === undefined) {
      v = { key, crypt, org, vault, bySeq: new Map(), byTxid: new Map(), children: new Map(), branches: new Map(), top: -1 }
      this.vaults.set(key, v)
      addTo(this.vaultsByOrg, `${crypt}|${org}`, vault)
    }
    if (!this.tokenSeen.has(txid)) this.write({ k: 't', txid, vout, crypt, at: this.now() })
    if (v.byTxid.has(txid)) return true
    const inputs: string[] = []
    let first = false
    for (const i of tx.inputs) {
      const src = srcTxid(i)
      if (src === undefined) continue
      inputs.push(outpoint(src, i.sourceOutputIndex))
      if (rec.seq === 0 && compareBytes(vaultID(hashOrder(src), i.sourceOutputIndex), rec.vault) === 0) first = true
    }
    const { height, root } = place(tx)
    const e: TokenEntry = { txid, vout, seq: rec.seq, prev: rec.seq === 0 ? '' : displayTxid(rec.prev), rec, inputs, first, height, root, rooted: false, status: 'pending' }
    v.bySeq.set(rec.seq, [...(v.bySeq.get(rec.seq) ?? []), e].sort((a, b) => cmp(a.txid, b.txid)))
    v.byTxid.set(txid, e)
    this.tokenVault.set(txid, key)
    if (e.prev !== '') addTo(v.children, e.prev, txid)
    if (this.restoring) return true
    this.rootFrom(v, e, true)
    if (!e.rooted) this.counted(v, e)
    this.bound(v, rec.seq)
    return v.byTxid.has(txid)
  }

  /** Takes a token out of the index; reroot decides the rest again when others descended from it. */
  private forgetToken(v: VaultIdx, t: TokenEntry, reroot = true): void {
    v.byTxid.delete(t.txid)
    this.tokenVault.delete(t.txid)
    const list = (v.bySeq.get(t.seq) ?? []).filter((x) => x.txid !== t.txid)
    if (list.length === 0) v.bySeq.delete(t.seq)
    else v.bySeq.set(t.seq, list)
    if (t.prev !== '') removeFrom(v.children, t.prev, t.txid)
    if (reroot && t.rooted) this.reroot(v)
  }

  private indexSweep(crypt: string, tx: Transaction, score: number): boolean {
    const txid = tx.id('hex')
    if (this.sweeps.has(txid)) return true
    const { height, offset } = place(tx)
    const spent: string[] = []
    for (const input of tx.inputs) {
      const src = srcTxid(input)
      if (src === undefined) continue
      const op = outpoint(src, input.sourceOutputIndex)
      spent.push(op)
      const r = this.rows.get(op)
      if (r !== undefined) {
        if (!r.sweeps.has(txid)) {
          this.write({ k: 's', op, s: txid, crypt, h: height, at: this.now() })
          this.host.metrics.inc('bsecret_retractions_total')
        }
      } else {
        let m = this.table.get(op)
        if (m === undefined) this.table.set(op, (m = new Map()))
        if (!m.has(txid)) m.set(txid, { crypt, h: height, at: this.now() })
      }
    }
    this.sweeps.set(txid, { txid, crypt, spent, height, offset, score })
    for (const op of spent) addTo(this.sweepsByOp, `${crypt}|${op}`, txid)
    return true
  }

  /** Whether a held sweep still records a spend: a row's, or one in the table. */
  private sweepLive(s: SweepEntry): boolean {
    return s.spent.some((op) => this.rows.get(op)?.sweeps.has(s.txid) === true || this.table.get(op)?.has(s.txid) === true)
  }

  /**
   * Keeps the table at its bound, oldest outpoint first. A sweep that then
   * records no spend at all is dropped and deleted from storage.
   */
  private enforceTable(): void {
    while (this.table.size > this.tableCap) {
      const [op, spends] = this.table.entries().next().value as [string, Map<string, Spend>]
      this.table.delete(op)
      for (const s of spends.keys()) {
        const e = this.sweeps.get(s)
        if (e === undefined || this.sweepLive(e)) continue
        this.forget(s, 0)
        this.pending.set(`${s}.0`, { txid: s, vout: 0, topic: topic(e.crypt) })
        this.host.metrics.inc('bsecret_dropped_total', { why: 'table' })
      }
    }
  }

  /** Removes a held output from the index; its rows stay. */
  private forget(txid: string, vout: number): void {
    if (vout === 0) {
      const e = this.carriers.get(toHex(hashOrder(txid)))
      if (e !== undefined) this.forgetCarrier(e)
      const s = this.sweeps.get(txid)
      if (s !== undefined) {
        this.sweeps.delete(txid)
        for (const op of s.spent) removeFrom(this.sweepsByOp, `${s.crypt}|${op}`, txid)
      }
    }
    const key = this.tokenVault.get(txid)
    const v = key === undefined ? undefined : this.vaults.get(key)
    const t = v?.byTxid.get(txid)
    if (v !== undefined && t !== undefined && t.vout === vout) this.forgetToken(v, t)
  }

  // ---- drops and retention (spec section 11.3)

  /** Drops a held carrier: marks its row, takes it out of every answer, and queues its output for deletion. */
  private drop(e: CarrierEntry, why: string): void {
    const r = this.rows.get(e.op)!
    const winner = r.row.winner !== undefined && toHex(r.row.winner) === e.c
    this.write({ k: 'd', op: e.op, c: e.c, w: winner })
    this.forgetCarrier(e)
    this.pending.set(`${e.txid}.0`, { txid: e.txid, vout: 0, topic: topic(e.crypt) })
    this.host.metrics.inc('bsecret_dropped_total', { why })
    this.host.log('ls_bsecret dropped a carrier', { txid: e.txid, outpoint: e.op, why, winner })
  }

  /**
   * Applies retention at the host's time and deletes what was dropped from
   * storage. Kept for the host's life: tokens, outpoint rows and the sweeps
   * they record. A listed carrier is kept while the answered set holds its
   * version, and for the retention period after the host first saw the
   * token that replaced or retired it. Any other carrier is kept for the
   * retention period after the host first saw it (after the sweep, for a
   * retracted one) where the host holds the vault's rooted chain, and for
   * the shorter period where it does not. Dropping an outpoint's winner
   * closes the outpoint: nothing on it is answered again. Returns how many
   * carriers were dropped.
   */
  async prune(): Promise<number> {
    const now = this.now()
    let n = 0
    const branches = new Map<string, Branch | undefined>()
    const paths = new Map<Branch, Map<number, string>>()
    for (const e of [...this.carriers.values()]) {
      const r = this.rows.get(e.op)!
      const v = this.vaults.get(e.vkey)
      if (!branches.has(e.vkey)) branches.set(e.vkey, await this.answerBranch(v))
      const b = branches.get(e.vkey)
      const st = this.statusOf(e, b)
      let from = e.at
      const period = v !== undefined && v.top >= 0 ? this.retention : this.unheld
      if (st === 'retracted') {
        from = Math.max(e.at, Math.min(...[...r.sweeps.values()].map((s) => s.at)))
      } else if (st === 'listed' && b !== undefined && v !== undefined) {
        if (b.fold.current(e.id)?.version === e.version) continue
        const seq = b.fold.endedAt(e.id, e.version)
        if (seq !== undefined) {
          let path = paths.get(b)
          if (path === undefined) {
            paths.set(b, (path = new Map()))
            for (let t: TokenEntry | undefined = b.good; t !== undefined; t = t.seq === 0 ? undefined : v.byTxid.get(t.prev)) path.set(t.seq, t.txid)
          }
          from = Math.max(e.at, this.tokenSeen.get(path.get(seq) ?? '')?.at ?? now)
        }
      }
      if (now - from >= period) {
        this.drop(e, 'retention')
        n++
      }
    }
    await this.flush()
    return n
  }

  /** Deletes dropped outputs from storage, when the host's storage can. */
  async flush(): Promise<void> {
    const del = this.storage?.deleteOutput?.bind(this.storage)
    if (del === undefined) return
    for (const [k, p] of [...this.pending]) {
      try {
        await del(p.txid, p.vout, p.topic)
        this.pending.delete(k)
      } catch (e) {
        this.host.log('ls_bsecret could not delete a dropped output', { txid: p.txid, err: String(e) })
      }
    }
  }

  // ---- questions (spec section 10.2)

  /** Asked through the engine: a class the host prices is refused here. */
  async lookup(question: LookupQuestion): Promise<LookupFormula> {
    return await this.answer(question, false)
  }

  /** The class of a question, validated, and whether this host prices it. */
  classify(question: LookupQuestion): { q: Question; priced: boolean } {
    if (question.service !== ServiceName) throw new Error(`ls_bsecret: this service is ${ServiceName}, not ${String(question.service)}`)
    let q: Question
    try {
      q = parseQuery(question.query)
    } catch (e) {
      if (e instanceof Refusal) throw new Error(`ls_bsecret: refused: ${e.message.replace(/^secrec: /, '')}`)
      throw e
    }
    if (!this.crypts.has(q.members['crypt']!)) throw new Error(`ls_bsecret: this host does not carry crypt ${q.members['crypt']}`)
    return { q, priced: !q.class.free && this.priced.has(q.class.name) }
  }

  /** The carriers held for one version of one secret whose status is one of want, by txid, at most 8. */
  private held(vkey: string, id: string, version: number, b: Branch | undefined, want: readonly CarrierStatus[]): CarrierEntry[] {
    return [...(this.versions.get(`${vkey}|${id}`)?.get(version) ?? [])]
      .map((c) => this.carriers.get(c)!)
      .filter((e) => want.includes(this.statusOf(e, b)))
      .sort((x, y) => cmp(x.txid, y.txid))
      .slice(0, PerVersion)
  }

  /** The inclusion context of the secret id in the set of the branch's token. */
  private context(b: Branch, id: string): number[] {
    b.tree ??= new SetTree(b.fold.setNow())
    const index = b.tree.index(id)!
    return Array.from(encodeContext({ seq: b.good!.seq, token: hashOrder(b.good!.txid), index, size: b.tree.size, path: b.tree.prove(index) }))
  }

  /**
   * Answers a question. paid says the question was paid for (or asked where
   * no payment is due); a class this host prices is refused otherwise.
   */
  async answer(question: LookupQuestion, paid: boolean): Promise<LookupFormula> {
    const { q, priced } = this.classify(question)
    if (priced && !paid) throw new Error(`ls_bsecret: ${q.class.name} is priced on this host; ask its terms route's /lookup over BRC-104`)
    this.host.metrics.inc('bsecret_lookups_total', { class: q.class.name })
    const m = q.members
    const crypt = m['crypt']!
    const limit = q.class.limit
    const tok = (t: TokenEntry): LookupFormula[number] => ({ txid: t.txid, outputIndex: t.vout })
    const car = (e: CarrierEntry): LookupFormula[number] => ({ txid: e.txid, outputIndex: 0 })
    const vaultOf = (org: string, vault: string): VaultIdx | undefined => this.vaults.get(this.vaultKey(crypt, org, vault))
    const latest = (v: VaultIdx | undefined): TokenEntry[] => (v === undefined || v.top < 0 ? [] : (v.bySeq.get(v.top) ?? []).filter((t) => t.rooted))
    const listed = ['listed'] as const
    const answered = ['listed', 'unlisted', 'mismatched'] as const
    switch (q.class.name) {
      case 'vault':
        return latest(vaultOf(m['org']!, m['vault']!)).slice(0, limit).map(tok)
      case 'vault-seq':
        return (vaultOf(m['org']!, m['vault']!)?.bySeq.get(Number(m['seq'])) ?? []).slice(0, limit).map(tok)
      case 'vaults':
      case 'vaults-after': {
        const org = m['vaultsOf']!
        const after = m['after']
        const out: LookupFormula = []
        for (const id of [...(this.vaultsByOrg.get(`${crypt}|${org}`) ?? [])].filter((x) => after === undefined || x > after).sort(cmp)) {
          const ts = latest(vaultOf(org, id))
          // A page never splits one vault's latest tokens, so the cursor loses nothing.
          if (out.length > 0 && out.length + ts.length > limit) break
          out.push(...ts.map(tok))
        }
        return out
      }
      case 'secret': {
        const v = vaultOf(m['org']!, m['vault']!)
        const b = await this.answerBranch(v)
        const cur = b?.fold.current(m['secret']!)
        if (v === undefined || b === undefined || cur === undefined) return []
        const context = this.context(b, m['secret']!)
        return this.held(v.key, m['secret']!, cur.version, b, listed)
          .slice(0, limit)
          .map((e) => ({ ...car(e), context }))
      }
      case 'version': {
        const v = vaultOf(m['org']!, m['vault']!)
        const vkey = this.vaultKey(crypt, m['org']!, m['vault']!)
        return this.held(vkey, m['secret']!, Number(m['version']), await this.answerBranch(v), answered)
          .slice(0, limit)
          .map(car)
      }
      case 'pending': {
        const v = vaultOf(m['org']!, m['vault']!)
        const vkey = this.vaultKey(crypt, m['org']!, m['vault']!)
        const b = await this.answerBranch(v)
        const above = b?.fold.current(m['pending']!)?.version ?? 0
        const out: LookupFormula = []
        for (const n of [...(this.versions.get(`${vkey}|${m['pending']}`)?.keys() ?? [])].filter((x) => x > above).sort((x, y) => y - x)) {
          out.push(...this.held(vkey, m['pending']!, n, b, ['unlisted']).map(car))
          if (out.length >= limit) break
        }
        return out.slice(0, limit)
      }
      case 'secrets':
      case 'secrets-after':
      case 'label':
      case 'label-after': {
        const v = vaultOf(m['org']!, m['secretsOf'] ?? m['vault']!)
        const b = await this.answerBranch(v)
        if (v === undefined || b === undefined) return []
        const after = m['after']
        const label = m['label']
        const out: LookupFormula = []
        for (const cur of b.fold.setNow()) {
          const id = toHex(cur.id)
          if (after !== undefined && id <= after) continue
          const es = this.held(v.key, id, cur.version, b, listed).filter((e) => label === undefined || e.view.label === label)
          if (es.length === 0) continue
          // A page never splits one secret's carriers, so the cursor loses nothing.
          if (out.length > 0 && out.length + es.length > limit) break
          const context = this.context(b, id)
          out.push(...es.map((e) => ({ ...car(e), context })))
        }
        return out
      }
      case 'sweep':
        return [...(this.sweepsByOp.get(`${crypt}|${m['spent']}`) ?? [])]
          .filter((s) => this.rows.get(m['spent']!)?.sweeps.has(s) === true || this.table.get(m['spent']!)?.has(s) === true)
          .map((s) => this.sweeps.get(s)!)
          .sort((a, b) => a.height - b.height || a.offset - b.offset || cmp(a.txid, b.txid))
          .slice(0, limit)
          .map((s) => ({ txid: s.txid, outputIndex: 0 }))
      case 'history':
      case 'history-after': {
        const org = m['history']!
        const vkey = this.vaultKey(crypt, org, m['vault']!)
        const b = await this.answerBranch(this.vaults.get(vkey))
        const after = m['after'] === undefined ? 0 : Number(m['after'])
        const out: LookupFormula = []
        for (const n of [...(this.versions.get(`${vkey}|${m['secret']}`)?.keys() ?? [])].filter((x) => x > after).sort((x, y) => x - y)) {
          const es = this.held(vkey, m['secret']!, n, b, answered)
          if (es.length === 0) continue
          // A page never splits one version's carriers.
          if (out.length > 0 && out.length + es.length > limit) break
          out.push(...es.map(car))
        }
        return out
      }
      case 'audit':
      case 'audit-after': {
        const v = vaultOf(m['audit']!, m['vault']!)
        if (v === undefined) return []
        const after = m['after'] === undefined ? -1 : Number(m['after'])
        const out: LookupFormula = []
        for (const seq of [...v.bySeq.keys()].filter((s) => s > after).sort((a, b) => a - b)) {
          const ts = (v.bySeq.get(seq) ?? []).filter((t) => t.rooted)
          if (ts.length === 0) continue
          // A page never splits a seq, so the cursor loses nothing.
          if (out.length > 0 && out.length + ts.length > limit) break
          out.push(...ts.map(tok))
        }
        return out
      }
    }
    throw new Error(`ls_bsecret: no answer for class ${q.class.name}`)
  }

  /**
   * An answer with each output's BEEF, as the engine hydrates one, read from
   * the host's storage: for the terms route, which answers outside the
   * engine. A context rides along as the engine passes it.
   */
  async hydrate(formula: LookupFormula): Promise<OutputList> {
    const storage = this.storage
    if (storage === undefined) throw new Error('ls_bsecret: storage is not restored yet')
    const outputs: OutputList['outputs'] = []
    for (const { txid, outputIndex, context } of formula) {
      const o = await storage.findOutput(txid, outputIndex, undefined, undefined, true)
      if (o?.beef === undefined) continue
      outputs.push(context === undefined ? { beef: o.beef, outputIndex } : { beef: o.beef, outputIndex, context })
    }
    return { type: 'output-list', outputs }
  }

  get restored(): boolean {
    return this.storage !== undefined
  }

  // ---- restore (spec section 11.4)

  /**
   * Rebuilds the index: the rows from the journal, then every output of this
   * module's topics the host hands over (a row handed without its BEEF is
   * read again from storage with it), then every token, carrier and sweep the
   * journal names that the unspent rows did not carry (a token its successor
   * spent, say), and then each held token's predecessors, read through the
   * input that spends them. A token is read as the engine stores it, the
   * token alone with its proof and without its parent, so a predecessor is
   * the token the host holds at seq - 1, never a BEEF's. Sweeps are taken in
   * storage's order, so the bounded table keeps the newest. Chains are
   * rooted and folded from seq 0 whatever order storage returns rows in,
   * and each seq is held to its bound only once every token's descent is
   * known. A storage failure propagates: a restore that skipped a sweep
   * would answer retracted carriers.
   */
  async restore(outputs: Output[], storage: RestoreStorage): Promise<number> {
    for (const m of [this.rows, this.seen, this.tokenSeen, this.vaults, this.vaultsByOrg, this.tokenVault, this.carriers, this.versions, this.sweeps, this.sweepsByOp, this.table, this.pending]) {
      m.clear()
    }
    const journal = this.journal.load()
    for (const l of journal) this.apply(l)
    const full = storage as Storage
    this.storage = full
    const seen = new Set<string>()
    const queue: Output[] = []
    for (const o of outputs) {
      const k = `${o.topic}|${o.txid}.${o.outputIndex}`
      if (this.cryptOf(o.topic) === undefined || seen.has(k)) continue
      seen.add(k)
      queue.push(o)
    }
    const named: Array<{ topic: string; txid: string; vout: number }> = []
    for (const [c, s] of this.seen) if (this.crypts.has(s.crypt)) named.push({ topic: topic(s.crypt), txid: displayTxid(fromHex(c)), vout: 0 })
    for (const [txid, t] of this.tokenSeen) if (this.crypts.has(t.crypt)) named.push({ topic: topic(t.crypt), txid, vout: t.vout })
    for (const r of this.rows.values()) for (const [s, sp] of r.sweeps) if (this.crypts.has(sp.crypt)) named.push({ topic: topic(sp.crypt), txid: s, vout: 0 })
    for (const n of named) {
      const k = `${n.topic}|${n.txid}.${n.vout}`
      if (seen.has(k)) continue
      seen.add(k)
      const o = await full.findOutput(n.txid, n.vout, n.topic, undefined, true)
      if (o !== null) queue.push(o)
    }
    const read = async (o: Output): Promise<Transaction | undefined> => {
      let row: Output | null = o
      if (row.beef === undefined) row = (await full.findOutput(o.txid, o.outputIndex, o.topic, undefined, true)) ?? row
      if (row.beef === undefined) return undefined
      try {
        const tx = Transaction.fromBEEF(row.beef, row.txid)
        const out = tx.outputs[o.outputIndex]
        if (out === undefined || classify(bin(out.lockingScript)) !== 'vault-token') return tx
        // A token as the engine stores it: alone, with its proof, read by the shared wire reader.
        return storedToken(Uint8Array.from(row.beef)).tx
      } catch {
        return undefined
      }
    }
    const txs: Array<{ o: Output; tx: Transaction; sweep: boolean }> = []
    for (const o of queue) {
      const tx = await read(o)
      if (tx === undefined) {
        this.host.log('ls_bsecret could not restore an output without its transaction', { topic: o.topic, txid: o.txid })
        continue
      }
      const out = tx.outputs[o.outputIndex]
      const sweep = out !== undefined && o.outputIndex === 0 && isFundingShape(bin(out.lockingScript))
      txs.push({ o, tx, sweep })
    }
    // Carriers and tokens first, sweeps after them in storage's order.
    txs.sort((a, b) => Number(a.sweep) - Number(b.sweep) || (a.sweep ? (a.o.score ?? 0) - (b.o.score ?? 0) || cmp(a.o.txid, b.o.txid) : 0))
    let indexed = 0
    this.restoring = true
    const take = (o: Output, tx: Transaction): void => {
      try {
        if (this.index(this.cryptOf(o.topic)!, tx, o.outputIndex, o.score ?? 0)) indexed++
      } catch (e) {
        this.host.log('ls_bsecret could not restore an output', { topic: o.topic, txid: o.txid, err: String(e) })
      }
    }
    for (const { o, tx } of txs) take(o, tx)
    // Each held token's predecessors, through the input that spends them.
    const walk: Array<{ t: string; tx: Transaction; prev: string }> = []
    const next = (o: Output, tx: Transaction): void => {
      const key = this.tokenVault.get(o.txid)
      const t = key === undefined ? undefined : this.vaults.get(key)?.byTxid.get(o.txid)
      if (t !== undefined && t.vout === o.outputIndex && t.prev !== '') walk.push({ t: o.topic, tx, prev: t.prev })
    }
    for (const { o, tx } of txs) next(o, tx)
    while (walk.length > 0) {
      const w = walk.pop()!
      if (this.tokenVault.has(w.prev)) continue
      const input = w.tx.inputs.find((i) => srcTxid(i) === w.prev)
      if (input === undefined) continue
      const o = await full.findOutput(w.prev, input.sourceOutputIndex, w.t, undefined, true)
      if (o === null) continue
      const tx = await read(o)
      if (tx === undefined) continue
      take(o, tx)
      next(o, tx)
    }
    this.restoring = false
    for (const v of this.vaults.values()) {
      for (const t of v.bySeq.get(0) ?? []) this.rootFrom(v, t, true)
      for (const t of v.byTxid.values()) if (!t.rooted) this.counted(v, t)
      for (const seq of [...v.bySeq.keys()]) this.bound(v, seq)
    }
    this.enforceTable()
    await this.flush()
    return indexed
  }

  async getDocumentation(): Promise<string> {
    return [
      '# ls_bsecret',
      '',
      'Answers every crypt this host carries (spec section 10.2). Free classes: `vault`',
      "(a vault's latest rooted tokens), `vault-seq` (every token held at one seq),",
      "`vaults`, `vaults-after` (the latest rooted token of each of an owner's vaults),",
      '`secret` (the carriers of the version the set holds, each with its inclusion',
      'path as context), `version`, `pending`, `secrets`, `secrets-after`, `label`,',
      '`label-after` (the set, 16 carriers a page, each with its path) and `sweep`',
      '(sweeps spending an outpoint). Priceable: `history`, `history-after` (every',
      "version of a secret) and `audit`, `audit-after` (every token of a vault's",
      'chain, by seq). A question must carry exactly the members of one class;',
      'anything else is refused with an error. An empty answer means only that this',
      'host holds nothing that answers.',
    ].join('\n')
  }

  async getMetaData(): Promise<LookupServiceMetaData> {
    return { name: ServiceName, shortDescription: 'Answers bsecret vaults, secrets and sweeps by crypt.' }
  }
}
