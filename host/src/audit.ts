/**
 * An auditor's side of a vault's trail (spec section 9.2), the twin of the
 * Go fold.go's Audit. A host never calls it: it is here so that a test
 * verifies what the `audit` class answers the way an auditor would, from
 * the tokens and block headers alone, and it is not part of the package's
 * entry point.
 */
import { bytesEqual } from '@lightwebinc/bcommon'
import { VaultFold, type TokenStatus } from './chain.js'
import { checkVaultTransition, reasonOf, type Vault } from './secrec.js'
import { toHex } from './util.js'

/** One vault token as an auditor holds it: its record, its txid (hash byte order) and the height of the block its proof names. */
export interface Mined {
  vault: Vault
  txid: Uint8Array
  height: number
}

/** One epoch of the vault's group, from the group's canonical chain: the height of the block that began it, and whether its token removed anyone. */
export interface EpochEvent {
  epoch: number
  epochId: Uint8Array
  height: number
  removed: boolean
}

/** What an audit reports for one epoch the group began after the vault's first token's. */
export interface Window {
  epoch: number
  removed: boolean
  /** The height of the group token that began the epoch. */
  began: number
  /** Vault tokens mined above began that still name an earlier epoch. */
  late: number
  /** The height of the first vault token at this epoch or later; 0 when none. */
  acknowledged: number
  /** The height of the first such token after which the fold holds nothing under an earlier epoch; 0 when none. */
  settled: number
  /** Secrets still under an earlier epoch at the end of the trail. */
  stale: number
}

export interface Finding {
  seq: number
  problem: 'empty' | 'first' | 'transition' | 'height' | 'status' | 'epoch' | 'group'
  detail: string
}

export interface Report {
  ok: boolean
  findings: Finding[]
  statuses: TokenStatus[]
  windows: Window[]
}

/**
 * Checks a vault's mined tokens, in seq order, against the epochs of its
 * group. It verifies no proof and no script: the caller has checked every
 * token and every epoch against its own headers and passes the heights it
 * found. A report that is not ok says nothing reliable about windows.
 */
export function audit(tokens: Mined[], epochs: EpochEvent[]): Report {
  const r: Report = { ok: true, findings: [], statuses: [], windows: [] }
  const bad = (seq: number, problem: Finding['problem'], detail = ''): void => {
    r.ok = false
    r.findings.push({ seq, problem, detail })
  }
  if (tokens.length === 0) {
    bad(0, 'empty')
    return r
  }
  const byEpoch = new Map(epochs.map((e) => [e.epoch, e]))
  const sorted = epochs.map((e, i) => ({ e, i })).sort((a, b) => a.e.epoch - b.e.epoch || a.i - b.i).map((x) => x.e)
  const ids = new Set<string>()
  for (const [i, e] of sorted.entries()) {
    const before = sorted[i - 1]
    if (ids.has(toHex(e.epochId)) || (before !== undefined && (e.epoch !== before.epoch + 1 || e.height < before.height))) {
      bad(0, 'group')
      return r
    }
    ids.add(toHex(e.epochId))
  }
  const first = tokens[0]!.vault.epoch
  for (const e of sorted) if (e.epoch > first) r.windows.push({ epoch: e.epoch, removed: e.removed, began: e.height, late: 0, acknowledged: 0, settled: 0, stale: 0 })
  if (tokens[0]!.vault.seq !== 0) bad(tokens[0]!.vault.seq, 'first')
  const f = new VaultFold()
  for (const [i, t] of tokens.entries()) {
    const v = t.vault
    const p = tokens[i - 1]
    if (p !== undefined) {
      try {
        checkVaultTransition(p.vault, p.txid, v)
      } catch (e) {
        bad(v.seq, 'transition', reasonOf(e))
      }
      if (t.height < p.height) bad(v.seq, 'height')
    }
    const st = f.apply(v)
    r.statuses.push(st)
    if (st !== 'consistent') bad(v.seq, 'status', st)
    const e = byEpoch.get(v.epoch)
    if (e === undefined) bad(v.seq, 'epoch', 'an epoch the group has not begun')
    else if (!bytesEqual(e.epochId, v.epochId)) bad(v.seq, 'epoch', 'another epoch id')
    else if (t.height < e.height) bad(v.seq, 'epoch', 'before the block that began the epoch')
    for (const w of r.windows) {
      if (v.epoch < w.epoch) {
        if (t.height > w.began) w.late++
        continue
      }
      if (w.acknowledged === 0) w.acknowledged = t.height
      if (w.settled === 0 && f.under(w.epoch) === 0) w.settled = t.height
    }
  }
  for (const w of r.windows) w.stale = f.under(w.epoch)
  return r
}
