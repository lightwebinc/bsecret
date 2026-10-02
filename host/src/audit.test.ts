/**
 * The auditor's checks against audit-v1.json: the scenario's trail, the
 * same trail cut short, a vault that never acknowledges, and the refused
 * trails that can be rebuilt from the scenario's own tokens.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { audit, type EpochEvent, type Mined, type Report } from './audit.js'
import { decodeVault } from './secrec.js'
import { hexVector, readVectors } from './testutil.js'
import { fromHex } from './util.js'

interface WindowVector {
  epoch: number
  removedAMember: boolean
  groupBeganAtHeight: number
  vaultTokensStillUnderAnEarlierEpoch: number
  vaultAcknowledgedAtHeight: number
  nothingUnderAnEarlierEpochAtHeight: number
  underAnEarlierEpochAtEnd: number
}

const f = readVectors<{
  groupEpochs: Array<{ epoch: number; epochId: string; height: number; removedAMember: boolean }>
  tokens: Array<{ seq: number; standInTxid: string; height: number; status: string }>
  windows: WindowVector[]
  cutAtSeq3: { windows: WindowVector[] }
  neverAcknowledged: { heights: number[]; records: string[]; windows: WindowVector[] }
  refused: Array<{ label: string; problems: string[] }>
}>('audit-v1.json')
const files = readVectors<{ records: Array<{ file: string }> }>('vault-v1.json').records.map((r) => r.file)
const epochs: EpochEvent[] = f.groupEpochs.map((e) => ({ epoch: e.epoch, epochId: fromHex(e.epochId), height: e.height, removed: e.removedAMember }))
const trail: Mined[] = f.tokens.map((t, i) => ({ vault: decodeVault(hexVector(files[i]!)), txid: fromHex(t.standInTxid), height: t.height }))

const windows = (r: Report): WindowVector[] =>
  r.windows.map((w) => ({
    epoch: w.epoch,
    removedAMember: w.removed,
    groupBeganAtHeight: w.began,
    vaultTokensStillUnderAnEarlierEpoch: w.late,
    vaultAcknowledgedAtHeight: w.acknowledged,
    nothingUnderAnEarlierEpochAtHeight: w.settled,
    underAnEarlierEpochAtEnd: w.stale,
  }))
const problems = (r: Report): string[] => r.findings.map((x) => `seq ${x.seq}: ${x.problem}${x.detail === '' ? '' : `: ${x.detail}`}`)
const refused = (label: string): string[] => f.refused.find((x) => x.label === label)!.problems

test('audit-v1: the trail passes, and its windows are those the Go codec derived', () => {
  const r = audit(trail, epochs)
  assert.equal(r.ok, true)
  assert.deepEqual(r.statuses, f.tokens.map((t) => t.status))
  assert.deepEqual(windows(r), f.windows)
  assert.deepEqual(windows(audit(trail.slice(0, 4), epochs)), f.cutAtSeq3.windows)
})

test('audit-v1: a vault that never acknowledges passes every check, and the audit counts what it wrote under the old epoch', () => {
  const recs = f.neverAcknowledged.records.map((h) => decodeVault(fromHex(h)))
  const tokens: Mined[] = recs.map((vault, i) => ({ vault, txid: recs[i + 1]?.prev ?? new Uint8Array(32), height: f.neverAcknowledged.heights[i]! }))
  const r = audit(tokens, epochs)
  assert.equal(r.ok, true)
  assert.deepEqual(windows(r), f.neverAcknowledged.windows)
})

test('audit-v1: the trails an audit refuses', () => {
  assert.equal(f.refused.length, 12)
  assert.deepEqual(problems(audit([], epochs)), refused('no tokens'))
  assert.deepEqual(problems(audit(trail.slice(1), epochs)), refused('a trail that does not start at seq 0'))
  assert.deepEqual(problems(audit([...trail.slice(0, 2), ...trail.slice(3)], epochs)), refused('a token left out of the middle'))
  assert.deepEqual(problems(audit(trail, [epochs[0]!, epochs[2]!])).slice(0, 1), refused('a group epoch missing from the middle'))
  assert.deepEqual(problems(audit(trail, [epochs[0]!, epochs[1]!, epochs[1]!, epochs[2]!])), refused('a group epoch given twice'))
  assert.deepEqual(problems(audit(trail, [epochs[0]!, { ...epochs[1]!, height: 900 }, epochs[2]!])), refused('group epochs out of height order'))
  assert.deepEqual(problems(audit(trail, [epochs[0]!, { ...epochs[1]!, epochId: new Uint8Array(32) }, epochs[2]!])), refused('a token whose epoch id is not the one the group gave that epoch').concat(['seq 4: epoch: another epoch id', 'seq 5: epoch: another epoch id']))
  assert.deepEqual(problems(audit(trail, epochs.slice(0, 2))), refused('a token that names an epoch the group has not begun'))
  const below = trail.map((t, i) => (i === 1 ? { ...t, height: 1000 } : t))
  assert.deepEqual(problems(audit(below, epochs)), refused('a token mined below the one it spends'))
})
