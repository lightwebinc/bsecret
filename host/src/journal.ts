/**
 * What ls_bsecret keeps for the host's life (spec sections 11.2 and 11.3),
 * as an append-only journal beside the engine's storage. The engine's
 * storage holds the outputs a host still keeps; it cannot hold what must
 * outlive them: which carrier won a funding outpoint, that a winner was
 * dropped, the sweeps that spent the outpoint, and when the host first saw
 * each token and each carrier.
 *
 * One JSON object a line:
 *
 *   {"k":"c","op":"<txid>.<vout>","c":"<C>","crypt":"...","at":<s>}
 *   {"k":"m","op":"..."}
 *   {"k":"d","op":"...","c":"<C>","w":true}
 *   {"k":"s","op":"...","s":"<sweep txid>","crypt":"...","h":<height>,"at":<s>}
 *   {"k":"t","txid":"<txid>","vout":<n>,"crypt":"...","at":<s>}
 *
 * `c` lines are the carriers a funding outpoint's row took in, each with
 * the outpoint it spent; an `m` line counts a carrier the row did not keep
 * (it was full of lower commitments), without its commitment; `d` lines are
 * drops, `w` when the dropped carrier was its outpoint's winner; `s` lines
 * are admitted sweeps' spends of outpoints a carrier spent (spends of any
 * other outpoint live only in the bounded table, never here); `t` lines are
 * vault tokens. Replayed in order, the lines rebuild every outpoint's row:
 * its winner as a running minimum, the lowest eight of the rest, the count
 * of the others, whether its winner was dropped, and its sweeps.
 * Commitments are in hash byte order and txids in display order, both
 * lowercase hex; `at` is the host's time of first sight in Unix seconds.
 */
import { closeSync, fdatasyncSync, mkdirSync, openSync, readFileSync, truncateSync, writeSync } from 'node:fs'
import { join } from 'node:path'

export interface CarrierLine {
  k: 'c'
  op: string
  c: string
  crypt: string
  at: number
}

export interface MoreLine {
  k: 'm'
  op: string
}

export interface DropLine {
  k: 'd'
  op: string
  c: string
  w: boolean
}

export interface SweepLine {
  k: 's'
  op: string
  s: string
  crypt: string
  h: number
  at: number
}

export interface TokenLine {
  k: 't'
  txid: string
  vout: number
  crypt: string
  at: number
}

export type Line = CarrierLine | MoreLine | DropLine | SweepLine | TokenLine

/** Where the rows live. `append` is durable when it returns. */
export interface Journal {
  load(): Line[]
  append(l: Line): void
}

/** A journal in memory, for tests and for a host that accepts losing it. */
export class MemoryJournal implements Journal {
  readonly lines: Line[] = []
  load(): Line[] {
    return this.lines.map((l) => ({ ...l }))
  }
  append(l: Line): void {
    this.lines.push({ ...l })
  }
}

function isLine(v: unknown): v is Line {
  if (typeof v !== 'object' || v === null) return false
  const o = v as Record<string, unknown>
  const s = (k: string): boolean => typeof o[k] === 'string'
  const n = (k: string): boolean => typeof o[k] === 'number' && Number.isSafeInteger(o[k]) && (o[k] as number) >= 0
  switch (o['k']) {
    case 'c':
      return s('op') && s('c') && s('crypt') && n('at')
    case 'm':
      return s('op')
    case 'd':
      return s('op') && s('c') && typeof o['w'] === 'boolean'
    case 's':
      return s('op') && s('s') && s('crypt') && n('h') && n('at')
    case 't':
      return s('txid') && n('vout') && s('crypt') && n('at')
  }
  return false
}

/** The journal's file name in the state directory. */
export const JournalFile = 'bsecret-rows.jsonl'

/**
 * The journal as a file, `bsecret-rows.jsonl` in dir. Each line is written
 * and flushed to disk before append returns. A last line cut short by a
 * crash is cut off on load; any other line that does not parse stops the
 * load, because a row silently skipped could let a swept or superseded
 * carrier be answered again.
 */
export class FileJournal implements Journal {
  readonly path: string
  private fd: number | undefined

  constructor(dir: string) {
    mkdirSync(dir, { recursive: true })
    this.path = join(dir, JournalFile)
  }

  load(): Line[] {
    let text: string
    try {
      text = readFileSync(this.path, 'utf8')
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return []
      throw e
    }
    if (text.length > 0 && !text.endsWith('\n')) {
      const keep = text.lastIndexOf('\n') + 1
      truncateSync(this.path, Buffer.byteLength(text.slice(0, keep), 'utf8'))
      text = text.slice(0, keep)
    }
    const out: Line[] = []
    for (const [i, l] of text.split('\n').entries()) {
      if (l === '') continue
      let v: unknown
      try {
        v = JSON.parse(l)
      } catch {
        throw new Error(`${this.path}: line ${i + 1} is not JSON`)
      }
      if (!isLine(v)) throw new Error(`${this.path}: line ${i + 1} is not a bsecret row`)
      out.push(v)
    }
    return out
  }

  append(l: Line): void {
    this.fd ??= openSync(this.path, 'a')
    writeSync(this.fd, JSON.stringify(l) + '\n')
    fdatasyncSync(this.fd)
  }

  close(): void {
    if (this.fd !== undefined) closeSync(this.fd)
    this.fd = undefined
  }
}
