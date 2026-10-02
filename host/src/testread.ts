/**
 * What a member and an auditor do with a host's answers, for tests: the
 * reader's checks of spec sections 14 and 7.2 and the auditor's of section
 * 9.2, each over a function that asks one question and returns the answered
 * outputs with their BEEF. The same code reads from the engine in a test
 * and from a reference host over HTTP. Nothing here is part of the module
 * the host loads, and nothing here trusts a host: every token is held to
 * the reader's own headers and every record to the token that lists it.
 */
import type { ChainTracker, PrivateKey, Transaction } from '@bsv/sdk'
import { admit, checkFirstToken, checkNextToken, mined, storedToken, type VaultToken } from './admit.js'
import { audit, type EpochEvent, type Mined, type Report } from './audit.js'
import { VaultFold, checkInSet } from './chain.js'
import { readAsMember } from './keyed.js'
import { decodeContext } from './merkle.js'
import { reasonOf } from './secrec.js'
import { openEpoch, type Group } from './testborg.js'
import { hashOrder } from './util.js'

export interface AskedOutput {
  tx: Transaction
  beef: number[]
  context?: number[]
}
export type Ask = (query: Record<string, string>) => Promise<AskedOutput[]>

export interface Named {
  crypt: string
  org: string
  vault: string
}

export interface HeldToken {
  tx: Transaction
  token: VaultToken
  height: number
}

/**
 * The vault's chain from seq 0, token by token through the free `vault-seq`
 * class: each proof against the reader's headers, each token well formed,
 * each a spend of the one before it under the transition rules, and the
 * fold consistent. Where a host answers several tokens at one seq, the one
 * that is mined for this reader and descends from the chain so far is
 * taken. It throws the label of the check that failed.
 */
export async function walk(ask: Ask, headers: ChainTracker, who: Named): Promise<HeldToken[]> {
  const chain: HeldToken[] = []
  const fold = new VaultFold()
  for (let seq = 0; ; seq++) {
    const answered = await ask({ crypt: who.crypt, org: who.org, vault: who.vault, seq: String(seq) })
    let next: HeldToken | undefined
    for (const o of answered) {
      try {
        const { tx } = storedToken(Uint8Array.from(o.beef))
        if (!(await mined(tx, headers))) continue
        const prev = chain[chain.length - 1]
        const token = prev === undefined ? checkFirstToken(tx).token : checkNextToken(prev.tx, prev.token, tx)
        next = { tx, token, height: tx.merklePath!.blockHeight }
        break
      } catch {
        // Not the vault's token at this seq for this reader.
      }
    }
    if (next === undefined) return chain
    if (fold.apply(next.token.vault) !== 'consistent') throw new Error('listing: the chain is broken')
    chain.push(next)
  }
}

export interface Read {
  value?: string
  version?: number
  epoch?: number
  /** The label of the check that failed. */
  refused?: string
}

/**
 * A member's read of one secret from a host's answers: the chain walked
 * from seq 0, the answered carrier held to the carrier rules and to the
 * latest token by its inclusion path, the epoch it names found on the
 * group's chain, that epoch's key opened from borg's wrap by the member's
 * own wallet, and then checks 1 to 4 of spec section 7.2.
 */
export async function readSecret(ask: Ask, headers: ChainTracker, who: Named, secret: string, group: Group, member: PrivateKey): Promise<Read> {
  const chain = await walk(ask, headers, who)
  const latest = chain[chain.length - 1]
  if (latest === undefined) return { refused: 'listing' }
  const claimed = await ask({ crypt: who.crypt, org: who.org, vault: who.vault })
  if (!claimed.some((o) => o.tx.id('hex') === latest.tx.id('hex'))) return { refused: 'rollback' }
  const answered = await ask({ crypt: who.crypt, org: who.org, vault: who.vault, secret })
  if (answered.length === 0) return { refused: 'listing' }
  let refused = 'listing'
  for (const o of answered) {
    try {
      const a = await admit(o.beef, [], { crypt: who.crypt, headers })
      const rec = a.carrier!.secret
      checkInSet(latest.token.vault, hashOrder(latest.tx.id('hex')), rec, o.context === undefined ? undefined : decodeContext(Uint8Array.from(o.context)))
      const opened = await openEpoch(group, rec.epoch, member)
      if (opened.symmetric === undefined) {
        refused = opened.refused!
        continue
      }
      if (rec.inline === undefined) throw new Error('hash')
      const p = readAsMember(rec, rec.inline, opened.symmetric)
      return { value: new TextDecoder().decode(p.value), version: rec.version, epoch: rec.epoch }
    } catch (e) {
      refused = reasonOf(e) === 'other' ? (e as Error).message : reasonOf(e)
    }
  }
  return { refused }
}

/**
 * An auditor's read of a vault's trail through the `audit` class, page by
 * page: every token's proof against the auditor's own headers, its output,
 * lock and signature, its descent from the first token, and then the audit
 * of the trail against the group's epochs (spec section 9.2). It holds no
 * key and reads no secret.
 */
export async function auditTrail(ask: Ask, headers: ChainTracker, who: Named, epochs: EpochEvent[]): Promise<{ report: Report; tokens: HeldToken[] }> {
  const pages: AskedOutput[] = []
  let after: string | undefined
  for (;;) {
    const page = await ask(after === undefined ? { crypt: who.crypt, audit: who.org, vault: who.vault } : { crypt: who.crypt, audit: who.org, vault: who.vault, after })
    if (page.length === 0) break
    pages.push(...page)
    after = String(storedToken(Uint8Array.from(page[page.length - 1]!.beef)).token.vault.seq)
  }
  const tokens: HeldToken[] = []
  for (const o of pages) {
    const { tx } = storedToken(Uint8Array.from(o.beef))
    if (!(await mined(tx, headers))) continue
    const prev = tokens[tokens.length - 1]
    try {
      const token = prev === undefined ? checkFirstToken(tx).token : checkNextToken(prev.tx, prev.token, tx)
      tokens.push({ tx, token, height: tx.merklePath!.blockHeight })
    } catch {
      // Another branch's token, or one that is not this vault's next.
    }
  }
  const trail: Mined[] = tokens.map((t) => ({ vault: t.token.vault, txid: hashOrder(t.tx.id('hex')), height: t.height }))
  return { report: audit(trail, epochs), tokens }
}
