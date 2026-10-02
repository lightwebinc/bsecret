/**
 * `tm_bsecret_<name>_<suffix>`: the topic manager of one crypt (spec
 * section 11.1), one instance per configured crypt. The rules are
 * admit.ts's; this file is the engine seam: it runs them on the submission
 * and turns the verdict into admittance instructions.
 *
 * The overlay engine records every transaction a topic manager returns
 * instructions for as applied, empty instructions included: a later
 * submission of the same txid is a duplicate no topic manager is shown
 * again. A refusal returned as empty instructions would therefore be
 * permanent for that txid: anyone could suppress a genuine carrier by
 * submitting it first in a different BEEF, and a token refused because the
 * host's headers lagged would stay refused. So every refusal is raised, and
 * the engine records nothing and marks nothing spent: a refused transaction
 * offered again is decided again.
 *
 * No rule reads another topic, another record or anything this topic holds:
 * the previous coins decide only which spent outputs are retained.
 */
import type { ChainTracker } from '@bsv/sdk'
import type { AdmittanceInstructions, ModuleHost, TopicManager } from '@lightwebinc/bcommon'
import { DefaultMaxBEEF, DefaultMaxSweepInputs, admit, type TxKind } from './admit.js'
import { Refusal, TopicPrefix, checkCrypt, type Reason } from './secrec.js'
import { toHex } from './util.js'

/**
 * Every label a host counts a refused submission by: the record rules of
 * spec section 3.1, the transition rules of section 4.2 and the
 * transaction rules of section 11.1. A reader's labels (`listing`,
 * `successor`, `hash`, `undecryptable`, `commitment`, `tag`, `payload`) and
 * `query` are never an admission verdict.
 */
export const Reasons: readonly Reason[] = [
  'too-large',
  'cbor',
  'key-type',
  'magic',
  'missing',
  'type',
  'range',
  'identity',
  'crypt',
  'hall',
  'name',
  'label',
  'list',
  'entry',
  'chain',
  'count',
  'debt',
  'content',
  'transition',
  'epoch',
  'shape',
  'beef',
  'mineable',
  'unlock',
  'lock',
  'signature',
  'funding',
  'unmined',
  'token-input',
  'vault-id',
  'not-bsecret',
]

/** What an admitted transaction was. */
export const AdmitKinds: readonly TxKind[] = ['secret', 'vault-token', 'sweep']

/** How many admitted txids a manager remembers to count each once. */
export const RecentAdmissions = 4096

/**
 * Raised for every refusal. The engine counts it as a failed topic for this
 * submission and stores nothing.
 */
export class Refused extends Error {
  constructor(
    readonly reason: Reason,
    detail: string,
  ) {
    super(`bsecret: refused, ${reason}: ${detail}`)
    this.name = 'Refused'
  }
}

export class SecretTopicManager implements TopicManager {
  readonly crypt: string

  constructor(
    readonly topic: string,
    private readonly host: ModuleHost,
    private readonly headers: ChainTracker,
    private readonly maxBEEF: number = DefaultMaxBEEF,
    private readonly maxSweepInputs: number = DefaultMaxSweepInputs,
  ) {
    if (!topic.startsWith(TopicPrefix)) throw new Error(`bsecret: ${topic} is not a tm_bsecret_ topic`)
    this.crypt = topic.slice(TopicPrefix.length)
    checkCrypt(this.crypt)
    // The floors (262144 bytes, 1024 inputs) are held where an operator sets
    // the bounds (module.ts); a test may name smaller ones.
    if (!Number.isSafeInteger(maxBEEF) || maxBEEF < 1) throw new Error(`bsecret: a BEEF bound of ${maxBEEF}`)
    if (!Number.isSafeInteger(maxSweepInputs) || maxSweepInputs < 1) throw new Error(`bsecret: a sweep input bound of ${maxSweepInputs}`)
  }

  async identifyAdmissibleOutputs(beef: number[], previousCoins: number[]): Promise<AdmittanceInstructions> {
    try {
      const a = await admit(beef, previousCoins, { crypt: this.crypt, headers: this.headers, maxBEEF: this.maxBEEF, maxSweepInputs: this.maxSweepInputs })
      this.count(a.kind, toHex(a.txid))
      return { outputsToAdmit: a.outputs, coinsToRetain: a.retain }
    } catch (e) {
      if (!(e instanceof Refusal)) throw e
      this.host.metrics.inc('bsecret_refused_total', { reason: e.reason })
      this.host.log('tm_bsecret refused', { topic: this.topic, reason: e.reason, detail: e.message })
      throw new Refused(e.reason, e.message.replace(/^secrec: /, ''))
    }
  }

  /**
   * Counts an admission once per transaction. The engine shows a manager a
   * txid it already applied only when two submissions of it race past its
   * duplicate check, so `bsecret_admitted_total` counts distinct
   * transactions and `bsecret_admitted_repeats_total` the rest. The memory
   * is the last RecentAdmissions txids.
   */
  private count(kind: TxKind, txid: string): void {
    if (this.recent.has(txid)) {
      this.host.metrics.inc('bsecret_admitted_repeats_total', { kind })
      return
    }
    this.recent.add(txid)
    if (this.recent.size > RecentAdmissions) this.recent.delete(this.recent.values().next().value as string)
    this.host.metrics.inc('bsecret_admitted_total', { kind })
  }

  private readonly recent = new Set<string>()

  /** Nothing is needed: a carrier carries its funding tree, a token its parent, and a sweep names what it spends. */
  async identifyNeededInputs(): Promise<Array<{ txid: string; outputIndex: number }>> {
    return []
  }

  async getDocumentation(): Promise<string> {
    return [
      `# ${this.topic}`,
      '',
      `The bsecret crypt ${this.crypt}: secret carriers, each spending one output of its`,
      "owner's mined funding tree; vault tokens, each mined and published with its",
      'parent; and the tombstones of mined sweeps (spec section 11.1). Each is admitted',
      "on its own bytes and the host's headers; no other record and nothing the topic",
      'holds is read. Every refusal is raised, so nothing refused is recorded.',
    ].join('\n')
  }

  async getMetaData(): Promise<{ name: string; shortDescription: string }> {
    return { name: this.topic, shortDescription: `Admits the bsecret crypt ${this.crypt}.` }
  }
}
