/**
 * The module and the real overlay engine together, for tests: an engine over
 * an in-memory store with the module's managers and lookup service mounted,
 * the configuration the tests use, and submit and answer helpers.
 */
import { Engine } from '@bsv/overlay'
import { Transaction, type ChainTracker } from '@bsv/sdk'
import type { Module, TopicManager } from '@lightwebinc/bcommon'
import { DefaultBudget } from './budget.js'
import { MemoryJournal } from './journal.js'
import { secretModule, type Config } from './module.js'
import { LookupService } from './secrec.js'
import { Chain } from './testmint.js'
import { FakeHost, MemoryStorage, quietConsole, txVectors } from './testutil.js'
import { Refused } from './tm_bsecret.js'

const v = txVectors()
export const topic = v.topic
export const crypt = v.crypt

export function engineOf(mod: Module, storage: MemoryStorage, tracker: ChainTracker): Engine {
  return new Engine(
    mod.topics as never,
    mod.lookups as never,
    storage as never,
    tracker,
    undefined,
    [],
    [],
    undefined,
    undefined,
    { [topic]: false },
    false,
    undefined,
    undefined,
    undefined,
    quietConsole(),
  )
}

export const config: Config = {
  crypts: [crypt],
  stateDir: '/nonexistent',
  headersURL: 'http://127.0.0.1:1',
  retentionDays: 31,
  unheldHours: 24,
  maxBEEF: 262144,
  maxSweepInputs: 1024,
  spendTable: 65536,
  prices: new Map(),
  sessions: { max: 100, ttlSeconds: 600 },
  handshakes: DefaultBudget,
}

export interface SetupOptions {
  naive?: boolean
  journal?: MemoryJournal
  chain?: Chain
  storage?: MemoryStorage
  spendTable?: number
  retentionDays?: number
  now?: () => number
}

/** A module and its engine, with storage handed over as the host does. */
export async function setup(opts: SetupOptions = {}) {
  const host = new FakeHost()
  const chain = opts.chain ?? new Chain(70000, v.headers)
  const journal = opts.journal ?? new MemoryJournal()
  const c = { ...config, spendTable: opts.spendTable ?? config.spendTable, retentionDays: opts.retentionDays ?? config.retentionDays }
  const m = secretModule(host, c, [topic], journal, chain.tracker, opts.now)
  const storage = opts.storage ?? new MemoryStorage()
  await m.ls.restore(await storage.findUTXOsForTopic(topic, undefined, undefined, true), storage)
  let calls = 0
  const tm = m.module.topics![topic]!
  const counting: TopicManager = {
    identifyAdmissibleOutputs: async (beef, previousCoins) => {
      calls++
      try {
        return await tm.identifyAdmissibleOutputs(beef, previousCoins)
      } catch (e) {
        // A manager that returned every refusal as empty instructions, as a
        // manager that does not raise would.
        if (opts.naive === true && e instanceof Refused) return { outputsToAdmit: [], coinsToRetain: [...previousCoins] }
        throw e
      }
    },
    getDocumentation: tm.getDocumentation.bind(tm),
    getMetaData: tm.getMetaData.bind(tm),
  }
  m.module.topics![topic] = counting
  return { host, ls: m.ls, storage, journal, chain, config: c, engine: engineOf(m.module, storage, chain.tracker), calls: () => calls }
}

export type Rig = Awaited<ReturnType<typeof setup>>

/** Submits; the outputs admitted, or undefined when the engine itself refused (its SPV). */
export async function submit(e: Engine, beef: number[] | Uint8Array): Promise<number[] | undefined> {
  try {
    const steak = await e.submit({ beef: Array.from(beef), topics: [topic] })
    return steak[topic]?.outputsToAdmit ?? []
  } catch {
    return undefined
  }
}

export interface Answered {
  tx: Transaction
  txid: string
  vout: number
  beef: number[]
  context?: number[]
}

/** An engine answer, hydrated: each output's transaction, and its context when it has one. */
export async function outputs(e: Engine, query: Record<string, unknown>): Promise<Answered[]> {
  const a = await e.lookup({ service: LookupService, query })
  if (a.type !== 'output-list') throw new Error('not an output list')
  return a.outputs.map((o) => {
    const tx = Transaction.fromBEEF(o.beef)
    return { tx, txid: tx.id('hex'), vout: o.outputIndex, beef: o.beef, context: (o as { context?: number[] }).context }
  })
}

/** An engine answer: each output's txid. */
export const answer = async (e: Engine, query: Record<string, unknown>): Promise<string[]> => (await outputs(e, query)).map((o) => o.txid)
