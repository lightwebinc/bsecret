/**
 * The vault's group, for tests: borg's own golden group records and wrap
 * records (internal/borgread/testdata, unchanged), read just far enough for
 * a member to do what borg asks of it before it opens a secret. A member
 * finds its wrap of an epoch's key, checks the wrap against the group token
 * that began the epoch (the record hashes to the epoch id), decrypts it with
 * its own wallet, and holds the key to the token's commitment. Nothing here
 * is borg's codec or part of the module the host loads: the rules are
 * borg's contract, and this reads four records of it.
 */
import { readFileSync } from 'node:fs'
import { PrivateKey, ProtoWallet } from '@bsv/sdk'
import { CborMap, bytesEqual, decodeValue } from '@lightwebinc/bcommon'
import { commitmentOf, symmetricKey } from './keyed.js'
import { bigEndian, concat, fromHex, sha256, toBase64, toHex } from './util.js'

const dir = new URL('../../internal/borgread/testdata/', import.meta.url)
const hexFile = (name: string): Uint8Array => fromHex(readFileSync(new URL(name, dir), 'utf8').trim())

/** borg's release derivation: BRC-369 section 5.2. */
export const ReleaseProtocol: [2, string] = [2, 'keyed content release']

function field<T>(m: CborMap, key: number, is: (v: unknown) => v is T): T {
  const v = m.get(BigInt(key))
  if (!is(v)) throw new Error(`testborg: key ${key}`)
  return v
}
const isBytes = (v: unknown): v is Uint8Array => v instanceof Uint8Array
const isInt = (v: unknown): v is bigint => typeof v === 'bigint'
const isText = (v: unknown): v is string => typeof v === 'string'
const isArray = (v: unknown): v is unknown[] => Array.isArray(v)

function mapOf(b: Uint8Array): CborMap {
  const v = decodeValue(b)
  if (!(v instanceof CborMap)) throw new Error('testborg: not a record')
  return v
}

/** One epoch of the group: the record of the token that began it, and its wraps. */
export interface GroupEpoch {
  epoch: number
  /** SHA-256 of the group record that began the epoch. */
  id: Uint8Array
  /** The BRC-369 digest of the epoch's key, as that record commits to it. */
  commitment: Uint8Array
  record: Uint8Array
  /** Whether the token that began the epoch removed anyone. */
  removed: boolean
  /** The wrap entries of the epoch's key, one per member it was released to. */
  entries: Uint8Array[]
}

export interface Group {
  hall: string
  org: Uint8Array
  group: Uint8Array
  epochs: GroupEpoch[]
}

/** The golden group: created with alice and bob, carol added, bob removed (epoch 1), rotated (epoch 2). */
export function goldenGroup(): Group {
  const epochs: GroupEpoch[] = []
  let hall = ''
  let org: Uint8Array = new Uint8Array(0)
  let group: Uint8Array = new Uint8Array(0)
  for (const name of ['group-create.hex', 'group-add.hex', 'group-remove.hex', 'group-rotate.hex']) {
    const record = hexFile(name)
    const m = mapOf(record)
    hall = field(m, 1, isText)
    org = field(m, 2, isBytes)
    group = field(m, 3, isBytes)
    // A token begins an epoch when its epochSeq is its own seq.
    if (field(m, 4, isInt) !== field(m, 8, isInt)) continue
    epochs.push({ epoch: Number(field(m, 7, isInt)), id: sha256(record), commitment: field(m, 9, isBytes), record, removed: field(m, 11, isArray).length > 0, entries: [] })
  }
  for (const name of ['wrap-create.hex', 'wrap-add.hex', 'wrap-remove.hex', 'wrap-rotate.hex']) {
    const m = mapOf(hexFile(name))
    const e = epochs.find((x) => x.epoch === Number(field(m, 4, isInt)))
    if (e === undefined || !bytesEqual(e.id, field(m, 5, isBytes))) throw new Error(`testborg: ${name} names no epoch of the group`)
    for (const entry of field(m, 6, isArray)) if (isBytes(entry)) e.entries.push(entry)
  }
  return { hall, org, group, epochs }
}

/** The test identities of borg's vectors and of this contract's: 32 bytes of one value. */
export const identity = (name: 'org' | 'alice' | 'bob' | 'carol' | 'dave'): PrivateKey =>
  PrivateKey.fromHex({ org: '51', alice: '52', bob: '53', carol: '54', dave: '56' }[name].repeat(32))

/**
 * A member's read of one epoch's key, in borg's order: its own entry of the
 * epoch's wraps (`entry` when it has none), the decryption by its own
 * wallet (`undecryptable`), the key against the commitment of the token
 * that began the epoch (`commitment`). It returns the epoch's BRC-369
 * symmetric key, or the label of the check that failed.
 */
export async function openEpoch(g: Group, epoch: number, member: PrivateKey): Promise<{ symmetric?: Uint8Array; refused?: string }> {
  const e = g.epochs.find((x) => x.epoch === epoch)
  if (e === undefined) return { refused: 'token' }
  const me = Uint8Array.from(member.toPublicKey().encode(true) as number[])
  const keyId = sha256(concat([e.id, bigEndian(epoch, 4)]))
  // version (4), sender (33), recipient (33), key id (32), ciphertext (80).
  const mine = e.entries.find((w) => w.length === 182 && bytesEqual(w.subarray(4, 37), g.org) && bytesEqual(w.subarray(37, 70), me) && bytesEqual(w.subarray(70, 102), keyId))
  if (mine === undefined) return { refused: 'entry' }
  let key: Uint8Array
  try {
    const r = await new ProtoWallet(member).decrypt({ protocolID: ReleaseProtocol, keyID: toBase64(keyId), counterparty: toHex(g.org), ciphertext: Array.from(mine.subarray(102)) })
    key = Uint8Array.from(r.plaintext)
  } catch {
    return { refused: 'undecryptable' }
  }
  if (key.length !== 32 || !bytesEqual(commitmentOf(key), e.commitment)) return { refused: 'commitment' }
  return { symmetric: symmetricKey(key) }
}
