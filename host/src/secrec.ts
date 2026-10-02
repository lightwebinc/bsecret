/**
 * The byte-level contract of bsecret, the twin of the Go package
 * internal/secrec: the vault record that rides a mined chain token, the
 * secret record that rides an unmined carrier, and the crypt, hall, label
 * and name grammars. docs/spec.md is the normative text; the vectors under
 * testdata/vectors hold both codecs to the same bytes.
 *
 * Every record is canonical CBOR through @lightwebinc/bcommon, so one value
 * has one encoding a reader accepts. Decoding follows the refusal order of
 * spec section 3.1 step for step, so both codecs refuse a record for the
 * same reason.
 */
import { PrivateKey } from '@bsv/sdk'
import { CborMap, ascending, bytesEqual, compareBytes, encode, recordReader, strictPublicKey, type Pair, type RecordFields, type Value } from '@lightwebinc/bcommon'
import { bigEndian, concat, sha256, utf8 } from './util.js'

/** The BRC-43 protocol of every public derivation, security level 1, and its key ids. */
export const ProtocolName = 'bsecret'
export const Protocol: [1, string] = [1, ProtocolName]
export const KeyVault = 'vault'
export const KeySecret = 'secret'
export const KeyChain = 'chain'
export const KeyFund = 'fund'

/** The self wrap's protocol, security level 2, counterparty self. */
export const SelfProtocolName = 'bsecret self'
export const SelfProtocol: [2, string] = [2, SelfProtocolName]

/** The overlay names (BRC-87). */
export const TopicPrefix = 'tm_bsecret_'
export const LookupService = 'ls_bsecret'

/** BRC-369 section 2's domain strings, and bsecret's own. */
export const DomainSymmetric = 'metanet keyed content symmetric v1'
export const DomainCommitment = 'metanet keyed content commitment v1'
export const DomainVaultID = 'bsecret vault id v1'
export const DomainSecretID = 'bsecret secret id v1'
export const DomainEpochWrap = 'bsecret epoch wrap v1'

/** Tags and magics. The tag prefix "se" belongs to bsecret. */
export const TagVault = Uint8Array.of(0x73, 0x65, 0x01)
export const TagFunding = Uint8Array.of(0x73, 0x65, 0x02)
export const MagicVault = Uint8Array.of(0x73, 0x65, 0x76, 0x01)
export const MagicSecret = Uint8Array.of(0x73, 0x65, 0x73, 0x01)
export const MagicPayload = Uint8Array.of(0x73, 0x65, 0x70, 0x01)

/** Bounds. A reader accepts every record within them. */
export const MaxSafe = Number.MAX_SAFE_INTEGER
export const MaxTime = 253402300799
export const MaxEpoch = 0xffffffff
export const SuffixLen = 10
export const MaxCrypt = 50 - TopicPrefix.length
export const MaxCryptName = MaxCrypt - 1 - SuffixLen
export const MinCrypt = 1 + 1 + SuffixLen
export const MinHall = 12
export const MaxHall = 42
export const GroupIDLen = 16
export const MaxName = 64
export const MaxSecretName = 128
export const MaxLabels = 16
export const MaxLabel = 32
export const MaxDelta = 64
export const MaxSecrets = 4096
export const MaxVaultRecord = 20480
export const MaxInline = 16384
export const MaxSecretRecord = MaxInline + 1024
/** The ciphertext a record describes: 2^27 bytes at most. */
export const MaxLength = 2 ** 27
export const MinSegment = 16
export const MaxSegment = 2 ** 20
export const TagLen = 16
export const SaltLen = 4
export const WrapLen = 80
export const MaxType = 128
/** An encoded payload: 2^26 bytes at most. */
export const MaxPayload = 2 ** 26

/** Anchor modes of a vault, fixed at its first token. */
export const AnchorVersion = 0
export const AnchorInterval = 1

export const DefaultLabels = ['confidential', 'internal', 'public', 'restricted']

/**
 * The fixed labels a host counts refusals by and a reader names a failed
 * check by: the record reasons of spec section 3.1, the transition reasons
 * of section 4.2, the transaction reasons of section 11.1, and a reader's
 * check labels of section 7.2.
 */
export type Reason =
  | 'too-large'
  | 'cbor'
  | 'key-type'
  | 'magic'
  | 'missing'
  | 'type'
  | 'range'
  | 'identity'
  | 'crypt'
  | 'hall'
  | 'name'
  | 'label'
  | 'list'
  | 'entry'
  | 'chain'
  | 'count'
  | 'debt'
  | 'content'
  | 'transition'
  | 'epoch'
  | 'query'
  | 'listing'
  | 'successor'
  | 'hash'
  | 'undecryptable'
  | 'commitment'
  | 'tag'
  | 'payload'
  | 'shape'
  | 'beef'
  | 'mineable'
  | 'unlock'
  | 'lock'
  | 'signature'
  | 'funding'
  | 'unmined'
  | 'token-input'
  | 'vault-id'
  | 'not-bsecret'

/** A refusal: the reason label, and a detail for people. */
export class Refusal extends Error {
  constructor(
    readonly reason: Reason,
    detail?: string,
  ) {
    super(detail === undefined ? `secrec: ${reason}` : `secrec: ${reason}: ${detail}`)
    this.name = 'Refusal'
  }
}

/** The reason of a thrown value: a Refusal's label, 'other' for anything else. */
export function reasonOf(e: unknown): Reason | 'other' {
  return e instanceof Refusal ? e.reason : 'other'
}

/** BRC-43's anyone key: the generator point. It is never an owner. */
export const AnyoneKey = Uint8Array.from(new PrivateKey(1).toPublicKey().encode(true) as number[])

export const isAnyone = (k: Uint8Array): boolean => bytesEqual(k, AnyoneKey)

/** The owner's key rule: a canonical compressed key (bcommon strictPublicKey), never the anyone key. */
export function checkOrgKey(k: Uint8Array): void {
  if (strictPublicKey(k) === undefined || isAnyone(k)) throw new Refusal('identity')
}

/** The readable part of a crypt or hall identifier: lowercase letters and single underscores, a letter first and last. */
function readable(s: string, max: number): boolean {
  if (s.length === 0 || s.length > max) return false
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c >= 0x61 && c <= 0x7a) continue
    if (c === 0x5f && i !== 0 && i !== s.length - 1 && s.charCodeAt(i - 1) !== 0x5f) continue
    return false
  }
  return true
}

/** <name>_<suffix>: a readable part and exactly ten lowercase letters. */
function suffixed(s: string, min: number, max: number, maxName: number): boolean {
  if (s.length < min || s.length > max) return false
  const cut = s.length - SuffixLen - 1
  if (s.charCodeAt(cut) !== 0x5f) return false
  for (let i = cut + 1; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c < 0x61 || c > 0x7a) return false
  }
  return readable(s.slice(0, cut), maxName)
}

export function checkCryptName(s: string): void {
  if (!readable(s, MaxCryptName)) throw new Refusal('crypt')
}

/** The crypt identifier grammar of spec section 10.1. */
export function checkCrypt(s: string): void {
  if (!suffixed(s, MinCrypt, MaxCrypt, MaxCryptName)) throw new Refusal('crypt')
}

/** The grammar of the identifier of the hall a vault's group lives in. */
export function checkHall(s: string): void {
  if (!suffixed(s, MinHall, MaxHall, MaxHall - 1 - SuffixLen)) throw new Refusal('hall')
}

/**
 * Creates a crypt identifier for name: name, an underscore and ten letters
 * drawn uniformly at random. random(n) returns n random bytes
 * (crypto.getRandomValues when omitted). The draw is the Go codec's: one byte
 * at a time, a byte of 234 or more (234 = 9 * 26) skipped, so the same bytes
 * give the same suffix in both languages.
 */
export function newCrypt(name: string, random?: (n: number) => Uint8Array): string {
  checkCryptName(name)
  const draw = random ?? ((n: number) => crypto.getRandomValues(new Uint8Array(n)))
  let suffix = ''
  while (suffix.length < SuffixLen) {
    const b = draw(1)
    if (b.length !== 1) throw new Error('secrec: short random read')
    if (b[0]! < 234) suffix += String.fromCharCode(0x61 + (b[0]! % 26))
  }
  return `${name}_${suffix}`
}

/** The topic manager name of a crypt. */
export const topic = (crypt: string): string => TopicPrefix + crypt

const lower = (c: number): boolean => c >= 0x61 && c <= 0x7a
const digit = (c: number): boolean => c >= 0x30 && c <= 0x39

/** The label grammar of spec section 5.3. */
export function checkLabel(s: string): void {
  if (s.length === 0 || s.length > MaxLabel || !lower(s.charCodeAt(0))) throw new Refusal('label')
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (lower(c) || digit(c)) continue
    if (c === 0x2d && i !== s.length - 1 && s.charCodeAt(i - 1) !== 0x2d) continue
    throw new Refusal('label')
  }
}

/** The label set rule: 1 to 16 labels, each meeting the grammar, strictly ascending. */
export function checkLabels(a: string[]): void {
  if (a.length < 1 || a.length > MaxLabels) throw new Refusal('label')
  for (const [i, l] of a.entries()) {
    checkLabel(l)
    if (i > 0 && a[i - 1]! >= l) throw new Refusal('label')
  }
}

/** The grammar of a secret's name (spec section 5.2). */
export function checkSecretName(s: string): void {
  if (s.length === 0 || s.length > MaxSecretName || s.startsWith('/') || s.endsWith('/')) throw new Refusal('name')
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (lower(c) || digit(c) || c === 0x2e || c === 0x5f || c === 0x2d) continue
    if (c === 0x2f && s.charCodeAt(i - 1) !== 0x2f) continue
    throw new Refusal('name')
  }
}

/** A vault's identifier: the hash of the outpoint its first token spends (txid in hash byte order). */
export function vaultID(txid: Uint8Array, vout: number): Uint8Array {
  return sha256(concat([utf8(DomainVaultID), txid, bigEndian(vout, 4)]))
}

/** A secret's identifier, stable across its versions. */
export function secretID(vault: Uint8Array, name: string): Uint8Array {
  checkSecretName(name)
  return sha256(concat([utf8(DomainSecretID), vault, utf8(name)]))
}

/** The leaf datum the vault's root commits one current secret by. */
export function leaf(id: Uint8Array, version: number, contentID: Uint8Array): Uint8Array {
  return sha256(concat([id, bigEndian(version, 8), contentID]))
}

// ---- the record reader, refusal steps 1 to 6 ----

type Fields = RecordFields

const rec = recordReader((reason, detail) => new Refusal(reason, detail))

/** The record reader with bsecret's refusals, for the payload codec beside this one. */
export const records = rec

const zero32 = (b: Uint8Array): boolean => b.every((x) => x === 0)
const k = (n: number): bigint => BigInt(n)

/** The display-name rule: 1 to 64 bytes of UTF-8 text. */
function checkName(s: string): void {
  const n = utf8(s).length
  if (n < 1 || n > MaxName) throw new Refusal('name')
}

// ---- the vault record ----

/** One change a vault token lists: a version of a secret entering the current set. */
export interface Entry {
  id: Uint8Array
  version: number
  contentId: Uint8Array
  commitment: Uint8Array
}

export interface Vault {
  crypt: string
  org: Uint8Array
  vault: Uint8Array
  seq: number
  /** Hash byte order; zero exactly at seq 0. */
  prev: Uint8Array
  name: string
  hall: string
  group: Uint8Array
  epoch: number
  epochId: Uint8Array
  labels: string[]
  anchor: number
  create: Entry[]
  update: Entry[]
  retire: Uint8Array[]
  count: number
  stale: number
  root: Uint8Array
  created: number
  extra: Pair[]
}

/** A change list: length (list), then each entry (entry), then order (list). */
function entries(f: Fields, key: number): Entry[] {
  const a = rec.array(f, key, MaxDelta)
  const out = a.map((x): Entry => {
    if (!Array.isArray(x) || x.length !== 4) throw new Refusal('entry', `key ${key}`)
    const [id, version, contentId, commitment] = x
    if (!(id instanceof Uint8Array) || typeof version !== 'bigint' || version < 0n || !(contentId instanceof Uint8Array) || !(commitment instanceof Uint8Array)) {
      throw new Refusal('entry', `key ${key}`)
    }
    if (id.length !== 32 || contentId.length !== 32 || commitment.length !== 32) throw new Refusal('entry', `key ${key}`)
    if (version > BigInt(MaxSafe)) return { id, version: Infinity, contentId, commitment }
    return { id, version: Number(version), contentId, commitment }
  })
  for (const e of out) if (e.version < 1 || e.version > MaxSafe) throw new Refusal('entry', `key ${key}`)
  if (!ascending(out.map((e) => e.id))) throw new Refusal('list', `key ${key}`)
  return out
}

function labels(f: Fields, key: number): string[] {
  const v = rec.need(f, key)
  if (!Array.isArray(v)) throw new Refusal('type', `key ${key}`)
  if (v.length < 1 || v.length > MaxLabels) throw new Refusal('label')
  const out = v.map((x) => {
    if (typeof x !== 'string') throw new Refusal('label')
    return x
  })
  checkLabels(out)
  return out
}

const hexKey = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

/** Refusal step 7 for a vault record: the rules across fields. */
function vaultCross(v: Vault): void {
  const seen = new Set<string>()
  const keys = new Set<string>()
  for (const e of [...v.create, ...v.update]) {
    if (seen.has(hexKey(e.id))) throw new Refusal('list', 'a secret changed twice in one transition')
    seen.add(hexKey(e.id))
    if (keys.has(hexKey(e.commitment))) throw new Refusal('list', 'a commitment repeated in one transition')
    keys.add(hexKey(e.commitment))
  }
  for (const id of v.retire) {
    if (seen.has(hexKey(id))) throw new Refusal('list', 'a secret changed twice in one transition')
    seen.add(hexKey(id))
  }
  if ((v.seq === 0) !== zero32(v.prev)) throw new Refusal('chain')
  if (v.seq === 0 && (v.update.length !== 0 || v.retire.length !== 0 || v.count !== v.create.length)) throw new Refusal('count')
  if (v.stale > v.count || (v.seq === 0 && v.stale !== 0) || (v.stale !== 0 && v.create.length !== 0)) throw new Refusal('debt')
}

/** Parses a vault record in the refusal order of spec section 3.1. */
export function decodeVault(b: Uint8Array): Vault {
  const f = rec.decode(b, MaxVaultRecord, 19, MagicVault)
  const crypt = rec.text(f, 1)
  checkCrypt(crypt)
  const org = rec.bytesN(f, 2, -1)
  checkOrgKey(org)
  const vault = rec.bytesN(f, 3, 32)
  const seq = rec.uint(f, 4, 0, MaxSafe)
  const prev = rec.bytesN(f, 5, 32)
  const name = rec.text(f, 6)
  checkName(name)
  const hall = rec.text(f, 7)
  checkHall(hall)
  const group = rec.bytesN(f, 8, GroupIDLen)
  const epoch = rec.uint(f, 9, 0, MaxEpoch)
  const epochId = rec.bytesN(f, 10, 32)
  const labelSet = labels(f, 11)
  const anchor = rec.uint(f, 12, AnchorVersion, AnchorInterval)
  const create = entries(f, 13)
  const update = entries(f, 14)
  const retire = rec.list32(f, 15, MaxDelta)
  const count = rec.uint(f, 16, 0, MaxSecrets)
  const stale = rec.uint(f, 17, 0, MaxSecrets)
  const root = rec.bytesN(f, 18, 32)
  const created = rec.uint(f, 19, 1, MaxTime)
  const v: Vault = { crypt, org, vault, seq, prev, name, hall, group, epoch, epochId, labels: labelSet, anchor, create, update, retire, count, stale, root, created, extra: f.extra }
  vaultCross(v)
  return v
}

const entryValue = (e: Entry): Value => [e.id, k(e.version), e.contentId, e.commitment]

/** Writes a vault record in canonical CBOR, and holds what it wrote to the record's rules. */
export function encodeVault(v: Vault): Uint8Array {
  const m: Pair[] = [
    { key: 0n, val: MagicVault },
    { key: 1n, val: v.crypt },
    { key: 2n, val: v.org },
    { key: 3n, val: v.vault },
    { key: 4n, val: k(v.seq) },
    { key: 5n, val: v.prev },
    { key: 6n, val: v.name },
    { key: 7n, val: v.hall },
    { key: 8n, val: v.group },
    { key: 9n, val: k(v.epoch) },
    { key: 10n, val: v.epochId },
    { key: 11n, val: v.labels },
    { key: 12n, val: k(v.anchor) },
    { key: 13n, val: v.create.map(entryValue) },
    { key: 14n, val: v.update.map(entryValue) },
    { key: 15n, val: v.retire },
    { key: 16n, val: k(v.count) },
    { key: 17n, val: k(v.stale) },
    { key: 18n, val: v.root },
    { key: 19n, val: k(v.created) },
  ]
  rec.checkExtra(v.extra, 19, m.length)
  const out = rec.encode(m, v.extra, MaxVaultRecord)
  decodeVault(out)
  return out
}

const sameLabels = (a: string[], b: string[]): boolean => a.length === b.length && a.every((x, i) => x === b[i])

/** Whether next acknowledges a later epoch than pred's. */
export const rekeys = (pred: Vault, next: Vault): boolean => next.epoch > pred.epoch

/**
 * The rules a host checks for a vault token against the one it spends (spec
 * section 4.2), in their order: transition, epoch, debt, count. predTxid is
 * the txid of the predecessor's transaction, hash byte order.
 */
export function checkVaultTransition(pred: Vault, predTxid: Uint8Array, next: Vault): void {
  if (
    next.crypt !== pred.crypt ||
    !bytesEqual(next.org, pred.org) ||
    !bytesEqual(next.vault, pred.vault) ||
    next.hall !== pred.hall ||
    !bytesEqual(next.group, pred.group) ||
    !sameLabels(next.labels, pred.labels) ||
    next.anchor !== pred.anchor ||
    next.seq !== pred.seq + 1 ||
    !bytesEqual(next.prev, predTxid)
  ) {
    throw new Refusal('transition')
  }
  const sameId = bytesEqual(next.epochId, pred.epochId)
  if (next.epoch < pred.epoch || (next.epoch === pred.epoch && !sameId) || (next.epoch > pred.epoch && sameId)) throw new Refusal('epoch')
  const base = rekeys(pred, next) ? pred.count : pred.stale
  const cleared = next.update.length + next.retire.length
  if ((base === 0 && next.stale !== 0) || (base !== 0 && (cleared > base || next.stale !== base - cleared)) || (next.stale !== 0 && next.create.length !== 0)) {
    throw new Refusal('debt')
  }
  if (next.retire.length > pred.count || next.count !== pred.count + next.create.length - next.retire.length) throw new Refusal('count')
}

// ---- the secret record ----

export interface Secret {
  crypt: string
  org: Uint8Array
  vault: Uint8Array
  id: Uint8Array
  version: number
  /** The content id of the version before; zero exactly at version 1. */
  previous: Uint8Array
  label: string
  group: Uint8Array
  epoch: number
  epochId: Uint8Array
  commitment: Uint8Array
  hash: Uint8Array
  length: number
  salt: Uint8Array
  segment: number
  created: number
  self: Uint8Array
  wrap: Uint8Array
  inline?: Uint8Array
  extra: Pair[]
}

/**
 * The plaintext length a ciphertext of length bytes holds in segments of
 * segment bytes, each followed by its 16-byte tag. It refuses a length no
 * plaintext of at least one byte produces.
 */
export function plainLength(length: number, segment: number): number {
  if (segment < MinSegment || segment > MaxSegment) throw new Refusal('range', 'segment')
  const step = segment + TagLen
  const full = Math.floor(length / step)
  const rem = length % step
  if (length === 0 || (rem !== 0 && rem <= TagLen)) throw new Refusal('range', 'length')
  return full * segment + (rem === 0 ? 0 : rem - TagLen)
}

/** The ciphertext length of n plaintext bytes in segments of segment bytes. */
export const cipherLength = (n: number, segment: number): number => n + Math.ceil(n / segment) * TagLen

/** Refusal step 7 for a secret record: the chain rule, then the length and the inline ciphertext. */
function secretCross(s: Secret): void {
  if ((s.version === 1) !== zero32(s.previous)) throw new Refusal('chain')
  if (plainLength(s.length, s.segment) > MaxPayload) throw new Refusal('range', 'a payload above the bound')
  if (s.inline === undefined) {
    if (s.length > MaxLength) throw new Refusal('range', 'length')
    return
  }
  if (s.inline.length === 0 || s.length > MaxInline) throw new Refusal('range', 'inline length')
  if (s.inline.length !== s.length || !bytesEqual(sha256(s.inline), s.hash)) throw new Refusal('content')
}

/** Parses a secret record in the refusal order of spec section 3.1. */
export function decodeSecret(b: Uint8Array): Secret {
  const f = rec.decode(b, MaxSecretRecord, 19, MagicSecret)
  const crypt = rec.text(f, 1)
  checkCrypt(crypt)
  const org = rec.bytesN(f, 2, -1)
  checkOrgKey(org)
  const vault = rec.bytesN(f, 3, 32)
  const id = rec.bytesN(f, 4, 32)
  const version = rec.uint(f, 5, 1, MaxSafe)
  const previous = rec.bytesN(f, 6, 32)
  const label = rec.text(f, 7)
  checkLabel(label)
  const group = rec.bytesN(f, 8, GroupIDLen)
  const epoch = rec.uint(f, 9, 0, MaxEpoch)
  const epochId = rec.bytesN(f, 10, 32)
  const commitment = rec.bytesN(f, 11, 32)
  const hash = rec.bytesN(f, 12, 32)
  const length = rec.uint(f, 13, 1, MaxLength)
  const salt = rec.bytesN(f, 14, SaltLen)
  const segment = rec.uint(f, 15, MinSegment, MaxSegment)
  const created = rec.uint(f, 16, 1, MaxTime)
  const self = rec.bytesN(f, 17, WrapLen)
  const wrap = rec.bytesN(f, 18, WrapLen)
  const s: Secret = { crypt, org, vault, id, version, previous, label, group, epoch, epochId, commitment, hash, length, salt, segment, created, self, wrap, extra: f.extra }
  const inline = f.known.get(19)
  if (inline !== undefined) {
    if (!(inline instanceof Uint8Array)) throw new Refusal('type', 'key 19')
    if (inline.length < 1 || inline.length > MaxInline) throw new Refusal('range', 'key 19')
    s.inline = inline
  }
  secretCross(s)
  return s
}

/** The record's pairs without the wraps and the inline ciphertext: what the content id hashes. */
function described(s: Secret): Pair[] {
  return [
    { key: 0n, val: MagicSecret },
    { key: 1n, val: s.crypt },
    { key: 2n, val: s.org },
    { key: 3n, val: s.vault },
    { key: 4n, val: s.id },
    { key: 5n, val: k(s.version) },
    { key: 6n, val: s.previous },
    { key: 7n, val: s.label },
    { key: 8n, val: s.group },
    { key: 9n, val: k(s.epoch) },
    { key: 10n, val: s.epochId },
    { key: 11n, val: s.commitment },
    { key: 12n, val: s.hash },
    { key: 13n, val: k(s.length) },
    { key: 14n, val: s.salt },
    { key: 15n, val: k(s.segment) },
    { key: 16n, val: k(s.created) },
  ]
}

/**
 * A version's content id (spec section 5.1): SHA-256 of the record's
 * canonical encoding with keys 17, 18 and 19 left out and every other key
 * kept, unknown keys included.
 */
export function contentID(s: Secret): Uint8Array {
  rec.checkExtra(s.extra, 19, 20)
  return sha256(encode(new CborMap([...described(s), ...s.extra])))
}

/** Writes a secret record in canonical CBOR, and holds what it wrote to the record's rules. */
export function encodeSecret(s: Secret): Uint8Array {
  const m = described(s)
  m.push({ key: 17n, val: s.self }, { key: 18n, val: s.wrap })
  if (s.inline !== undefined) m.push({ key: 19n, val: s.inline })
  rec.checkExtra(s.extra, 19, 20)
  const out = rec.encode(m, s.extra, MaxSecretRecord)
  decodeSecret(out)
  return out
}

/** Ascending byte order, for a writer's lists. */
export const byBytes = compareBytes
