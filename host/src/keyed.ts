/**
 * A reader's side of a secret: BRC-369's content key and its segments, both
 * wraps, the ordered checks of spec section 7.2 and the payload, the twin of
 * the Go keyed.go, wrap.go and the reads of secret.go. A host never calls
 * any of it: it holds no key and decrypts nothing. It is here so that the
 * two codecs open what the other wrote, and it is not part of the package's
 * entry point. It uses node:crypto.
 */
import { createCipheriv, createDecipheriv } from 'node:crypto'
import { BigNumber, Curve, type WalletInterface } from '@bsv/sdk'
import { bytesEqual, type Pair } from '@lightwebinc/bcommon'
import {
  DomainCommitment,
  DomainEpochWrap,
  DomainSymmetric,
  MagicPayload,
  MaxEpoch,
  MaxPayload,
  MaxTime,
  MaxType,
  Refusal,
  SelfProtocol,
  TagLen,
  WrapLen,
  checkSecretName,
  contentID,
  plainLength,
  records,
  secretID,
  type Secret,
} from './secrec.js'
import { bigEndian, concat, sha256, toBase64, toHex, utf8 } from './util.js'

/** The one wallet method a read needs: BRC-100's decrypt. */
export type Decrypter = Pick<WalletInterface, 'decrypt'>

/** BRC-369 section 2.1 rule 3: the symmetric key of a scalar. */
export const symmetricKey = (k: Uint8Array): Uint8Array => sha256(concat([utf8(DomainSymmetric), k]))

/** BRC-369 section 2.2's digest form. */
export const commitmentOf = (k: Uint8Array): Uint8Array => sha256(concat([utf8(DomainCommitment), k]))

const order = new Curve().n

/** A 32-byte big-endian value in [1, n-1], or the refusal undecryptable. */
export function checkScalar(k: Uint8Array): void {
  const v = new BigNumber(toHex(k), 16)
  if (k.length !== 32 || v.isZero() || v.cmp(order) >= 0) throw new Refusal('undecryptable', 'not a scalar in [1, n-1]')
}

/** The key a content key is wrapped under for one epoch (spec section 6.3). */
export const epochWrapKey = (epochSymmetric: Uint8Array, cid: Uint8Array): Uint8Array => sha256(concat([utf8(DomainEpochWrap), epochSymmetric, cid]))

/** The self wrap's BRC-43 key id: the standard padded base64 of the content id. */
export const selfKeyID = (cid: Uint8Array): string => toBase64(cid)

/** BRC-2's symmetric form: AES-256-GCM under a 32-byte IV, written IV, ciphertext, tag. */
export function symmetricSeal(key: Uint8Array, iv: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const c = createCipheriv('aes-256-gcm', key, iv)
  return concat([iv, c.update(plaintext), c.final(), c.getAuthTag()])
}

export function symmetricOpen(key: Uint8Array, sealed: Uint8Array): Uint8Array {
  if (sealed.length < 32 + TagLen) throw new Refusal('undecryptable', 'too short')
  const d = createDecipheriv('aes-256-gcm', key, sealed.subarray(0, 32))
  d.setAuthTag(sealed.subarray(sealed.length - TagLen))
  try {
    return concat([d.update(sealed.subarray(32, sealed.length - TagLen)), d.final()])
  } catch {
    throw new Refusal('undecryptable')
  }
}

/** The check on a key just unwrapped: 32 bytes, a scalar, the committed one, in that order. */
function checkOpened(k: Uint8Array, commitment: Uint8Array): Uint8Array {
  if (k.length !== 32) throw new Refusal('undecryptable', 'not 32 bytes')
  checkScalar(k)
  if (!bytesEqual(commitmentOf(k), commitment)) throw new Refusal('commitment')
  return k
}

/** A member's checks 2a and 2b: the wrap opened with the named epoch's key and no other. */
export function unwrapFromEpoch(epochSymmetric: Uint8Array, cid: Uint8Array, wrap: Uint8Array, commitment: Uint8Array): Uint8Array {
  if (wrap.length !== WrapLen) throw new Refusal('undecryptable', `length ${wrap.length}`)
  return checkOpened(symmetricOpen(epochWrapKey(epochSymmetric, cid), wrap), commitment)
}

/** The owner's side: its wallet decrypts the self wrap. */
export async function unwrapFromSelf(wallet: Decrypter, cid: Uint8Array, wrap: Uint8Array, commitment: Uint8Array): Promise<Uint8Array> {
  if (wrap.length !== WrapLen) throw new Refusal('undecryptable', `length ${wrap.length}`)
  let plain: number[]
  try {
    plain = (await wallet.decrypt({ protocolID: SelfProtocol, keyID: selfKeyID(cid), counterparty: 'self', ciphertext: Array.from(wrap) })).plaintext
  } catch {
    throw new Refusal('undecryptable')
  }
  return checkOpened(Uint8Array.from(plain), commitment)
}

const segmentIV = (salt: Uint8Array, i: number): Uint8Array => concat([salt, bigEndian(i, 8)])

/** BRC-369 section 2.3: segments of segment plaintext bytes, each followed by its own tag. */
export function seal(k: Uint8Array, salt: Uint8Array, segment: number, plaintext: Uint8Array): Uint8Array {
  const key = symmetricKey(k)
  const parts: Uint8Array[] = []
  for (let i = 0, off = 0; off < plaintext.length; i++, off += segment) {
    const c = createCipheriv('aes-256-gcm', key, segmentIV(salt, i))
    parts.push(c.update(plaintext.subarray(off, off + segment)), c.final(), c.getAuthTag())
  }
  return concat(parts)
}

/** Decrypts what seal wrote, verifying every segment's tag; a tag that fails is the refusal tag. */
export function openSegments(k: Uint8Array, salt: Uint8Array, segment: number, ciphertext: Uint8Array): Uint8Array {
  plainLength(ciphertext.length, segment)
  const key = symmetricKey(k)
  const step = segment + TagLen
  const parts: Uint8Array[] = []
  for (let i = 0, off = 0; off < ciphertext.length; i++, off += step) {
    const seg = ciphertext.subarray(off, off + step)
    const d = createDecipheriv('aes-256-gcm', key, segmentIV(salt, i))
    d.setAuthTag(seg.subarray(seg.length - TagLen))
    try {
      parts.push(d.update(seg.subarray(0, seg.length - TagLen)), d.final())
    } catch {
      throw new Refusal('tag', `segment ${i}`)
    }
  }
  return concat(parts)
}

/** The plaintext a secret's ciphertext holds. */
export interface Payload {
  name: string
  value: Uint8Array
  type?: string
  notAfter?: number
  rotateEvery?: number
  pad?: Uint8Array
  extra: Pair[]
}

export function decodePayload(b: Uint8Array): Payload {
  const f = records.decode(b, MaxPayload, 6, MagicPayload)
  const name = records.text(f, 1)
  checkSecretName(name)
  const p: Payload = { name, value: records.bytesN(f, 2, -1), extra: f.extra }
  if (f.known.has(3)) {
    p.type = records.text(f, 3)
    const n = utf8(p.type).length
    if (n < 1 || n > MaxType) throw new Refusal('range', 'key 3')
  }
  if (f.known.has(4)) p.notAfter = records.uint(f, 4, 1, MaxTime)
  if (f.known.has(5)) p.rotateEvery = records.uint(f, 5, 1, MaxEpoch)
  if (f.known.has(6)) {
    p.pad = records.bytesN(f, 6, -1)
    if (p.pad.length === 0) throw new Refusal('range', 'key 6')
  }
  return p
}

export function encodePayload(p: Payload): Uint8Array {
  const m: Pair[] = [
    { key: 0n, val: MagicPayload },
    { key: 1n, val: p.name },
    { key: 2n, val: p.value },
  ]
  if (p.type !== undefined) m.push({ key: 3n, val: p.type })
  if (p.notAfter !== undefined) m.push({ key: 4n, val: BigInt(p.notAfter) })
  if (p.rotateEvery !== undefined) m.push({ key: 5n, val: BigInt(p.rotateEvery) })
  if (p.pad !== undefined) m.push({ key: 6n, val: p.pad })
  records.checkExtra(p.extra, 6, 7)
  const out = records.encode(m, p.extra, MaxPayload)
  decodePayload(out)
  return out
}

/** The payload padded with zero bytes to a multiple of block bytes. */
export function encodePadded(p: Payload, block: number): Uint8Array {
  let out = encodePayload({ ...p, pad: undefined })
  for (let pad = 1; out.length % block !== 0 && pad <= 2 * block; pad++) out = encodePayload({ ...p, pad: new Uint8Array(pad) })
  if (out.length % block !== 0) throw new Refusal('range', `no padding reaches a multiple of ${block}`)
  return out
}

/** A reader's check 1: the ciphertext is the record's length and hashes to its hash. */
export function checkCiphertext(s: Secret, ciphertext: Uint8Array): void {
  if (ciphertext.length !== s.length || !bytesEqual(sha256(ciphertext), s.hash)) throw new Refusal('hash')
}

/** Checks 3 and 4 with a key already held to the commitment: every tag, then the payload and its name. */
function openWith(s: Secret, ciphertext: Uint8Array, k: Uint8Array): Payload {
  const plain = openSegments(k, s.salt, s.segment, ciphertext)
  let p: Payload
  try {
    p = decodePayload(plain)
  } catch (e) {
    throw new Refusal('payload', (e as Error).message)
  }
  if (!bytesEqual(secretID(s.vault, p.name), s.id)) throw new Refusal('payload', "the name does not hash to the record's id")
  return p
}

/**
 * A member's read of one version in the order of spec section 7.2: the
 * ciphertext's length and hash before any wrap is opened; the wrap under the
 * symmetric key of the epoch the record names; the scalar and the
 * commitment; every segment's tag; the payload and its name.
 */
export function readAsMember(s: Secret, ciphertext: Uint8Array, epochSymmetric: Uint8Array): Payload {
  checkCiphertext(s, ciphertext)
  return openWith(s, ciphertext, unwrapFromEpoch(epochSymmetric, contentID(s), s.wrap, s.commitment))
}

/** The owner's read through its self wrap, in the same order. */
export async function readAsOwner(wallet: Decrypter, s: Secret, ciphertext: Uint8Array): Promise<Payload> {
  checkCiphertext(s, ciphertext)
  return openWith(s, ciphertext, await unwrapFromSelf(wallet, contentID(s), s.self, s.commitment))
}
