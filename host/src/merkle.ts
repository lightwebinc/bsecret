/**
 * The RFC 6962 root a vault record commits its current set to (bcommon
 * commit), and the inclusion context of a secret answer: the twins of the Go
 * fold.go's SetRoot and context.go.
 */
import { CborError, bytesEqual, compareBytes, decodeValue, encode, type Value } from '@lightwebinc/bcommon'
import { MaxSafe, MaxSecrets, Refusal, leaf } from './secrec.js'
import { concat, sha256 } from './util.js'

const leafHash = (d: Uint8Array): Uint8Array => sha256(concat([Uint8Array.of(0), d]))
const nodeHash = (l: Uint8Array, r: Uint8Array): Uint8Array => sha256(concat([Uint8Array.of(1), l, r]))

function split(n: number): number {
  let k = 1
  while (k * 2 < n) k *= 2
  return k
}

function subtree(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 1) return leafHash(leaves[0]!)
  const k = split(leaves.length)
  return nodeHash(subtree(leaves.slice(0, k)), subtree(leaves.slice(k)))
}

/** The RFC 6962 Merkle Tree Hash; the empty tree's root is SHA-256 of nothing. */
export function root(leaves: Uint8Array[]): Uint8Array {
  return leaves.length === 0 ? sha256(new Uint8Array(0)) : subtree(leaves)
}

/** One step of an inclusion path: the sibling, and whether it sits on the left. */
export interface Step {
  hash: Uint8Array
  left: boolean
}

export function prove(leaves: Uint8Array[], index: number): Step[] {
  if (leaves.length === 1) return []
  const k = split(leaves.length)
  if (index < k) return [...prove(leaves.slice(0, k), index), { hash: subtree(leaves.slice(k)), left: false }]
  return [...prove(leaves.slice(k), index - k), { hash: subtree(leaves.slice(0, k)), left: true }]
}

export function verify(leafDatum: Uint8Array, path: Step[], want: Uint8Array): boolean {
  let cur = leafHash(leafDatum)
  for (const s of path) cur = s.left ? nodeHash(s.hash, cur) : nodeHash(cur, s.hash)
  return bytesEqual(cur, want)
}

/** One secret of a vault's current set. */
export interface Current {
  id: Uint8Array
  version: number
  contentId: Uint8Array
  /** The epoch and seq of the token that listed this version. */
  epoch: number
  seq: number
}

const sortSet = (set: Current[]): Current[] => [...set].sort((a, b) => compareBytes(a.id, b.id))

/** The set root: one leaf per secret, ascending by identifier. */
export const setRoot = (set: Current[]): Uint8Array => root(sortSet(set).map((c) => leaf(c.id, c.version, c.contentId)))

export const MaxPathSteps = 32
export const MaxContext = 2048

/** A secret answer's BRC-24 context: [seq, token, index, size, [[bytes(32), bool], ...]]. */
export interface InclusionContext {
  seq: number
  /** The txid of the vault token whose set was used, hash byte order. */
  token: Uint8Array
  index: number
  size: number
  path: Step[]
}

export function encodeContext(c: InclusionContext): Uint8Array {
  if (c.path.length > MaxPathSteps || c.size === 0 || c.size > MaxSecrets || c.index >= c.size) throw new Refusal('range')
  return encode([BigInt(c.seq), c.token, BigInt(c.index), BigInt(c.size), c.path.map((s) => [s.hash, s.left] as Value[])])
}

export function decodeContext(b: Uint8Array): InclusionContext {
  if (b.length > MaxContext) throw new Refusal('too-large')
  let v: Value
  try {
    v = decodeValue(b)
  } catch (e) {
    if (e instanceof CborError) throw new Refusal('cbor', e.message)
    throw e
  }
  if (!Array.isArray(v) || v.length !== 5) throw new Refusal('type')
  const [seq, token, index, size, steps] = v
  if (typeof seq !== 'bigint' || typeof index !== 'bigint' || typeof size !== 'bigint' || seq < 0n || index < 0n || size < 0n || !Array.isArray(steps)) {
    throw new Refusal('type')
  }
  if (!(token instanceof Uint8Array) || token.length !== 32) throw new Refusal('type')
  if (seq > BigInt(MaxSafe)) throw new Refusal('range')
  if (size === 0n || size > BigInt(MaxSecrets) || index >= size || steps.length > MaxPathSteps) throw new Refusal('range')
  const path = steps.map((s) => {
    if (!Array.isArray(s) || s.length !== 2) throw new Refusal('type')
    const [h, left] = s
    if (!(h instanceof Uint8Array) || typeof left !== 'boolean' || h.length !== 32) throw new Refusal('type')
    return { hash: h, left }
  })
  return { seq: Number(seq), token, index: Number(index), size: Number(size), path }
}

/** The context for the secret id within the current set of the token at seq whose txid is token. */
export function proveSecret(seq: number, token: Uint8Array, set: Current[], id: Uint8Array): InclusionContext {
  const s = sortSet(set)
  const i = s.findIndex((c) => bytesEqual(c.id, id))
  if (i < 0) throw new Refusal('range', 'not in the set')
  return { seq, token, index: i, size: s.length, path: prove(s.map((c) => leaf(c.id, c.version, c.contentId)), i) }
}

/** Whether a context takes the leaf of (id, version, content id) to the root. */
export const verifySecret = (c: InclusionContext, id: Uint8Array, version: number, contentID: Uint8Array, rootValue: Uint8Array): boolean =>
  verify(leaf(id, version, contentID), c.path, rootValue)
