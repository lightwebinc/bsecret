/**
 * The classifier and the canonical scripts, the twin of the Go
 * internal/secrec/script.go and txscript.go. The script reader is bcommon's,
 * so that both codecs read every byte string the same way; every script a
 * host checks is compared byte for byte with the one rebuilt here.
 */
import { bytesEqual, claimsRecord, firstPush, pushDropScript } from '@lightwebinc/bcommon'
import { MagicSecret, TagFunding, TagVault } from './secrec.js'

export { firstPush, minimalPushBytes, pushDropScript, pushFields } from '@lightwebinc/bcommon'

const OP_DROP = 0x75

/** What a locking script claims to be (spec section 11.1, Classify). */
export type Kind = 'none' | 'secret' | 'vault-token' | 'funding'

/** What a locking script claims, reading nothing else of it. */
export function classify(s: Uint8Array): Kind {
  const p = firstPush(s)
  if (p === undefined) return 'none'
  if (claimsRecord(p, MagicSecret)) return 'secret'
  if (bytesEqual(p, TagVault)) return 'vault-token'
  if (bytesEqual(p, TagFunding) && s.length === 35 + 4 + 1 && s[39] === OP_DROP) return 'funding'
  return 'none'
}

/** A funding-shaped script under any key. */
export const isFundingShape = (s: Uint8Array): boolean => classify(s) === 'funding'

/** A funding output locked to key: <key> OP_CHECKSIG <73 65 02> OP_DROP. */
export const fundingScript = (key: Uint8Array): Uint8Array => pushDropScript(key, [TagFunding])
