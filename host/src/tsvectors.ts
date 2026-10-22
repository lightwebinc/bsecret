/**
 * The vectors the TypeScript codec writes, for the Go codec to read: the
 * other direction of the cross-language check. Every input is fixed, so a
 * run writes the same bytes every time; tsvectors.test.ts regenerates the
 * file and compares it byte for byte, and the Go tests decode, open, fold
 * and admit each value.
 *
 *   node dist/tsvectors.js          # write testdata/ts/ts-v1.json
 *   node dist/tsvectors.js -check   # compare, write nothing
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { CompletedProtoWallet, Hash, KeyDeriver, LockingScript, MerklePath, P2PKH, PrivateKey, PushDrop, Transaction, UnlockingScript } from '@bsv/sdk'
import { CborMap, LockTime, compareBytes, readerLockingKey } from '@lightwebinc/bcommon'
import { tokenBEEF } from './admit.js'
import { commitmentOf, encodePadded, epochWrapKey, seal, selfKeyID, symmetricKey, symmetricSeal, checkScalar } from './keyed.js'
import { encodeContext, proveSecret, setRoot, type Current } from './merkle.js'
import {
  DefaultLabels,
  KeyChain,
  KeySecret,
  KeyVault,
  Protocol,
  SelfProtocol,
  TagVault,
  contentID,
  encodeSecret,
  encodeVault,
  newCrypt,
  secretID,
  vaultID,
  type Entry,
  type Secret,
  type Vault,
} from './secrec.js'
import { fundingScript, pushDropScript } from './script.js'
import { concat, fromHex, sha256, toHex, utf8 } from './util.js'

export const file = new URL('../../testdata/ts/ts-v1.json', import.meta.url)

const sha = (s: string): Uint8Array => sha256(utf8(s))

/** The organization's test key of the Go vectors: 32 bytes of 0x51. */
const orgKey = PrivateKey.fromHex('51'.repeat(32))
const org = Uint8Array.from(orgKey.toPublicKey().encode(true) as number[])
const orgWallet = new CompletedProtoWallet(orgKey)

const Crypt = 'example_crypt_hmqzvtkwrx'
const Hall = 'example_hall_vkqzmtrwxp'
const t0 = 1798761600
const group = sha('bsecret/ts-vector/group').subarray(0, 16)

/** Two epochs of a group, their keys fixed stand-ins. */
const epochs = [0, 1].map((e) => {
  const key = sha(`bsecret/ts-vector/epoch/${e}`)
  checkScalar(key)
  return { epoch: e, key, symmetric: symmetricKey(key), id: sha(`bsecret/ts-vector/epoch-id/${e}`) }
})

const key = (id: string): Uint8Array => Uint8Array.from(readerLockingKey(Protocol, id, toHex(org)).encode(true) as number[])

async function fieldSig(id: string, data: Uint8Array): Promise<Uint8Array> {
  const r = await orgWallet.createSignature({ data: Array.from(data), protocolID: Protocol, keyID: id, counterparty: 'anyone' })
  return Uint8Array.from(r.signature)
}

const ls = (b: Uint8Array): LockingScript => LockingScript.fromBinary(Array.from(b))
const hashOf = (tx: Transaction): Uint8Array => Uint8Array.from(tx.hash() as number[])

/** A transaction from nowhere: one unsigned input of a fixed outpoint. */
function fromNowhere(tag: string, outs: Array<{ satoshis: number; lockingScript: LockingScript }>): Transaction {
  return new Transaction(1, [{ sourceTXID: toHex(sha(`bsecret/ts-vector/nowhere/${tag}`)), sourceOutputIndex: 0, unlockingScript: new UnlockingScript(), sequence: 0xffffffff }], outs, 0)
}

const headers: Array<{ height: number; merkleRoot: string }> = []

/** A block of two at height: the transaction at offset 1 beside a fixed sibling. */
function mine(tx: Transaction, height: number): void {
  tx.merklePath = new MerklePath(height, [
    [
      { offset: 0, hash: '55'.repeat(32) },
      { offset: 1, hash: tx.id('hex'), txid: true },
    ],
  ])
  headers.push({ height, merkleRoot: tx.merklePath.computeRoot(tx.id('hex')) })
}

/** a and b in one block of four, at offsets 1 and 2, each with its own minimal path. */
function mineTogether(a: Transaction, b: Transaction, height: number): void {
  const s0 = '66'.repeat(32)
  const s3 = '77'.repeat(32)
  const pair = (l: string, r: string): string => toHex(Uint8Array.from(Hash.hash256(Array.from(concat([fromHex(l).reverse(), fromHex(r).reverse()])))).reverse())
  a.merklePath = new MerklePath(height, [
    [
      { offset: 0, hash: s0 },
      { offset: 1, hash: a.id('hex'), txid: true },
    ],
    [{ offset: 1, hash: pair(b.id('hex'), s3) }],
  ])
  b.merklePath = new MerklePath(height, [
    [
      { offset: 2, hash: b.id('hex'), txid: true },
      { offset: 3, hash: s3 },
    ],
    [{ offset: 0, hash: pair(s0, a.id('hex')) }],
  ])
  headers.push({ height, merkleRoot: a.merklePath.computeRoot(a.id('hex')) })
}

interface Version {
  name: string
  value: string
  key: Uint8Array
  secret: Secret
  record: Uint8Array
  cid: Uint8Array
}

/** One version of one secret, sealed and wrapped entirely by this codec, its random values fixed. */
function version(vault: Uint8Array, name: string, n: number, epoch: number, label: string, value: string, previous: Version | undefined, extra: Secret['extra']): Version {
  const k = sha(`bsecret/ts-vector/key/${name}/${n}`)
  checkScalar(k)
  const salt = sha(`bsecret/ts-vector/salt/${name}/${n}`).subarray(0, 4)
  const segment = 64
  const cipher = seal(k, salt, segment, encodePadded({ name, value: utf8(value), type: 'text/plain', extra: [] }, 256))
  const e = epochs[epoch]!
  const secret: Secret = {
    crypt: Crypt,
    org,
    vault,
    id: secretID(vault, name),
    version: n,
    previous: previous?.cid ?? new Uint8Array(32),
    label,
    group,
    epoch,
    epochId: e.id,
    commitment: commitmentOf(k),
    hash: sha256(cipher),
    length: cipher.length,
    salt,
    segment,
    created: t0 + 60 * n,
    self: new Uint8Array(80),
    wrap: new Uint8Array(80),
    inline: cipher,
    extra,
  }
  const cid = contentID(secret)
  // The self wrap: the symmetric key the owner's wallet derives under
  // [2, "bsecret self"], the content id's base64 and counterparty self.
  const selfKey = new KeyDeriver(orgKey).deriveSymmetricKey(SelfProtocol, selfKeyID(cid), 'self')
  secret.self = symmetricSeal(Uint8Array.from(selfKey.toArray('be', 32)), sha(`bsecret/ts-vector/iv/self/${name}/${n}`), k)
  secret.wrap = symmetricSeal(epochWrapKey(e.symmetric, cid), sha(`bsecret/ts-vector/iv/epoch/${name}/${n}`), k)
  return { name, value, key: k, secret, record: encodeSecret(secret), cid }
}

const entry = (v: Version): Entry => ({ id: v.secret.id, version: v.secret.version, contentId: v.cid, commitment: v.secret.commitment })
const byId = (a: Entry[]): Entry[] => [...a].sort((x, y) => compareBytes(x.id, y.id))

export async function generate(): Promise<string> {
  headers.length = 0
  // A crypt drawn from fixed bytes: 234 and above are skipped.
  const random = Uint8Array.from([0xff, 0x00, 0xea, 0x19, 0xfe, 0x1a, 0xeb, 0x33, 0xf0, 0x4e, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
  let at = 0
  const drawn = newCrypt('ts_written', (n) => random.subarray(at, (at += n)))

  const pd = new PushDrop(orgWallet)
  const changeKey = PrivateKey.fromHex(toHex(sha('bsecret/ts-vector/change')))
  const change = new P2PKH().lock(changeKey.toAddress())

  // The trees, mined: one pays for first tokens, one funds secrets.
  const tree = (tag: string, id: string, n: number, height: number): Transaction => {
    const t = fromNowhere(
      tag,
      Array.from({ length: n }, () => ({ satoshis: 1000, lockingScript: ls(fundingScript(key(id))) })),
    )
    mine(t, height)
    return t
  }
  const chainTree = tree('chains', KeyChain, 4, 700)
  const secretTree = tree('secrets', KeySecret, 6, 701)
  const coin = fromNowhere('coin', [{ satoshis: 20000, lockingScript: change }])
  mine(coin, 702)

  // The vault's identifier is the hash of the outpoint its first token spends.
  const vault = vaultID(hashOf(chainTree), 0)
  const a1 = version(vault, 'ts/api-token', 1, 0, 'internal', 'tok_ts_0001', undefined, [])
  const b1 = version(vault, 'ts/db-password', 1, 0, 'confidential', 'mot de passe écrit en TypeScript', undefined, [{ key: 33n, val: 'kept' }])
  const a2 = version(vault, 'ts/api-token', 2, 0, 'internal', 'tok_ts_0002', a1, [])
  const b2 = version(vault, 'ts/db-password', 2, 1, 'confidential', 'a new password after the removal', b1, [])

  // A carrier signed through the SDK's PushDrop unlocker.
  const carrier = async (v: Version, vout: number): Promise<Transaction> => {
    const lock = pushDropScript(key(KeySecret), [v.record], await fieldSig(KeySecret, v.record))
    const tx = new Transaction(
      1,
      [{ sourceTransaction: secretTree, sourceOutputIndex: vout, unlockingScriptTemplate: pd.unlock(Protocol, KeySecret, 'anyone', 'all', false), sequence: 0 }],
      [{ satoshis: 1000, lockingScript: ls(lock) }],
      LockTime,
    )
    await tx.sign()
    return tx
  }
  const carriers = [await carrier(a1, 0), await carrier(b1, 1), await carrier(a2, 2), await carrier(b2, 3)]

  const token = async (rec: Uint8Array, inputs: Array<{ src: Transaction; vout: number; id: string }>, changeSats: number): Promise<Transaction> => {
    const lock = pushDropScript(key(KeyVault), [TagVault, rec], await fieldSig(KeyVault, concat([TagVault, rec])))
    const tx = new Transaction(
      1,
      inputs.map((i) => ({
        sourceTransaction: i.src,
        sourceOutputIndex: i.vout,
        unlockingScriptTemplate: i.id === 'fee' ? new P2PKH().unlock(changeKey) : pd.unlock(Protocol, i.id, 'anyone', 'all', false),
        sequence: 0xffffffff,
      })),
      [
        { satoshis: 1, lockingScript: ls(lock) },
        { satoshis: changeSats, lockingScript: change },
      ],
      0,
    )
    await tx.sign()
    return tx
  }
  const current = (v: Version, epoch: number, seq: number): Current => ({ id: v.secret.id, version: v.secret.version, contentId: v.cid, epoch, seq })
  const base = { crypt: Crypt, org, vault, name: 'Coffre écrit en TypeScript', hall: Hall, group, labels: DefaultLabels, anchor: 0 }

  // seq 0 creates two secrets under epoch 0.
  const v0: Vault = {
    ...base,
    seq: 0,
    prev: new Uint8Array(32),
    epoch: 0,
    epochId: epochs[0]!.id,
    create: byId([entry(a1), entry(b1)]),
    update: [],
    retire: [],
    count: 2,
    stale: 0,
    root: setRoot([current(a1, 0, 0), current(b1, 0, 0)]),
    created: t0,
    extra: [],
  }
  const r0 = encodeVault(v0)
  const token0 = await token(r0, [{ src: chainTree, vout: 0, id: KeyChain }], 1000 - 1 - 300)
  // seq 1 updates one, and carries a key this version does not define. It is
  // mined in the same block as seq 0, so its BEEF holds one merged path.
  const v1: Vault = {
    ...v0,
    seq: 1,
    prev: hashOf(token0),
    create: [],
    update: [entry(a2)],
    root: setRoot([current(a2, 0, 1), current(b1, 0, 0)]),
    created: t0 + 3600,
    extra: [{ key: 40n, val: new CborMap([{ key: 'later', val: true }]) }],
  }
  const r1 = encodeVault(v1)
  const token1 = await token(
    r1,
    [
      { src: token0, vout: 0, id: KeyVault },
      { src: coin, vout: 0, id: 'fee' },
    ],
    20000 + 1 - 1 - 400,
  )
  mineTogether(token0, token1, 703)
  // seq 2 acknowledges epoch 1 and re-keys one of two secrets: one is stale.
  // It spends its predecessor's token and its change, both outputs of its
  // parent.
  const set2 = [current(a2, 0, 1), current(b2, 1, 2)]
  const v2: Vault = {
    ...v0,
    seq: 2,
    prev: hashOf(token1),
    epoch: 1,
    epochId: epochs[1]!.id,
    create: [],
    update: [entry(b2)],
    stale: 1,
    root: setRoot(set2),
    created: t0 + 7200,
    extra: [],
  }
  const r2 = encodeVault(v2)
  const token2 = await token(
    r2,
    [
      { src: token1, vout: 0, id: KeyVault },
      { src: token1, vout: 1, id: 'fee' },
    ],
    20000 - 400 + 1 - 1 - 400,
  )
  mine(token2, 704)

  // A sweep of the first db-password version's funding outpoint and an
  // unused one: its output 0 is a funding-shaped tombstone.
  const sweep = new Transaction(
    1,
    [1, 5].map((vout) => ({ sourceTransaction: secretTree, sourceOutputIndex: vout, unlockingScriptTemplate: pd.unlock(Protocol, KeySecret, 'anyone', 'all', false), sequence: 0xffffffff })),
    [{ satoshis: 1700, lockingScript: ls(fundingScript(key(KeySecret))) }],
    0,
  )
  await sweep.sign()
  mine(sweep, 705)

  const hx = (b: Uint8Array): string => toHex(b)
  const beef = (tx: Transaction): string => hx(Uint8Array.from(tx.toAtomicBEEF()))
  const secret = (v: Version): Record<string, unknown> => ({
    name: v.name,
    version: v.secret.version,
    epoch: v.secret.epoch,
    value: v.value,
    key: hx(v.key),
    contentId: hx(v.cid),
    record: hx(v.record),
  })
  const out = {
    description:
      'Written by the TypeScript codec (host/src/tsvectors.ts) and read by the Go codec: the crypt draw reproduces from the same random bytes; each record decodes and re-encodes to the same bytes, unknown keys kept, and gives the same content id; ' +
      'each secret (sealed in segments and wrapped twice by the TypeScript side, the self wrap under the key the SDK derives for the owner) opens through the owner wallet and under the key of the epoch it names, hash checked first, and under no other epoch; ' +
      'the vault chain folds consistently and the context takes its record to the last token root; every transaction (carriers and tokens signed through the SDK PushDrop unlocker; tokens 0 and 1 mined in one block, so the BEEF of token 1 holds one path the SDK merged; token 2 spending two outputs of its parent; a sweep) is admitted against the headers below, and each token BEEF is the one the Go TokenBEEF writes.',
    crypt: Crypt,
    cryptDraw: { name: 'ts_written', random: hx(random), crypt: drawn },
    vault: hx(vault),
    epochs: epochs.map((e) => ({ epoch: e.epoch, key: hx(e.key), symmetricKey: hx(e.symmetric), epochId: hx(e.id) })),
    vaults: [hx(r0), hx(r1), hx(r2)],
    secrets: [a1, b1, a2, b2].map(secret),
    context: {
      secret: 'ts/db-password',
      version: 2,
      hex: hx(encodeContext(proveSecret(2, hashOf(token2), set2, b2.secret.id))),
    },
    headers,
    transactions: [
      ...carriers.map((c, i) => ({ name: `carrier-${i}`, txid: c.id('hex'), beef: beef(c), kind: 'secret' })),
      { name: 'vault-0', txid: token0.id('hex'), beef: hx(tokenBEEF(token0, chainTree)), kind: 'vault-token' },
      { name: 'vault-1-same-block', txid: token1.id('hex'), beef: hx(tokenBEEF(token1, token0)), kind: 'vault-token' },
      { name: 'vault-2', txid: token2.id('hex'), beef: hx(tokenBEEF(token2, token1)), kind: 'vault-token' },
      { name: 'sweep', txid: sweep.id('hex'), beef: beef(sweep), kind: 'sweep' },
    ],
  }
  return JSON.stringify(out, null, 2) + '\n'
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const out = await generate()
  if (process.argv.includes('-check')) {
    let have = ''
    try {
      have = readFileSync(file, 'utf8')
    } catch {}
    if (have !== out) {
      console.error(`differs: ${fileURLToPath(file)}`)
      process.exit(1)
    }
  } else {
    writeFileSync(file, out)
  }
}
