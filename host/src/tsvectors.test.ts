/**
 * The TypeScript-written vectors regenerate byte for byte, and the
 * TypeScript codec admits, folds and opens everything it wrote.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { PrivateKey, ProtoWallet } from '@bsv/sdk'
import { admit, storedToken } from './admit.js'
import { VaultFold, checkInSet } from './chain.js'
import { readAsMember, readAsOwner } from './keyed.js'
import { decodeContext } from './merkle.js'
import { decodeSecret, decodeVault, reasonOf } from './secrec.js'
import { file, generate } from './tsvectors.js'
import { fromHex, hashOrder, toHex } from './util.js'

test('ts-v1.json regenerates byte for byte', async () => {
  assert.equal(await generate(), readFileSync(file, 'utf8'))
})

test('ts-v1.json: every transaction the TypeScript side built is admitted by it', async () => {
  const v = JSON.parse(readFileSync(file, 'utf8'))
  const roots = new Map<number, string>(v.headers.map((h: { height: number; merkleRoot: string }) => [h.height, h.merkleRoot]))
  const headers = { isValidRootForHeight: async (r: string, h: number) => roots.get(h) === r, currentHeight: async () => 0 }
  for (const t of v.transactions) {
    const a = await admit(fromHex(t.beef), [], { crypt: v.crypt, headers })
    assert.equal(a.kind, t.kind, t.name)
  }
})

test('ts-v1.json: the chain folds, the context holds, and every secret opens', async () => {
  const v = JSON.parse(readFileSync(file, 'utf8'))
  const fold = new VaultFold()
  const vaults = v.vaults.map((h: string) => decodeVault(fromHex(h)))
  for (const x of vaults) assert.equal(fold.apply(x), 'consistent')
  assert.equal(fold.stale(), 1)
  const owner = new ProtoWallet(PrivateKey.fromHex('51'.repeat(32)))
  for (const s of v.secrets) {
    const rec = decodeSecret(fromHex(s.record))
    const e = v.epochs[s.epoch]
    assert.equal(new TextDecoder().decode(readAsMember(rec, rec.inline!, fromHex(e.symmetricKey)).value), s.value)
    assert.equal((await readAsOwner(owner, rec, rec.inline!)).name, s.name)
    const other = v.epochs[1 - s.epoch]
    let got = 'ok'
    try {
      readAsMember(rec, rec.inline!, fromHex(other.symmetricKey))
    } catch (err) {
      got = reasonOf(err)
    }
    assert.equal(got, 'undecryptable', `${s.name} under the other epoch`)
  }
  const last = v.transactions.find((t: { name: string }) => t.name === 'vault-2')
  const rec = decodeSecret(fromHex(v.secrets[3].record))
  checkInSet(vaults[2], hashOrder(last.txid), rec, decodeContext(fromHex(v.context.hex)))
  assert.equal(toHex(vaults[2].vault), v.vault)
  assert.throws(() => storedToken(fromHex(v.transactions[0].beef)))
})
