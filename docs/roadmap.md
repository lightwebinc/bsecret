# Roadmap

What bsecret is for, what this version does, what comes next and in what
order, and what is deliberately left as it is. Versions are plain semantic
versions; nothing here carries a date.

## What bsecret is for

bsecret keeps an organization's secrets on hosts that hold ciphertext and
never a key. Readers are the members of a borg group; a removal from the
group makes the vault re-key everything it holds before anything else, and
every replica checks that; the chain is the audit trail, verified from
block headers with nobody's cooperation.

## In this version

- Vaults keyed to borg groups, with versions encrypted once under their own
  content keys (BRC-369) and wrapped to the owner and under one epoch's key.
- Revoke forces rotation: once a vault acknowledges a new epoch, every host
  refuses anything but re-keying or retirement until nothing is stale.
- Readers that check every answer against their own headers, report a vault
  that is behind or in debt and a value that is exposed, and refuse either
  under `-strict`.
- The audit: every epoch's exposure window from block headers alone, free
  or by priced pages.
- Per-version vaults for secrets people manage, and interval vaults for
  credentials machines rotate faster than blocks.
- No node needed: public header, chain view and broadcast services by
  default, every proof checked; your own node where you have one.
- The kill switch, the host module with its priced terms route, and the
  payee.

## Next

Ordered by what unblocks the most.

1. **A reader that stays running.** A daemon that holds one member home,
   keeps verified values, walks the vault's chain on an interval and serves
   them locally over HTTP: JSON with each value's standing (settled, in
   debt, exposed, anchored), and a path shaped like Vault's KV version 2.
   It is what a sidecar, a Vault Agent template and the External Secrets
   Operator's webhook provider read, so Kubernetes and most deployment
   tools take secrets from bsecret without code of their own.
2. **Private crypts.** A host setting that serves a crypt only to the
   organizations it names and their groups' members, through the
   authenticated route the priced classes already use, so that outsiders
   cannot walk a vault's chain at the hosts. What the tokens carry stays on
   the chain.
3. **Machine enrolment.** `init` already makes a key where a workload runs,
   so no private key need travel. Next is the enrolment around it: the
   workload asks to join, the owner approves the request in one step, and
   the workload picks up its membership, instead of a public key copied to
   the owner by hand.
4. **The organization's key in a wallet of its own.** Signing and wrapping
   through a BRC-100 wallet, so the key can live in a hardware module or a
   remote signer rather than a file in the home.
5. **Large secrets through bstore**, in place of a local directory and a
   `uhrp://` address.

## Later, and areas of exploration

- **A second record version for metadata.** A signing key per vault, so a
  vault's tokens do not name the organization on the chain, and token
  fields sealed under a key the crypt's members hold, so the chain shows
  that a vault moved and not what it holds. It trades the audit anyone can
  run for an audit the organization's members and invited auditors run.
- **A secret name that cannot be guessed from its identifier**, by a
  per-vault value folded into the identifier. It changes how a reader
  checks an identifier, so it waits for the same record version.
- **Hosts that keep chain trees**, so a first token a host lost is filled
  without the owner's home.
- **A native External Secrets provider** and a TypeScript reader.

## Left as it is

- **Forward secrecy.** An epoch's key reaches a member under its long-term
  identity key; rotation on a schedule and short retention are the
  controls.
- **Forcing the acknowledgement at the hosts.** A host admits a record by
  its own bytes and reads no group's chain; the owner's tooling, every
  reader and the audit stand against a vault that does not acknowledge.
- **Changing a credential where it is accepted**, and leased or dynamic
  credentials: bsecret stores and distributes values.
- **FIPS 140-only runtimes**, which refuse the IV layouts BRC-369 and
  BRC-2 use ([limits.md](limits.md)).
