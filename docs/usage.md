# The bsecret command

`bsecret` keeps an organization's secrets on overlay hosts
([spec.md](spec.md)), and reads them as a member of the group a vault is
keyed to, or audits a vault as anyone. The owner's home holds the
organization's identity key: it creates vaults on borg groups, writes each
version of a secret under a content key of its own, wrapped to the group's
current epoch, and, when the group removes a member, acknowledges the new
epoch and re-keys everything the vault held. A member's home reads a
secret with every check made in the signed order. An auditor needs no home:
it verifies a vault's trail from block headers and reports how long each
secret stayed listed under an epoch a removed member held. A reader pays a
host's 402 for the priced questions, and a host's payee settles the
payments the host recorded.

```text
  borg home (the organization)                           hosts of the hall (tm_borg_<hall>, ls_borg)
  ────────────────────────────                           ──────────────────────────────────────────
  borg org create, group create, org signer ───────────▶ the group's chain, the wraps of each epoch
  borg org remove <key> -group G  (a new epoch) ───────▶ a group token, wraps to the members who remain
        │ identity.json
        ▼
  bsecret home (the owner)                               hosts of the crypt (tm_bsecret_<crypt>, ls_bsecret)
  ────────────────────────                               ──────────────────────────────────────────────────
  init -borg DIR ─▶ fund ─▶ vault create <group> ──────▶ vault token seq 0, mined, with its chain tree
        ◀── borg's reader: the group's chain, the epoch key (the wrap to the signer key)
  put <name> ─▶ a carrier (ciphertext, both wraps) ────▶ facade (plane) or each host (unicast)
               a vault token listing it, mined ────────▶ facade and every host named
  rotate ─▶ acknowledge the new epoch, re-key or retire everything stale; sweep the old versions
  member home
  ───────────
  get <name> ◀── ls_bsecret answers of every host, compared, checked against header_url
             ◀── borg's reader: the group's chain, the wrap of the epoch the record names
  anyone
  ──────
  audit ◀── the vault's tokens (the priced audit class, paid; or vault-seq, free) and the group's
        ─▶ every token verified from headers; the exposure window of each removal
  host's payee
  ────────────
  payee settle payments.jsonl ─▶ each payment: checked, broadcast, pooled
```

[user-guide.md](user-guide.md) explains the concepts and the day-to-day
use; this page is the reference.

## Install

```console
$ go install github.com/lightwebinc/bsecret/cmd/bsecret@latest
$ make bsecret            # or from a checkout: bin/bsecret (Go 1.27.2 or later)
$ make borg               # bin/borg, the borg command at the tag go.mod pins
$ make docker-build       # ghcr.io/lightwebinc/bsecret and bsecret-devchain, locally
```

Release tarballs for Linux and macOS (amd64, arm64) are on the
[releases page](https://github.com/lightwebinc/bsecret/releases). In the
image the home is `/home/nonroot/.bsecret`; mount a named volume
there (`-v bsecret-home:/home/nonroot/.bsecret`) and pass settings as
`BSECRET_<KEY>` variables.

## bsecret and a borg home

A vault's owner is a borg organization: the key that signs every vault
token and every carrier is the organization's identity key, and the vault's
readers are the members of one of the organization's groups. bsecret does
none of borg's work and keeps none of borg's state.

- **The identity is shared, the homes are not.** `bsecret init -borg DIR`
  makes a bsecret home around the identity key of the borg home `DIR`: it
  copies `DIR/identity.json` and reads nothing else, then or later.
  (`-from FILE` takes an identity file carried by hand, for a home on
  another machine.) The two homes keep separate coin pools, state files and
  locks: bsecret's fund address is derived under its own protocol, so coin
  paid to a borg home is not bsecret's, and a bsecret command never writes
  into a borg home. A member does the same with its own borg home, and a
  key that is in no borg home uses a plain `bsecret init`.
- **The group is read from the hall's hosts.** Every command that needs the
  group (its chain, its epochs, who removed whom and when) asks the hosts
  of the group's hall through borg's own `reader` package and verifies
  every token against `header_url`, as any reader of the group does. No
  borg state file is read.
- **Epoch keys come from borg's wraps.** A member opens the key of the
  epoch a record names from the wrap borg made to it. The owner opens it
  from the wrap borg made to the organization's **signer key**, the key
  borg derives from the organization's identity key and keeps a member of
  every group once `borg org signer` has run. So run `borg org signer`
  once, in the organization's borg home, before `bsecret vault create`:
  without it the organization holds no wrap, and bsecret refuses to create
  a vault it could not write to. bsecret keeps no epoch key on disk: it
  opens the wrap each time.
- **The removal is borg's, the rotation is bsecret's.** A revoke is three
  steps: `bsecret rotate -check` (is there a choice for every secret?),
  `borg org remove <key> -group G` (the removal, a new epoch), then
  `bsecret rotate` (the acknowledgement and the re-keying). bsecret cannot
  stop a borg command; the first step is how a revoke that cannot be
  finished is not begun.

The hall's hosts are `hall_hosts`, or `hosts` when the same hosts carry
both the hall and the crypt.

## Commands

| Command | Needs a home | Needs | What it does |
| --- | --- | --- | --- |
| `init [-borg DIR \| -from FILE]` | creates it | nothing | identity key and empty coin pool; prints the identity and the fund address. `-borg` makes the home around a borg home's identity, `-from` around an identity file |
| `fund -txid TXID` | yes | `chain`, `header_url` (defaults on main and test) | imports a mined payment you sent from your own wallet to the fund address, read from the chain view, once its proof checks. How a home is funded on mainnet and testnet |
| `fund -beef FILE\|- [-refuse-unmined]` | yes | `header_url` | imports that payment from the BEEF your wallet handed over, with no lookup: a mined one once its proof checks, an unmined one (unless `-refuse-unmined` or `fund_unmined = refuse`) once its parents' proofs check and it verifies against them, held back until it mines and sent to `settle` in case the wallet did not |
| `fund [-blocks N]` | yes | `rpc`, `chain = asset:<URL>` | coinbase: only on a regtest chain you run (development and tests). Mines coinbase to the fund address through `generatetoaddress`. Refused on network `main`. `-batch N` blocks a call; `-rescan` re-reads the last `-blocks` blocks for coinbase the pool lacks and mines nothing |
| `crypt new <name>` | optional | nothing | draws the 10-letter random suffix; prints the crypt, its topic, and the host's `BSECRET_CRYPTS` line |
| `crypt list` | yes | nothing | the crypts this home created |
| `vault create <group> [-name N]` | yes, the owner's, funded | `crypt`, `hall`, a publisher's settings (below) | a vault keyed to a group of the organization (its id, or its name in the hall): a chain tree, and the vault's first token naming the group's current epoch. `-anchor version` (default) or `interval`; `-labels a,b,c`. The name is one line of plain text and public; without `-name` one is drawn at random (`vault_` and ten letters) |
| `enroll request [-label L]` | yes, a machine's own (a plain `init`) | a reader's settings | a join request for the vault's group naming this home's key, signed by it, printed as one line for the owner ([Enrolling a machine](#enrolling-a-machine)) |
| `enroll approve <REQUEST>` | yes, the owner's | the borg command and the organization's borg home | checks the request and runs `borg org add` for its key and the vault's group: the one step the owner takes. `-print` prints the borg command instead |
| `enroll wait` | yes, the machine's | a reader's settings | waits until the machine's key is a member of the group and opens its current epoch's key; exit 3 at `-timeout` |
| `vault list` | optional | a reader's settings | the owner's vaults the hosts answer |
| `vault show` | optional | a reader's settings | one vault's chain token by token as verified here, its standing against its group, whether its last token is the latest, and its set |
| `put <name>` | yes, the owner's | a publisher's | the next version of a secret, its value from standard input or `-file`: sealed, wrapped, its carrier published, and listed in the vault's next token. `-label`, `-type`, `-not-after`, `-rotate-every`; `-defer` (interval vaults) |
| `anchor` | yes, the owner's | a publisher's | an interval vault: one token listing the latest deferred version of each secret |
| `retire <name>...` | yes, the owner's | a publisher's | one token retiring the secrets, then a sweep of every version of them (`-keep` leaves them answered) |
| `rotate` | yes, the owner's | a publisher's | acknowledges the group's new epoch and re-keys or retires everything stale, 64 secrets a token, then sweeps what the ended epochs held. Each stale secret needs `-set NAME=FILE`, `-same NAME` (or `-same-all`) or `-retire NAME`. `-check` builds nothing; `-keep`; `-unwrapped` |
| `sync` | yes, the owner's, funded to go on | a publisher's, `crypt` | rebuilds the home's record of its vaults from the hosts: chains, current records, names (through the self wraps), commitments, and the funding trees of the carriers answered |
| `kill -confirm KILL [-yes]` | yes, the owner's | with `-yes` a publisher's | the kill switch: one sweep per secret tree the home holds, published in every crypt the tree funded a version in. Every version it published is retracted. Without `-yes` it lists the sweeps and sends nothing |
| `get <name>` | yes (the key that reads) | a reader's settings; `content` for a large secret | reads a secret's value, every check in the signed order; the value raw on standard output, only when it is not a terminal or with `-show`. `-version N` reads history; `-strict` refuses an exposed or possibly stale value |
| `list` | yes (the key that reads) | a reader's settings | the vault's secrets by name, each host's answer compared with the set's root; no value is printed |
| `serve` | yes (the key that reads), held for the daemon's life | a reader's settings | a reader that stays running: walks each vault on `-interval` and serves the values it verified over HTTP, as JSON with their standing and in Vault's KV version 2 shape; `-refuse` sets what is not served ([Serving](#serving)) |
| `due` | optional | a reader's settings | what the vault owes: an acknowledgement, re-keyings, and for the owner the rotations it scheduled and the values whose `-not-after` falls within `-within` (720h). Exit 3 when anything is due |
| `audit` | no; one with coin to pay | a reader's settings; `paid_host`, `chain`, `settle` to pay | verifies the vault's trail from headers and prints the exposure window of every epoch the group began. Paid through the 402 when a paid host is named, at most `-max-sats` a page and `-budget` in all; `-free` walks the free class. `-json` prints the report alone on standard output, and a payment made on standard error |
| `history <name>` | yes, funded | a reader's settings, `paid_host`, `chain`, `settle` | the priced question: pays the host's 402 and prints every version of a secret the host holds, 16 a page; `-after VERSION` asks for the next page |
| `terms [URL]` | no | `paid_host` or URL | prints a host's terms document |
| `fill` | optional | a reader's settings, `chain` | replays to each host what another host answered and it lacks: the vault's chain, its set's carriers, and sweeps; signs nothing |
| `payee key -out FILE` | yes | nothing | writes `BSECRET_PAYEE_KEY` for this home's identity to a new file, mode 0600 |
| `payee settle <payments.jsonl>...` | yes, the payee's | `header_url`, `chain`, `settle` | internalizes every payment in a host's ledger this home has not: all broadcast, then awaited together (`-in-flight`) |
| `doctor` | optional | nothing | the home's state (trees, a tree signed and not yet recorded as minted, vaults, a transition in flight, the outbox, versions published and not listed, commitments recorded, unmined payments), the chain view, broadcaster and fee policy in use, and whether the headers, hosts and priced host answer; reads only |
| `version` | no | nothing | prints the version |

A reader's settings are `hosts`, `header_url`, `crypt`, `org` (the owner's
identity key; a home that owns a vault reads its own by default), the
vault (`vault`, by identifier or display name; the owner's only vault by
default) and, when the hall's hosts are other hosts, `hall_hosts`. A
publisher's settings are those, and `chain`, `settle`, and `facade` in mode
`plane`. On `main` and `test`, `header_url`, `chain` and `settle` default
to WhatsOnChain and GorillaPool's public arcade, so no node is needed
([configuration.md](configuration.md#no-node-needed)). Below, "the node"
means the chain view (`chain`), whichever it is. An identity key is 66 lowercase hex digits; a vault identifier 64;
a group identifier 32. A crypt and a hall are always the full identifier
`<name>_<suffix>`. A txid is 64 lowercase hex digits, in display order.
`bsecret <command> -h` prints a command's flags.

## Configuration

Settings come from, highest first: the global flags, `BSECRET_<KEY>` in
the environment, the config file, and the defaults. Every key, flag and
environment variable, with its default, is in
[configuration.md](configuration.md).

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | done, or everything asked verified |
| 1 | refused: a reader's check failed and names its culprit (`listing`, `retracted`, `hash`, `undecryptable`, `commitment`, `tag`, `payload`, `successor`, `rollback`); a vault that is ahead of its group, broken or terminated; an audit that fails; a writer's evidence that failed closed; a content key used before; a transition another one beat to the chain (`lost`); a readiness check (`rotate -check`) that found a secret with no choice, or one to be re-keyed as it is whose value cannot be read; `get -strict` on an exposed value; or a sweep or payment the network refuses |
| 2 | usage, configuration, local or transport error, a home another command is using, a quorum not met, or a price over `-max-sats` or `-budget`; what was persisted is published by the next command |
| 3 | incomplete: the hosts disagree, a host answered something that does not verify, verified tokens of the vault exist above the chain read, a host could not be asked, no host answered what was asked (an empty answer proves nothing), a ciphertext no content source holds, the token read is spent by a later one no host answers, something is due (`due`), borg's wraps of a new epoch are not published yet, no host of the hall answers a member the wrap of an epoch it was a member of, or with `-strict` nothing says the token read is the latest. It proves nothing either way |

## A home

`init` creates the home at mode 0700: `identity.json` (the identity key),
`wallet.json` (the coin pool) and, once anything is done, `state.json`. The
state holds what must survive a crash: the two kinds of funding tree, and
each tree signed and not yet adopted (`pendingTrees`, below); each
vault's chain of mined tokens and every version the home published (its
carrier, the funding output it spends, whether a token lists it); every
object persisted and not yet confirmed published; the sweeps built; every
content key commitment the home ever published or listed; the payments
made and not yet mined, each recorded before it is sent; while a command
that spends is running, the coin pool as it last stood (`taking`), so that
a coin a run took and never recorded a spend of is found by the next
command and put back when the node shows it unspent; and, for a reader,
the latest token of each vault it verified, with that vault's chain beside
it under `chains/`, and the latest token of each vault's group. It holds no content key and no epoch key. **The home holds a
secret all the same**: the identity key, which for an owner opens every
version it ever wrote through its self wrap. Back it up as one, and keep it
at 0700. One command at a time uses a home; a second is refused (exit 2),
a reading command too: it would otherwise read with no memory of what the
home verified before.

A member's home needs no coin unless it asks a priced question.

### The identity key in a wallet of its own

With `wallet = wire:<URL>` (or `-wallet`), the home holds no key: every
signature, derivation and decryption of the identity key is asked of a
BRC-100 wallet over the wallet wire, the binary substrate both SDKs speak,
at a loopback URL. That wallet is a hardware module's local endpoint, or a
remote signer reached through a tunnel; the wire carries no
authentication, so a URL that is not loopback is refused, and a wallet
that is not on this machine is tunneled to it, not exposed.

```console
$ bsecret -wallet wire:http://127.0.0.1:3321 init     # pins the wallet's identity key
created /home/owner/.bsecret around the identity key of the wallet at http://127.0.0.1:3321
identity     02c6…9a1e
fund address 1EUY…zipY (main)
```

`init` writes `keyholder.json` (the setting and the identity key the
wallet answered) and an empty pool; every later command asks the wallet
for its identity key and refuses (exit 1) one that answers another. The
home's coin pool, state and chains stay in the home, and its fund key is
derived and signed for inside the wallet. What the wallet is asked, so
that its permission policy can be set:

| Call | Protocol and key id | Counterparty | For |
| --- | --- | --- | --- |
| `getPublicKey`, `createSignature` | `[1, "bsecret"]`, `vault`, `secret`, `chain` | anyone | every vault token, carrier and funding tree output |
| `getPublicKey`, `createSignature` | `[1, "bsecret"]`, `fund` | self | the fund address, and spending the pool |
| `encrypt`, `decrypt` | `[2, "bsecret self"]`, a content id | self | the self wrap of every content key, and reading it back |
| `decrypt` | `[2, "keyed content release"]`, borg's key id | the organization's signer key | opening each epoch's key from borg's wrap to the signer key: the wallet released that wrap, so it opens it from the releaser's side, and no private key leaves it |
| `createSignature` | `[1, "bsecret"]`, `enroll` | anyone | a member's join request (`enroll request`) |

Two things still need an embedded wallet in this version: a priced
question and `payee settle`, which pay and take through the home's own
wallet (ask a priced question from a member's or an auditor's home; a
payee's key is the host's, and the host holds it as a file anyway). And
borg reads the organization's key from its own home: a key held only by a
wallet needs borg to sign through one too, so until it does, keep the borg
home with the wallet, offline between borg commands.

## A funding tree a run left

A funding tree's fee coin leaves the pool when the tree is signed, and the
tree is recorded as the home's only once the settlement leg took it; a tree
minted ahead is recorded later still, when the command ends. So a funding
tree has a record of its own. Before a tree of either kind reaches the
settlement leg, the state records it with its kind and the coin it spends
(`pendingTrees`), and the save that records the tree as adopted drops that
record. A command that stopped in between leaves the record, and `doctor`
names it (`tree ... signed for coin ... and not recorded as minted`). The
next command that publishes asks the node what became of the tree before it
spends anything, and says what it found:

| The node shows | The command does | It says |
| --- | --- | --- |
| the tree, and the current tree of its kind is used up or there is none | adopts the tree and takes its unspent change into the pool | `funding tree ... is recovered` |
| the tree, and the current tree of its kind still has outputs | holds the tree, behind any tree already held, takes its change, and adopts it when the trees before it run out; the record stays until then | `funding tree ... is recovered and waits for the switch` |
| no such tree, and the coin unspent | puts the coin back in the pool and keeps the record for one more command; the second such answer drops it | `... never reached the chain: its fee coin ... is unspent and back in the pool`, then `its record is kept for one more command` |
| no such tree, and the coin spent by another transaction | drops the record | `... never reached the chain: its fee coin ... is spent by ...` |
| nothing: it cannot be asked, or cannot say | keeps the record and goes on; the next command asks again | `... could not be settled now (...): its record is kept and the next command asks again` |

A tree that reaches the node after its coin went back is found by the next
command, which adopts it and takes the coin, now spent, out of the pool
(`... its fee coin ... is spent and is taken out of the pool`). Several
trees found on the chain while the current tree has outputs are all held,
and are spent one after the other, in the order of their records; `doctor`
lists each as `minted ahead`. Signing is deterministic, so a command that
mints a tree from a coin that went back builds the tree the stopped run
signed, under the same txid, and adopts it. A command that only reads
(`get`, `list`, `vault show`, `due`, `audit`, `fill`, `doctor`) asks
nothing about a tree and needs no node for it. What is left open is in
[limits.md](limits.md).

A fee needed while a tree is being minted ahead waits for that tree: a home
with one coin has none between the moment the tree takes it and the moment
its change comes back, and the command waits for the change, up to ten
minutes, where it would otherwise report an empty wallet. If the wait ends
first the command says that a funding tree minted ahead still holds the
coin (exit 2): run it again.

The home pays for its trees from its own pool. A deployment that funded
trees through a BRC-100 wallet instead (bcommon's `Trees.Fund`) would not
be covered by any of this: such a wallet chooses the coins, signs and
broadcasts inside one call, so there is no moment before the broadcast to
record the tree in, and a run that stopped after the broadcast and before
the tree was adopted would leave a tree only that wallet knows.

## Crypts

`crypt new <name>` draws the 10-letter suffix uniformly at random and
prints the crypt `<name>_<suffix>`, its topic
`tm_bsecret_<name>_<suffix>`, and the line a host takes
(`BSECRET_CRYPTS=<crypt>`). Many organizations may share a crypt; a vault's
chain and carriers all live in one. The suffix keeps unrelated crypts off
each other's topic. It is not a secret and not an access control.

## Writing

Every change is one or more carriers plus a mined token (spec section 8).

**Evidence first.** Before it builds anything a writing command holds
positive evidence (spec section 7.1): the vault's latest token, as the home
holds it, verifies against `header_url` and its output is unspent per
`chain`; and the group's latest token, read from the hall's hosts, is
unspent too. The evidence is taken again as each token is built. Without
it nothing is written (exit 1): a vault's tip spent by something this home
does not know means another home moved the vault (`bsecret sync`), or the
vault is terminated. Only a positive "unspent" counts: a node's status
`OK`, or WhatsOnChain's "known output, no spend" (404). A source that
answers anything else (a node's `NOT_FOUND`, which it also answers for an
output it pruned or could not read, `IMMATURE`, `FROZEN`, a `SPENT` naming
no spender; WhatsOnChain's "unknown output" (400)) or cannot be read is no
evidence either, and the message says
`the node could not say whether ... is spent`; run the command again once
the node answers.

**A version.** `put` draws a content key and a salt at random, pads the
payload (the name, the value, the claims) to a multiple of 256 bytes, seals
it, builds the record, and wraps the key twice: to the owner's own wallet,
and under a key derived from the group's current epoch key and the
version's content id. The version is then opened again both ways, and its
carrier held to the host's rules, before anything is kept or sent. A
commitment the home has ever published or listed is refused (exit 1): a
content key used twice breaks both versions without any key. The carrier is
**persisted, with its funding output marked used and its commitment
recorded, before it is sent**.

**A token.** The token that lists the version is built from the fold of
the vault's own chain. **The tooling folds before it signs**: the record is
applied to a copy of the fold, which must answer `consistent`; it is held
to the transition rules every host checks against its predecessor; every
version it lists is held to the record its carrier published; and the
token transaction's own output is read back and compared with the record
folded. A transition any of these would flag is refused, unbuilt, with the
reason (`debt`, `count`, `set-mismatch`, `stale-mismatch`,
`commitment-reuse`, `mismatched`): one token whose counts its change lists
do not give ends a vault for good. The token is persisted, settled, and
waited for until it is mined in this home's headers. It took effect only
when a transaction spending its predecessor is mined and carries byte for
byte the record built: a copy of it with another txid is taken as the same
transition; any other spender won, and the transition is discarded (exit
1, `lost`). When a leg refuses the token and the node does not say whether
its predecessor is spent (`the node could not say what spends its
predecessor`), nothing is discarded, even if its fee coin is spent
elsewhere, since that may be a copy of this token: it stays persisted (exit
2) and the next command looks again. Then, after `delay`, the token is published with its parent,
each with its minimal proof, to the facade and to every host named (in
unicast to every host), and confirmed at each host by a lookup. Every token
and sweep must reach every host named; a carrier in unicast needs the
quorum.

**A first token's fee.** A vault's first token spends exactly one output of
its chain tree, and every host refuses a second input from it (spec section
11.1, `token-input`). So its fee is never paid from the chain tree's own
change. A home whose one coin paid for the tree holds nothing else: `vault
create` then first pays that change to the home's own fund key, in a
transaction of its own that it waits to see mined, and pays the fee from
that. It costs one more block, once, on a home's first vault. If the run
stops in between, the command names the payment: import it with `fund
-txid`. Every token is also held to that rule on its inputs before it is
sent, so a token no host would admit is never mined.

**Large secrets.** A ciphertext of up to 16384 bytes rides in the record.
A larger one is written to the first directory in `content`, in a file
named by its hash, and the record names it by that hash: `put` prints the
path and the `uhrp://` locator to serve it under (BRC-26). A reader finds
it in its own `content` sources, a directory or a base URL, within
`max_fetch`.

**Interval vaults.** In a vault created with `-anchor interval`, `put
-defer` publishes a version and lists nothing: a reader takes it by its
link to the listed version, marked unanchored. `anchor` then lists the
latest deferred version of each secret in one token, and the versions
between are swept. A secret's first version is always listed.

**What is left behind.** A version published whose token never mined (the
command stopped, or lost) stays unlisted. `doctor` counts them, and the
next `put`, `retire` or `rotate` sweeps them.

## Revoking a reader

A revoke is complete only when the reader is removed, the vault has
acknowledged the new epoch, and every secret is re-keyed or retired (spec
section 8.2).

```console
$ bsecret rotate -check -set db/password=new.txt -same-all     # ready?
$ borg org remove <key> -group engineering                     # the removal: a new epoch
$ bsecret rotate -set db/password=new.txt -same-all            # acknowledge, re-key, sweep
```

`rotate` first holds the choices to the rule that **every stale secret has
exactly one of a new value, an explicit same-value re-keying, or a
retirement**; with any missing it builds nothing (exit 2; with `-check`,
exit 1). A same-value re-keying needs the value, so each is read first,
from this home's own record and, for a secret kept by its hash, from
`content`: one that cannot be read stops the rotation before anything is
built, and `-check` says so before borg removes anyone. There is no default, because re-keying is not enough for a
credential: give it a new value, and disable the old one where it was
accepted. It then waits for borg's wraps of the new epoch to be published
for the group's members (exit 3 until they are; `-unwrapped` goes on), and
mints the acknowledgement, which carries the first 64 re-keyings, then one
token a block until nothing is stale. Once the vault is settled it sweeps
the versions keyed under the epochs that ended, one sweep per funding tree,
so honest hosts stop answering what the removed member can still open;
`-keep` keeps them answered until a later rotation. A run that stops is
finished by running the same command again: choices for secrets already
re-keyed are ignored, and a choice for a name the vault never held is an
error.

`retire <name>...` retires outside a rotation. While the vault is in debt
only stale secrets can be retired; while it is behind its group, nothing is
built but the acknowledgement.

`due` says what a vault owes, from the two chains: exit 3 when the vault is
behind, in debt, or (in the owner's own home) a secret's `-rotate-every`
has elapsed or its `-not-after` has passed.

## Several homes of one owner

Any home made around the organization's key can own its vaults. What such
a home lacks is at the hosts, and `sync` reads it as a reader does (spec
section 8.5): each vault's chain from its first token, verified and folded;
every current secret's record and, through its self wrap, its name; in an
interval vault every version published and not yet listed that links to the
listed one, so that this home's next version follows it and is not a second
record at a version another home deferred; every commitment any token
listed; and the funding tree of each carrier answered, recorded as spent so
that a sweep or the kill switch reaches it. A home
whose vault another home moved refuses to write (its evidence fails
closed, exit 1) until it runs `sync`.

Not recoverable from the hosts: a version published and not yet listed
whose carrier no host kept; another home's outbox, sweeps in flight and
funding trees with outputs left. Two homes never fund carriers from one
tree: a home made with `init` mints its own.

## The kill switch

`kill -confirm KILL` lists, and with `-yes` makes, one sweep per secret
tree the home holds, each spending every output of the tree, used or not
(spec section 12.5). Once they mine, every honest host retracts every
version the home published. The vaults' tokens stay: they are mined, and
they name identifiers, versions, content ids and commitments, never a
value or a name. It does not reach a copy anyone kept.

A funding tree is the identity's, not a crypt's: each sweep is published in
every crypt that holds a version the tree funded. Work an earlier command
left unfinished (an object a host has not taken, a transition not yet
mined) does not stop the kill switch: it is reported and left for the next
command. Before a sweep is built the node is asked what spends each output:
one another transaction already spends is left out, and that transaction,
once mined, is taken as the sweep it is and published as one (another home
swept it, or this home built it and gave up on it). A sweep refused because
another transaction spends its fee coin is built again. A run that leaves
an output spent by a transaction not yet mined exits 3: run it again.

## Reading

Every reading command asks every host in `hosts` and checks every answer
against `header_url` (spec section 14). The vault's chain is read by asking
each host the `vault` class and then every seq from 0 (`vault-seq`), so the
reader walks it itself: the first token is the one whose input's outpoint
hashes to the vault identifier, and each later token must spend the token
before it under the transition rules. It is folded as it is walked. A host
that lacks a token another host answered is reported (`DISAGREES`, exit 3),
never merged silently. A host that answers a token that does not verify is
named (`REFUSED`), the vault is read from what verified, and the command
is incomplete (exit 3): one host at fault does not make a check fail.
Verified tokens of the vault above the last one the walk could link are
reported (`WITHHELD`, exit 3): a token between was withheld, and what was
read may be an older state. A carrier is held to the same rule: a host that
answers one that does not verify (bytes substituted or damaged on the way,
a carrier that breaks the carrier rules) is named (`REFUSED carrier`), and
so is a host that answers the carrier of another version than the one the
vault lists; the value is read from a host that answered the listed one,
and the command is incomplete (exit 3). When no host answers the listed
one, a carrier that does not verify leaves nothing to read (exit 3), and
one that verifies and is another version fails the first of a reader's
checks (`listing`, exit 1). A host of the hall is held to the same rule
for the wraps of an epoch's key: one that answers a wrap to this key that
does not verify is named (`hall host ...: REFUSED wrap carrier`), also when
another host's wrap opened the key, and the command is incomplete (exit 3);
the key opened is bound by the group's commitment, so the value is still
read. A host of the hall that answers one question with more than borg's
reader takes (128 outputs, or 16 tokens to one seq of the group's chain),
or whose paged walk the reader cuts, is named (`hall host ...: OVERFULL`
or `TRUNCATED`): what it answered below the bound is used, what it
answered past it is not read, and the command is incomplete (exit 3). The walk is bounded by the chain itself: a seq
is asked for only once the one before it is on the chain, and an answer is
read up to 16 MiB and the outputs a page of the contract holds. The group is read from the hall's hosts by borg's
reader, and the vault is held to it: its owner is the group's
organization, and every epoch and epoch id a token or a record names is
one the group's chain began.

With `lookup_auth = on` every question to the crypt's hosts is asked over
BRC-104 as this home's identity, which a private crypt's hosts require
(spec section 10.4); a host that does not serve the crypt to this key
answers an error, which reads as a host that could not be asked (exit 3).
The hall's hosts are asked as before.

A home keeps the chain of each vault it verified (`chains/` in the home:
mined tokens with their proofs, nothing secret), so the next read starts
from the token it remembers, held again to `header_url`, and asks the
hosts only for what came after; a reader with no home walks from seq 0
every time. A host that answers an older latest token than the home
verified is named; when every host does, the answer is refused (exit 1,
`rollback`), and when only some do the vault is read from the others (exit
3). A remembered token whose kept proof no longer verifies is looked up at
`chain`: its current proof replaces the old one, and only the node's word
that the transaction is not mined (a reorganization displaced it) makes
the home forget it. A header source or a node that fails proves nothing,
and nothing is forgotten on its account. Whether the
token read is the latest is settled by `chain`: its output is unspent, or
spent by the vault's next token (exit 3: a later token exists that no host
answers), or by something else (the vault is terminated, exit 1). Without
`chain` the answer is said to be possibly stale, and a version is never
reported current. `get` holds the group's latest token, as the hall's
hosts answer it, to `chain` in the same way: when it is spent, or the node
cannot say, the group may have removed a member since, and the value is
not reported current (`-strict`: exit 3). The evidence is taken at the
read: a value kept afterwards keeps its age.

A home also remembers the latest token of the vault's group it verified
(`seenGroups` in `state.json`), through the `Floor` of borg's reader. Hosts
of the hall that answer the group's chain only below it are answering an
older state, one in which a member since removed is still a member, and
every token of it verifies: the read is refused (exit 1, `rollback`), and a
writing command refuses the same before it builds anything. Only the
node's word that the remembered token is not mined makes the home forget
it.

**`get <name>`** makes the checks of spec section 7.2 in their order and
stops at the first that fails, which names its culprit:

| # | Label | The check |
| --- | --- | --- |
| 0 | `listing` | the set folded here holds this version; the token that listed it lists this record's content id and commitment, under the record's epoch; no earlier token listed the commitment; the record's epoch and epoch id are on the group's chain |
| 0 | `retracted` | no mined sweep, answered by any host or shown by its proof, spends the record's funding output |
| 1 | `hash` | the ciphertext, inline or fetched by hash, is the length and hash the record names: before any wrap is opened. A ciphertext fetched by hash names the content source that served other bytes |
| 2a | `undecryptable` | the wrap opens under the key of the epoch the record names, and of no other (the owner: its self wrap); a key that was not a member of that epoch stops here. A key that was a member, by the group's own chain, and whose wrap of that epoch's key no host of the hall answers was refused nothing: that read is incomplete (exit 3), and a host of the hall that answered a wrap that does not verify is named |
| 2b | `commitment` | the key is the one committed to |
| 3 | `tag` | every segment's tag verifies |
| 4 | `payload` | the plaintext is a payload whose name hashes to the record's identifier |

The value is written raw to standard output, and only when standard output
is not a terminal, or with `-show`. Standard error says the vault's state
(settled, in debt, behind, ahead), whether the version is anchored, and
whether it is current or **exposed**: keyed under an epoch before the
group's latest, so that a key the group has since removed, or rotated away
from, opens it. Names, labels and every other text a host or an owner
wrote is filtered before it reaches a terminal, and held to the line it is
printed on. A vault's display name cannot hold a line break or a control
character at all (the record refuses it, spec section 3), and what a name
may hold that a terminal acts on all the same, an override or a zero-width
character, is filtered. `audit -json` writes such characters as escapes.

In an interval vault the versions above the listed one are asked for one
by one, only while they are answered in a row, and at most 64 of them: a
version a carrier claims never sets how far a reader walks. A retracted
version is not a link: the read takes the highest version it can link
below it, and says that a later one exists. `get -version N` reads a
version as history: it is held to the first token that listed that version,
and refused (`listing`) when that token listed it under a commitment an
earlier one listed. A ciphertext fetched by hash is taken from the first
`content` source that serves exactly the bytes the record names; one that
serves other bytes is passed over.

**`audit`** is the auditor's check of spec section 9. It needs the owner's
key and the vault's identifier (or its name), the hosts and a header
source; it holds no key and reads no secret. Each token is checked mined,
the owner's, linked from the first token, lawful, consistent and keyed to
the group; then, for every epoch the group began after the vault's first
token, it prints the height the group began it and whether it removed
anyone, how many vault tokens mined above that height still named an
earlier epoch, the height of the acknowledgement, the height after which
nothing was listed under an earlier epoch, and the **exposure window**
between the first and the last, in blocks, with each secret's own
re-keying or retirement. A window still open at the end of the trail is
said to be open. The report ends with the token it ends at: an audit covers
nothing after it.

## Serving

`bsecret serve` is a reader that stays running. It takes the home's lock
for its whole life (no other command uses the home meanwhile), and on
every `-interval` (default `1m`) it walks each vault it serves as `get`
does, from the chain the home remembers, and reads every secret of the
vault's set with the checks of `get`, in their order. What it verified is
kept in its memory, and nowhere else, and served over HTTP on `-listen`
(default `127.0.0.1:8250`). No value is ever logged.

| Route | Answers |
| --- | --- |
| `GET /secrets/<name>` | the first vault's secret as JSON: `value` (when it is UTF-8), `value_base64`, `name`, `vault_id`, `version`, `secret_epoch`, `label`, `type`, `not_after`, `read_at`, and `standing` |
| `GET /vaults/<vault>/secrets/<name>` | the same for a vault served, by identifier or display name |
| `GET /v1/<mount>/data/<name>` | the same in the shape of Vault's KV version 2 read: `data.data.value` (and `value_base64`), `data.metadata.version`, and the standing as strings in `data.metadata.custom_metadata`. The mount is `secret` for the first vault, or a vault's identifier or display name |
| `GET /status` | each vault's last walk: its standing, the names read, the secrets it could not read and why; no value |
| `GET /healthz` | 200 while every vault's last walk established it within three intervals, else 503; needs no token |
| `GET /metrics` | Prometheus text (below) |
| `POST /refresh` | walk now; at most once in 5 seconds (429 otherwise) |

`standing` is `vault` (`settled`, `behind`, `in-debt` or
`behind-in-debt`), `settled`, `epoch` and `group_epoch`, `stale` (the
count), `seq` (the token read), `latest` (a spend source says that token is
the vault's latest and the group's latest token is the group's),
`anchored`, `exposed`, `current` (latest and not exposed) and `incomplete`
(a host disagreed, refused or could not be asked during the walk).

`-refuse` names what is not served: `exposed`, `unsettled` (the vault is
behind or in debt), `stale` (not `latest`, which includes a walk that
failed), `unanchored` and `incomplete`; `none` serves every value it
verified. The default, `exposed,unsettled,stale`, is what `get -strict`
refuses. A refused value is answered 409 with its standing and the
conditions it met, and no value. A vault that is ahead of its group,
broken, terminated or rolled back serves nothing (503). A walk that fails
for another reason (a host or the header source down) leaves the values
the last walk verified, marked not `latest` and `incomplete`, so the
default policy refuses them and `-refuse none` serves them. A name the
vault's set does not hold is 404; one it holds and the walk could not read
is 503 with the reason (for a key that is not a member of the epoch, the
`undecryptable` check). The KV shape answers errors as Vault does,
`{"errors": [...]}`.

`-token-file FILE` makes every route but `/healthz` require the file's
token (16 bytes at least), as `Authorization: Bearer <token>` or
`X-Vault-Token: <token>`; a `-listen` address that is not loopback is
refused without one. `-vault V` (repeatable) names the vaults served, by
identifier or display name; the default is the configured vault. `-once`
walks once, prints the status as JSON and exits 0 when every secret was
read and none is refused, else 3.

Metrics, each labeled by `vault` (its identifier):
`bsecret_serve_vault_usable`, `bsecret_serve_vault_settled`,
`bsecret_serve_vault_latest`, `bsecret_serve_vault_seq`,
`bsecret_serve_secrets`, `bsecret_serve_secrets_unread`,
`bsecret_serve_secrets_exposed`,
`bsecret_serve_last_walk_ok_timestamp_seconds` and
`bsecret_serve_walk_seconds` (gauges); `bsecret_serve_walks_total{result}`
(`ok`, `incomplete`, `failed`); and `bsecret_serve_requests_total{route,code}`
and `bsecret_serve_refused_total{condition}`.

A value served keeps the age of the walk that read it: `read_at` says
when. For a vault rotated faster than blocks (an interval vault), each
walk takes the newest version that links to the listed one, marked not
`anchored`; refuse `unanchored` where only a listed version will do.

## Enrolling a machine

A machine that reads makes its key where it runs, and the owner adds that
key to the vault's group; only the public key travels. `enroll` puts the
three steps in one command each:

```console
machine$ bsecret init                                  # its own key, no coin
machine$ bsecret enroll request -label web-1           # prints one line
owner$   bsecret enroll approve 'bsecret-join-v1.…'    # checks it, then borg org add
machine$ bsecret enroll wait                           # until its membership opens
```

`enroll request` writes a join request: version 1, the network, the
owner's key (`org`), the vault (`crypt` and `vault`, the configured or
`-vault` one) or a group and its hall (`-group`, `-hall`), this home's
identity key, `-label` (a name for the machine, a claim, one line of
plain text of at most 64 bytes), a random nonce and the time. It is
signed by the key it names, through the home's wallet, under BRC-43
protocol `[1, "bsecret"]`, key id `enroll`, counterparty anyone,
over `bsecret enrollment request v1` and a line feed followed by the
request's JSON without its signature, and printed as `bsecret-join-v1.`
and the base64url of the JSON. The home keeps it as `enroll.json`, and
standard error prints the key's fingerprint (the first 16 hex digits of
its SHA-256). The request is not secret.

`enroll approve` takes the line, a file holding it, or `-` for standard
input, in the owner's home. It refuses (exit 1) a request whose signature
does not verify under the key it names, that names another organization
or another network, that is older than `-max-age` (24h), or that names a
vault this home does not own; it prints the key, its fingerprint and the
label; then it runs

```text
borg [-home DIR] -hall HALL org add <key> -group <group> [-expiry DUR]
```

with `-borg-cmd` (default `borg` on `PATH`), `-borg-home` and `-expiry`
passed through. borg grants the key a membership and wraps the group's
current epoch key to it; nothing changes in the vault. borg's exit code is
the command's. `-print` prints that command and runs nothing, for a borg
home on another machine.

Approving admits whoever holds the key. A signature proves only that the
request was made by that key and not altered: approve a request that
reached you through a channel you trust (your deployment's log, a ticket
the workload opened), and compare the fingerprint with the one the machine
printed.

`enroll wait` reads the group the kept request names (for a vault, the
group its token names), every token checked against this home's headers,
until this key is one of its members and opens its current epoch's key,
asking again every `-poll` (10s) until `-timeout` (10m; 0 asks once). A
daemon needs no wait: `serve` reads a secret it cannot open as unread, and
serves it once a walk opens it.

## Filling a host

A host that was down off the plane, or was left out of a unicast publish,
lacks what the others hold, and nothing resends it: `get`, `list` and
`vault show` report it (`DISAGREES`). `fill` repairs it from the other
hosts' answers (spec sections 11.6 and 13). Each token a host lacks is
replayed in the BEEF a host admits, assembled from the token and its parent
(the token at `seq - 1`, or at `seq` 0 the chain tree with its proof); each carrier of the vault's set, and each sweep of such a
carrier's funding output, is submitted as another host answered it.
Everything is verified against `header_url` first, and each fill is
confirmed by a lookup at the host it went to. Anyone who reads the crypt
can run it; it needs no coin.

The chain tree at `seq` 0 is the one part no host keeps. Run in the
owner's home, `fill` takes it from the home's own record of its funding
trees, which keeps every tree it minted with its proof, and asks `chain`
only when the home holds no record of it. Elsewhere it asks `chain`, which
may have dropped the tree: a node can prune a transaction whose outputs are
all spent, and each chain tree output is spent by a vault's first token. A
tree taken from the home is checked as the node's answer would be: its txid
must be the one the token spends, its proof must verify against
`header_url` (a proof a reorganization left stale is replaced by the node's
current one when the node gives one), and the token's BEEF must pass the
host's rules. A record whose bytes are another transaction is named
(`REFUSED`) and not used. A second home records the vault's chain tree,
with its proof, when `sync` first takes the chain, while the node still
answers it; a home made by `sync` before bsecret v0.1.1 holds no such
record. When neither the home nor the node supplies the tree, `fill` names
it and exits 3:

```text
vault token seq 0 <txid>: cannot assemble its BEEF: the chain tree <txid>: this home keeps no record of it (a home made by sync before bsecret v0.1.1 does not), and from the node: <the node's answer> (a node drops a fully spent transaction, and no host keeps a chain tree); run bsecret fill from the owner's home that created the vault
```

From a home that is not the owner's, the message says `this home is not
the vault owner's` in place of `this home keeps no record of it ...`.

On the plane the owner's own tooling does part of this as it publishes:
every object is submitted once to the facade, then looked for at every host
in `hosts`, and offered directly to a host the plane did not deliver it to.
The facade's answer is not taken as publication: a carrier counts as
published once `quorum` of the hosts answer it, and a token or a sweep once
all do; short of that the command stops (exit 2), the object stays in the
home, and the next command publishes it first.

## Priced questions

A host may price the `history` and `audit` classes (spec section 10.3).
`terms` prints what a host charges. `history` and `audit` ask at the
host's terms route (`paid_host`, or `-at`) over BRC-104; the host answers
402 with its price, and the question is asked again with a BRC-29 payment
from this home's pool (BRC-105) as output 0, which the host records and its
payee settles. One payment buys one page, and one question is paid for
once: a host that asks again is refused. A payment is recorded in the home
before it is sent, and from then on it is made: its coin is not reused,
whatever the host answers. A price over `-max-sats` (default 1000) is not
paid, and `audit` pays at most `-budget` (default 16000) over all its
pages: a page it may not pay ends the command (exit 2), with the trail not
complete and what was paid for the pages before spent. A page that repeats
tokens of an earlier one is refused. The change of an unmined payment is spendable by this
home's next payment at once, up to 16 in a row. Everything a priced class
answers is also reachable free, one item at a time: `audit -free`, and `get
-version N`.

A host's payee runs `payee key -out FILE` once, to give the host its key,
and `payee settle <state-dir>/payments.jsonl` on a schedule: until a
payment is settled, its payer can still spend the coins elsewhere.
