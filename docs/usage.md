# The bsecret command

`bsecret` keeps an organisation's secrets on overlay hosts
([spec.md](spec.md)), and reads them as a member of the group a vault is
keyed to, or audits a vault as anyone. The owner's home holds the
organisation's identity key: it creates vaults on borg groups, writes each
version of a secret under a content key of its own, wrapped to the group's
current epoch, and, when the group removes a member, acknowledges the new
epoch and re-keys everything the vault held. A member's home reads a
secret with every check made in the signed order. An auditor needs no home:
it verifies a vault's trail from block headers and reports how long each
secret stayed listed under an epoch a removed member held. A reader pays a
host's 402 for the priced questions, and a host's payee settles the
payments the host recorded.

```text
  borg home (the organisation)                           hosts of the hall (tm_borg_<hall>, ls_borg)
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

## Build

Go 1.27.1 or later, or Docker.

```console
$ make bsecret            # bin/bsecret
$ make borg               # bin/borg, the borg command at the tag go.mod pins
$ make docker-build       # ghcr.io/lightwebinc/bsecret and bsecret-devchain, locally
```

In the image the home is `/home/nonroot/.bsecret`; mount a named volume
there (`-v bsecret-home:/home/nonroot/.bsecret`) and pass settings as
`BSECRET_<KEY>` variables.

## bsecret and a borg home

A vault's owner is a borg organisation: the key that signs every vault
token and every carrier is the organisation's identity key, and the vault's
readers are the members of one of the organisation's groups. bsecret does
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
  from the wrap borg made to the organisation's **signer key**, the key
  borg derives from the organisation's identity key and keeps a member of
  every group once `borg org signer` has run. So run `borg org signer`
  once, in the organisation's borg home, before `bsecret vault create`:
  without it the organisation holds no wrap, and bsecret refuses to create
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
| `fund -txid TXID` | yes | `asset`, `header_url` | imports a mined payment to the fund address, once its proof checks |
| `fund [-blocks N]` | yes | `rpc`, `asset` | mines coinbase to the fund address through `generatetoaddress`: a chain you run. Refused on network `main`. `-batch N` blocks a call; `-rescan` re-reads the last `-blocks` blocks for coinbase the pool lacks and mines nothing |
| `crypt new <name>` | optional | nothing | draws the 10-letter random suffix; prints the crypt, its topic, and the host's `BSECRET_CRYPTS` line |
| `crypt list` | yes | nothing | the crypts this home created |
| `vault create <group> -name N` | yes, the owner's, funded | `crypt`, `hall`, a publisher's settings (below) | a vault keyed to a group of the organisation (its id, or its name in the hall): a chain tree, and the vault's first token naming the group's current epoch. `-anchor version` (default) or `interval`; `-labels a,b,c`. The name is one line of plain text |
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
| `due` | optional | a reader's settings | what the vault owes: an acknowledgement, re-keyings, and for the owner the rotations it scheduled and the values whose `-not-after` falls within `-within` (720h). Exit 3 when anything is due |
| `audit` | no; one with coin to pay | a reader's settings; `paid_host`, `asset`, `settle` to pay | verifies the vault's trail from headers and prints the exposure window of every epoch the group began. Paid through the 402 when a paid host is named, at most `-max-sats` a page and `-budget` in all; `-free` walks the free class. `-json` prints the report alone on standard output, and a payment made on standard error |
| `history <name>` | yes, funded | a reader's settings, `paid_host`, `asset`, `settle` | the priced question: pays the host's 402 and prints every version of a secret the host holds, 16 a page; `-after VERSION` asks for the next page |
| `terms [URL]` | no | `paid_host` or URL | prints a host's terms document |
| `fill` | optional | a reader's settings, `asset` | replays to each host what another host answered and it lacks: the vault's chain, its set's carriers, and sweeps; signs nothing |
| `payee key -out FILE` | yes | nothing | writes `BSECRET_PAYEE_KEY` for this home's identity to a new file, mode 0600 |
| `payee settle <payments.jsonl>...` | yes, the payee's | `header_url`, `asset`, `settle` | internalizes every payment in a host's ledger this home has not: all broadcast, then awaited together (`-in-flight`) |
| `doctor` | optional | nothing | the home's state (trees, a tree signed and not yet recorded as minted, vaults, a transition in flight, the outbox, versions published and not listed, commitments recorded, unmined payments) and whether the node, headers, hosts and priced host answer; reads only |
| `version` | no | nothing | prints the version |

A reader's settings are `hosts`, `header_url`, `crypt`, `org` (the owner's
identity key; a home that owns a vault reads its own by default), the
vault (`vault`, by identifier or display name; the owner's only vault by
default) and, when the hall's hosts are other hosts, `hall_hosts`. A
publisher's settings are those, and `asset`, `settle`, and `facade` in mode
`plane`. An identity key is 66 lowercase hex digits; a vault identifier 64;
a group identifier 32. A crypt and a hall are always the full identifier
`<name>_<suffix>`. A txid is 64 lowercase hex digits, in display order.
`bsecret <command> -h` prints a command's flags.

## Configuration

Settings come from, highest first: the global flags, `BSECRET_<KEY>` in the
environment (the key in upper case), the config file, and the defaults. The
config file is `-config PATH`, else `$BSECRET_HOME/config`, else
`$XDG_CONFIG_HOME/bsecret/config`, else `~/.bsecret/config`. Its grammar is
one `key = value` per line, `#` comments, blank lines ignored; a key it
does not define, a key given twice, or a line without `=` is an error,
never ignored.

| Key | Default | Meaning |
| --- | --- | --- |
| `arcade_key` | none | bearer token for an arcade installation named in `settle` |
| `asset` | none | the node's asset API base URL: proofs, the chain tip, raw transactions, and the node's view of which outputs are spent (a writer's evidence, and a reader's that a token is the latest) |
| `chain_tree_count` | `8` | outputs of a new chain tree, 1 to 32: a vault's first token carries its chain tree whole |
| `content` | none | where a ciphertext over the inline bound is kept, comma separated: a directory (a writer stores into the first one; a reader reads from each) or an `http(s)` base URL a reader fetches `<base>/<hash>` from. A file is named by the lowercase hex of its SHA-256 |
| `crypt` | none | the crypt identifier a command uses; an owner whose vaults are all in one crypt uses it |
| `delay` | `60s` | the propagation delay: a mined token or sweep is published this long after its block is in this home's headers, so the hosts' headers have it too (spec section 8.3); `0s` to `10m` |
| `facade` | none | mode `plane`: the overlay host a publisher submits to, from which the plane delivers to every subscribed host. Refused in mode `unicast` |
| `freshness` | `60s` | how old a writer's evidence that the vault's and the group's latest tokens are unspent may be when it publishes a version (spec section 7.1); at most `600s`. Every token retakes the evidence as it is built |
| `hall` | none | the borg hall a new vault's group lives in (`vault create`); a vault names its own afterwards |
| `hall_hosts` | `hosts` | the overlay hosts asked about the group's hall, comma separated, at most 16 |
| `header_url` | none | the header source every proof is checked against: an overlay bridge's base URL (native `/v1/root/<height>` and `/v1/tip`), `woc:main`, `woc:test` or `chaintracks:URL` |
| `home` | `~/.bsecret` | the identity's home |
| `hosts` | none | the crypt's overlay hosts, comma separated, at most 16: every host a reader asks and compares; in mode `unicast` every host a publisher submits to; in mode `plane` the hosts every mined object is also sent to directly |
| `max_fetch` | `16777216` | the most ciphertext a reader fetches by hash, in bytes; at most 134217728 |
| `mode` | `plane` | `plane` or `unicast`: how a publisher's objects reach the hosts (spec section 13) |
| `network` | `main` | `main`, `test` or `regtest`: the fund address prefix and the header source's proof-of-work floor |
| `object_bound` | `1048576` | the plane's object bound in bytes, at most 8388608; a carrier or token whose BEEF is larger is not published |
| `org` | none | the owner a reader reads: the organisation's identity key |
| `originator` | `bsecret` | the BRC-100 originator presented to the wallet |
| `paid_host` | none | the base URL of `ls_bsecret` on the host the priced questions are asked of (`audit`, `history`, `terms`): the host's terms route (spec section 10.3). An origin, with no path |
| `quorum` | `all` | how many of `hosts` must hold a carrier for it to count as published: `all`, `majority`, `one`, or a number up to the host count. In mode `unicast` they are the hosts that took it; in mode `plane`, the hosts that answer it by lookup once the facade took it. A token or a sweep always needs every host |
| `rpc` | none | the node's JSON-RPC URL (`fund`) |
| `rpc_pass`, `rpc_user` | `bitcoin` | the node's basic auth, also for `settle = rpc:` |
| `settle` | none | the settlement leg for what is mined (funding trees, tokens, sweeps, a payment a payee takes): `tcp:<host:port>`, `rpc:<url>` or `arcade:<url>` |
| `timeout` | `15s` | bounds each request; `1s` to `5m` |
| `tree_count` | `32` | outputs of a new secret tree, 1 to 1000 |
| `vault` | none | the vault a command uses: its identifier, or its display name when that names one vault |

Global flags, before the command: `-config PATH`, `-home DIR`,
`-crypt CRYPT`, `-org KEY`, `-vault VAULT`, `-hosts URLS`,
`-hall-hosts URLS`, `-header-url SOURCE`, `-mode MODE`, `-network NET`,
`-quorum Q`, `-timeout DUR`, `-v` (also accepted after the command),
`-version`.

Every limit, with its reason, is in [limits.md](limits.md). A cap is
refused with exit 2 and a message naming the limit; a recommendation
passed prints `warning: ...` and goes on. The addresses have no default on
purpose: a default would send an organisation's records, or a member's
questions, to a server nobody configured.

An owner's config file, with documentation addresses:

```text
# ~/.bsecret/config
network      = test
crypt        = example_crypt_hmqzvtkwrx
hall         = example_hall_vkqzmtrwxp
asset        = http://192.0.2.10:8090
settle       = rpc:http://192.0.2.10:9292
facade       = https://host-a.example.com
hosts        = https://host-a.example.com,https://host-b.example.com
header_url   = https://headers.example.com
content      = /srv/bsecret/content
```

A member's, without the plane:

```text
network      = test
crypt        = example_crypt_hmqzvtkwrx
org          = 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
vault        = ops
hosts        = https://host-a.example.com,https://host-b.example.com
header_url   = https://headers.example.com
asset        = http://192.0.2.10:8090
content      = https://content.example.com
paid_host    = https://terms.host-a.example.com
```

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
(`BSECRET_CRYPTS=<crypt>`). Many organisations may share a crypt; a vault's
chain and carriers all live in one. The suffix keeps unrelated crypts off
each other's topic. It is not a secret and not an access control.

## Writing

Every change is one or more carriers plus a mined token (spec section 8).

**Evidence first.** Before it builds anything a writing command holds
positive evidence (spec section 7.1): the vault's latest token, as the home
holds it, verifies against `header_url` and its output is unspent per
`asset`; and the group's latest token, read from the hall's hosts, is
unspent too. The evidence is taken again as each token is built. Without
it nothing is written (exit 1): a vault's tip spent by something this home
does not know means another home moved the vault (`bsecret sync`), or the
vault is terminated.

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
1, `lost`). Then, after `delay`, the token is published with its parent,
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

Any home made around the organisation's key can own its vaults. What such
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
organisation, and every epoch and epoch id a token or a record names is
one the group's chain began.

A home keeps the chain of each vault it verified (`chains/` in the home:
mined tokens with their proofs, nothing secret), so the next read starts
from the token it remembers, held again to `header_url`, and asks the
hosts only for what came after; a reader with no home walks from seq 0
every time. A host that answers an older latest token than the home
verified is named; when every host does, the answer is refused (exit 1,
`rollback`), and when only some do the vault is read from the others (exit
3). A remembered token whose kept proof no longer verifies is looked up at
`asset`: its current proof replaces the old one, and only the node's word
that the transaction is not mined (a reorganisation displaced it) makes
the home forget it. A header source or a node that fails proves nothing,
and nothing is forgotten on its account. Whether the
token read is the latest is settled by `asset`: its output is unspent, or
spent by the vault's next token (exit 3: a later token exists that no host
answers), or by something else (the vault is terminated, exit 1). Without
`asset` the answer is said to be possibly stale, and a version is never
reported current. `get` holds the group's latest token, as the hall's
hosts answer it, to `asset` in the same way: when it is spent, or the node
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
trees, which keeps every tree it minted with its proof, and asks `asset`
only when the home holds no record of it. Elsewhere it asks `asset`, which
may have dropped the tree: a node can prune a transaction whose outputs are
all spent, and each chain tree output is spent by a vault's first token. A
tree taken from the home is checked as the node's answer would be: its txid
must be the one the token spends, its proof must verify against
`header_url` (a proof a reorganisation left stale is replaced by the node's
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
