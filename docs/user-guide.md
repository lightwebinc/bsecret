# bsecret: user guide

bsecret keeps an organisation's secrets (passwords, tokens, keys, small
files) on overlay hosts that hold ciphertext and never a key. This guide
explains the ideas and the day-to-day use. [usage.md](usage.md) is the
reference for every command and setting, [spec.md](spec.md) the contract,
and [../QUICKSTART.md](../QUICKSTART.md) a ten-minute run on one machine.

## 1. The ideas

**A secret** has a name (`db/password`), a value, and versions. Each
version is encrypted once under a random **content key** of its own. The
ciphertext is public; what matters is who can open the content key.

**The content key is wrapped twice.** Once to the owner's own wallet, so
the owner can always read what it wrote. And once under the key of one
**epoch** of a borg group, so the members of that epoch, and nobody else,
can open it.

**A group and its epochs are borg's.** An organisation (an identity key)
runs groups with borg. A group's membership is a chain of mined tokens.
Every time the organisation removes a member, the group begins a new epoch
with a new key that the removed member never receives. bsecret does not
manage members: to give someone access you add their key to the group with
borg, and to take it away you remove it.

**A vault** is a set of secrets bound to one group, for good. It is a
chain of mined tokens that lists every version of every secret it holds
and names the epoch each is keyed under. Different readers for different
secrets means different vaults on different groups.

**A crypt** is where vaults live: one topic that a set of overlay hosts
carries. Many organisations can share a crypt.

**Revoke forces rotation.** When the group begins a new epoch, the vault
must acknowledge it in its next token. From that token on, every host
refuses anything on the vault's chain except the re-keying or retirement
of what the vault held, until nothing in it is left under the old epoch.
This is checked by every replica, not by the owner's good intentions.

**The chain is the audit trail.** Anyone with block headers can verify
which versions the owner listed, in what order, under which epoch, and how
long each secret stayed listed under an epoch a removed member held.

## 2. What a removal does, and does not

This is the part to read before relying on bsecret.

A removed member **can still read**:

- every version they ever opened (they may have kept the plaintext);
- every version keyed under an epoch whose key they hold, whether or not
  they fetched it before they left, for as long as any host or any copy
  still has its ciphertext;
- every current value, **until the vault re-keys it**: between the removal
  and the token that lists a secret's re-keyed version, the secret is still
  open to them. `bsecret audit` reports that window, in blocks.

A removed member **cannot read** any version keyed under the new epoch.

So removal protects **what is written after the vault re-keys**. And for a
credential, re-keying is not enough: the removed reader knew the old
value. **Give every credential a new value when you re-key, and disable
the old one where it was accepted.** bsecret stores and distributes the new
value; changing it at the service that takes it is yours to do.

bsecret also does not hide names, sizes or timing (a secret's identifier is
a hash of a guessable name), does not prove who read what, and does not
erase: a sweep makes honest hosts stop answering a version, and a copy
anyone kept stays a copy. [spec.md](spec.md) section 18 has the whole list.

## 3. Install

Build `bin/bsecret` with `make bsecret` (Go 1.27.1 or later), or run the
image `ghcr.io/lightwebinc/bsecret` with a volume at
`/home/nonroot/.bsecret`. The organisation and its groups are borg's, so an
owner also needs the `borg` command (`make borg` builds the one this
version was tested with). A host is borg's host image with the bsecret
module added, or the module on a reference overlay host
([host.md](host.md)). `bsecret doctor` shows the home and asks every
configured endpoint whether it answers; it changes nothing.
[../QUICKSTART.md](../QUICKSTART.md) runs all of it in containers on one
machine.

## 4. Words

| Word | Meaning |
| --- | --- |
| home | a directory holding one identity: its key, its coin and its state. Secret: the owner's key opens everything it wrote |
| organisation, owner | an identity key that runs groups with borg and owns vaults here |
| group, epoch | borg's: a chain of tokens naming the members, and one generation of the group's key; every removal begins an epoch |
| crypt | the topic `tm_bsecret_<name>_<suffix>` a set of hosts carries, shared by any number of owners |
| vault | a chain of mined tokens that lists every version of every secret it holds, bound to one group for good |
| secret, version | a named value; each new value, or each re-keying of the same value, is a version with a content key of its own |
| wrap | a content key encrypted to someone: once to the owner, once under the epoch's key |
| token, carrier | a token is a mined transaction (one per change of a vault); a carrier is an unmined one that holds one version's record and spends a funding output |
| funding tree | a mined transaction whose outputs fund carriers (a secret tree) or begin vaults (a chain tree) |
| listed, anchored | a version a mined token of the vault lists; an unanchored one is published and not yet listed (interval vaults) |
| behind, in debt, settled | a vault that has not acknowledged its group's latest epoch; one that has, with secrets still under an earlier one; one that owes nothing |
| exposed | a version keyed under an epoch before the group's latest: a removed member's key opens it |
| sweep | a mined spend of funding outputs: every honest host stops answering the versions they funded |

## 5. Who runs what

| Role | Has | Runs |
| --- | --- | --- |
| The owner | the organisation's identity key; a borg home and a bsecret home around the same key; some coin | `borg` to manage the group; `bsecret vault create`, `put`, `rotate`, `retire` |
| A member | its own identity key, which the group names; no coin | `bsecret get`, `list` |
| An auditor | nothing but block headers and the vault's identifier; coin only to pay a priced question | `bsecret audit` |
| A host operator | an overlay host with the bsecret module ([host.md](host.md)) | the host; `bsecret payee settle` for its payee |

## 6. Setting up as the owner

You need the organisation's borg home, with the group created and, once,
`borg org signer` run: that makes the organisation's own signer key a
member of every group, which is how the organisation's tooling comes to
hold each epoch's key. bsecret reads that key from borg's wrap each time
it needs it, and keeps none on disk.

```console
$ bsecret init -borg ~/.borg          # a bsecret home around the same identity
$ bsecret fund -txid <a payment to the fund address printed>
$ bsecret crypt new ops               # or use a crypt your hosts already carry
$ bsecret vault create engineering -name ops
```

`init -borg` copies the identity file and nothing else. The two homes keep
separate coin, state and locks, and bsecret never writes into the borg
home. Put the addresses in `~/.bsecret/config` ([usage.md](usage.md) has an
example): the crypt's hosts, the hall's hosts when they are others, a
header source, a node, a settlement leg, and on a multicast plane the
facade.

```text
# ~/.bsecret/config, a member
crypt      = example_crypt_hmqzvtkwrx
org        = 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
vault      = ops
hosts      = https://host-a.example.com,https://host-b.example.com
header_url = https://headers.example.com
asset      = http://192.0.2.10:8090
```

No address has a default: a default would send an organisation's records,
or a member's questions, to a server nobody chose.

A vault's label set (`-labels`) and anchor mode (`-anchor`) are fixed when
it is created. A label is a classification the owner writes down
(`confidential`, `restricted`); it decides nothing about who reads.

One coin is enough. A home's first vault made from a single coin takes one
block more than later ones: a vault's first token may not pay its fee from
its own chain tree's change, so the command first pays that change to the
home's own fund key and says so.

## 7. Writing and reading

```console
$ bsecret put db/password < new-password.txt
$ pass generate | bsecret put api/token -rotate-every 720h
$ bsecret get db/password | psql ...
$ bsecret get db/password -show        # to a terminal, on purpose
$ bsecret list
```

A value is read from standard input or `-file`, never from an argument, so
it is in no process list and no shell history. `get` writes the value raw
to standard output only when that is not a terminal, or with `-show`, so a
secret is not left in a scrollback by accident. Everything else `get` says
goes to standard error:

```text
vault   7b1e…04aa ops seq 5: settled at epoch 1
latest  seq 5 is the latest: its output is unspent per the node
secret  db/password version 2 label confidential epoch 1, read as a member: anchored, current
```

Read these three lines. **settled** means the vault owes nothing; **in
debt** that some secrets are still under an old epoch; **behind** that the
group has begun an epoch the vault has not acknowledged. **current** means
the version is keyed under the group's latest epoch and the node says the
token read is the vault's latest; **EXPOSED** means it is keyed under an
earlier epoch, so a key the group has since removed can open it. A script
that must not act on such a value uses `get -strict`, which refuses it.

Each `put` takes one block: the version is listed by a mined token, which
is published a minute after its block (the propagation delay), and the
next token of the same vault is built on it. To write many secrets, expect
one block each; different vaults move in the same block.

What it costs: a version is one carrier, which is never mined and rides a
funding output of one satoshi, and one mined token of about 850 bytes, so
about 900 satoshis at 1 satoshi a byte with its share of the funding tree.
Reading costs nothing. [limits.md](limits.md) has the measured table.

If a command stops part way (a host down, the network slow, the machine
switched off), what it built is kept in the home and the next command
finishes it first: the same bytes are sent again, never a second version.
The same holds for a funding tree. If a command stops while it is minting
one, the next command that publishes asks the node what became of it and
tells you: `funding tree ... is recovered` when the tree reached the chain
(nothing is lost), or `... never reached the chain: its fee coin ... is
unspent and back in the pool` when it did not. You have nothing to do; if
the node cannot be asked, the command says so and the next one asks again.
`bsecret doctor` lists whatever is still owed.

A secret larger than about 16 KB of ciphertext does not ride in its
record. `put` writes its ciphertext to the directory named by `content`,
in a file named by its hash, and prints the `uhrp://` address to serve it
under; readers name a directory or a URL where they can fetch it in their
own `content`. The record's hash check tells a reader when a store served
the wrong bytes.

## 8. Giving someone access

Add their key to the group with borg (`borg org add <key> -group
engineering`). Nothing changes in the vault: borg wraps the current
epoch's key to the new member, who then opens every version keyed under
that epoch, including the ones written before they joined.

## 9. Taking access away

Three steps, in this order.

```console
$ bsecret rotate -check -set db/password=new.txt -same tls/cert -retire old/token
$ borg org remove <key> -group engineering
$ bsecret rotate -set db/password=new.txt -same tls/cert -retire old/token
```

1. **Decide, before the removal, what becomes of every secret.** Each
   needs one of: a new value (`-set NAME=FILE`), an explicit re-keying of
   the same value (`-same NAME`, or `-same-all` for everything not named),
   or retirement (`-retire NAME`). `rotate -check` says whether your
   choices cover the vault, and builds nothing. There is no default, on
   purpose: a credential re-keyed with its old value is still known to the
   person you removed.
2. **Remove the key from the group** with borg. This begins the new epoch.
   From this moment the vault is behind, and every reader says so.
3. **Rotate.** bsecret acknowledges the new epoch and re-keys or retires
   every secret, 64 a token, one token a block. Then it sweeps the old
   versions, so that honest hosts stop answering what the removed member
   can still open. `-keep` keeps them answered instead, as history.

Do steps 2 and 3 together: every block between them is a block in which
every value in the vault is still open to the removed member. If `rotate`
stops part way, run the same command again.

Between steps 2 and 3 the vault can be written by nothing but `rotate`: a
`put` or a `retire` is refused, with nothing built or sent, until the
vault has acknowledged the new epoch. That refusal is the owner's own
tooling's. No host can make an owner acknowledge; what a host does refuse,
from the acknowledgement on, is anything but the re-keying or retirement
of what is still under the old epoch.

`rotate` waits for borg to have published the new epoch's key to the
members who remain; if it says the wraps are not published yet, run a borg
command in the organisation's home so that it publishes them, then rotate
again.

Then, for each credential you gave a new value: **change it where it is
accepted**, and disable the old one.

`bsecret due` says what a vault owes, to anyone: it exits 3 when the vault
is behind or in debt. In the owner's own home it also lists secrets whose
`-rotate-every` has elapsed and values whose `-not-after` has passed. Run
it from a timer.

## 10. Credentials that machines rotate

A token rotated every few minutes cannot wait for a block. Create the
vault with `-anchor interval`. Then `put -defer` publishes a version
without listing it: readers take it by its link to the last listed
version, and are told it is **unanchored**. `bsecret anchor`, run at an
interval of your choosing, lists the latest version of each secret in one
token. The price is assurance: an unanchored version can be withheld by a
host or replaced by the owner without a trace in the audit trail, and a
reader that needs the newest asks more than one host. A reader follows at
most 64 unlisted versions above a listed one, so anchor at least that
often.

## 11. Auditing

```console
$ bsecret -org <owner key> -vault <vault id> audit -free
```

needs no home, no key and no coin. It verifies every token of the vault's
chain from block headers and prints, for every epoch the group began:

```text
epoch   1 began at height 918 (a member removed): acknowledged at height 920, settled at height 920
window  epoch 1: 2 block(s) from the block that began it to the token after which nothing was listed under an earlier epoch
secret  41c2…9f0e re-keyed at seq 4, height 920: listed under epoch 0 until then, 2 block(s) exposed
```

The **window** is the exposure the owner's own signed statements give for
that removal. A window that is `OPEN` means the trail ends before the
vault settled; `NEVER ACKNOWLEDGED` means the owner went on without
acknowledging, and the count beside it is how many tokens it wrote under
the old epoch after the removal. The report ends with the token it ends
at: an audit covers nothing after it, and says whether the node shows that
token unspent. Read [spec.md](spec.md) section 9.3 for what a trail does
not prove.

Without `-free`, when a paid host is configured, `audit` asks the priced
audit class and pays the host's price for each page of the chain (64
tokens): at most `-max-sats` a page and `-budget` in all. The free path
reads the same tokens one at a time. `-json` prints the same report for a
program.

An audit needs nobody's permission and nobody's key, so the check that
matters is the one somebody else runs: hand an auditor the owner's key,
the vault's identifier, the crypt and the hosts, and they verify the trail
against their own header source. What an audit cannot see is which key a
wrap is under: a version the owner mis-keyed is found by the members who
cannot open it, not by the trail ([limits.md](limits.md)).

## 12. More than one host, and plane or unicast

Name every host of the crypt in `hosts`. A reader asks them all, verifies
every answer itself, and says `DISAGREES` when one lacks what another
answered; it never merges silently. `bsecret fill` then copies what a host
lacks from the others' answers, verified first. Anyone can run it.

`fill` cannot repair one thing without help: a vault's first token, at a
host that lost it, once the node no longer serves the vault's chain tree
([limits.md](limits.md)).

| | Plane (`mode = plane`, `facade`) | Unicast (`mode = unicast`) |
| --- | --- | --- |
| A carrier | submitted once to the facade; every subscribed host receives it; counts once `quorum` hosts answer it by lookup | submitted to each host; counts once `quorum` hosts took it |
| A token or a sweep | to the facade and to every host named | to every host; needs all of them |
| A host that was down | repaired by the plane within its window; every object is also looked for at each host and offered directly | misses what was sent meanwhile; `fill` repairs it |
| Object size | kept small: at most 4 packets at the defaults, with warnings above | one HTTP request an object, up to the record bounds |
| Cost that grows with hosts | none | every object uploaded once per host |
| Priced questions | not on the plane: the terms route is HTTP | the same |

Either way a reader asks every host it names and compares the answers.
Tokens and sweeps always need every host: if one is down, the command
stops with exit 2, what it built stays in the home, and the next command
publishes it first.

## 13. A second machine

```console
$ bsecret init -from identity.json    # the organisation's key, carried by hand
$ bsecret fund -txid <...>
$ bsecret sync
```

`sync` rebuilds the home's record from the hosts: each vault's chain, the
current records, the names (through the owner's own wraps), the versions
an interval vault's other home published and has not listed yet, and every
commitment ever listed. If two homes change one vault, one of them loses
the race for the next token; it says so, and `sync` catches it up.

## 14. Priced questions and the payee

The free questions answer everything a member needs. A host may price the
bulk questions: the whole trail of a vault (`audit`) and every version of
one secret it still holds (`history`). `bsecret terms` prints what a host
charges. A priced question is paid from the home's coin through the host's
402: one payment a page, at most `-max-sats` a page (1000 unless you say
otherwise) and, for an audit, at most `-budget` in all (16000). A budget
that cannot pay the next page stops the command; what it paid for the
pages before is spent. One question is paid for once: a host that asks for
a second payment is refused, and a payment that was sent is kept as made
even when the host does not answer, so its coin is never spent twice. One
coin is enough for several questions in a row: each payment spends the
change of the one before, up to 16 unmined at once.

A host's operator settles what it was paid with `bsecret payee settle
<payments.jsonl>` from the payee's home, on a schedule: until a payment is
settled, its payer can still spend the coins elsewhere.

## 15. Limits

The ones you meet first; the full table, with reasons and with which
numbers are measured, is [limits.md](limits.md).

| Setting | Default | Cap |
| --- | --- | --- |
| A value carried in its record | as needed | about 16 KB; larger is stored by its hash (`content`) |
| Secrets in a vault | as needed | 4096; warns above 256 |
| Changes per token | as needed | 64 each; plane warns above 16 |
| Changes per vault | one a block, published 60 s after it mines | one a block |
| Unlisted versions in a row (interval vaults) | as published | 64 a reader follows |
| Readers of a vault | the group's members | borg's, 1024 a group |
| Hosts | none | 16; unicast warns above 5 |
| Quorum (carriers) | all | the host count |
| Price paid for one priced page | at most 1000 sat | `-max-sats` |
| Paid by one audit | at most 16000 sat | `-budget` |
| Payments in a row from one coin | each spends the last one's change | 16 unmined |

## 16. If something goes wrong

Run `bsecret doctor` first: it shows the home, the pool, the trees, a
funding tree a stopped command left, each vault and what it owes, anything
persisted and not yet published, a sweep in flight or failed, and whether
every endpoint answers.

| Exit | Meaning | What to do |
| --- | --- | --- |
| 0 | done; everything asked verified | nothing |
| 1 | refused: a check failed and names its culprit, or the evidence contradicts what was asked | read the message: it names the host, the owner, the source or the reason |
| 2 | usage, configuration, transport, a home in use, a quorum not met, or a price over `-max-sats` or `-budget` | fix the named setting; what was persisted is published by the next command |
| 3 | incomplete: it proves nothing either way | ask again, ask other hosts, or `fill` |


| What you see | What it means | What to do |
| --- | --- | --- |
| `BEHIND` | the group began an epoch the vault has not acknowledged | `bsecret rotate`, with a choice for every secret |
| `IN DEBT` | the vault acknowledged, and some secrets are not re-keyed yet | run `bsecret rotate` again |
| `EXPOSED` | the version is keyed under an epoch before the group's latest | as above; treat the value as known to whoever was removed |
| `undecryptable` | this key was not a member of the epoch the record names; or, when the message says this key opened that epoch's key, the owner wrapped the content key under another key | ask the organisation to add the key to the group; the second names the owner |
| `was a member of epoch N ... no host of the hall answers a wrap` (exit 3) | the hall's hosts withhold, lost or have not yet received borg's wrap of that epoch's key to this key; a host that answered one that does not verify is named | other hosts of the hall (`hall_hosts`); the organisation runs a borg command, which publishes the wraps it owes |
| `hash` | the content source named served other bytes than the record names: it substituted or cut them | use another content source; the record names what is right |
| `commitment`, `tag`, `payload` | the owner wrapped or encrypted something other than what it committed to | this names the owner; nothing a host did |
| `listing` | every host that answered, answered another version than the vault lists, or the owner listed a record as it is not | another host; `bsecret fill` |
| `answered a carrier that is not the version the vault lists` (exit 3) | the host named answered another version; the value was read from a host that answered the listed one | that host is behind or at fault; `bsecret fill` |
| `retracted` | the owner swept this version | it is gone on purpose |
| `rollback` | the hosts answer an older state of the vault, or of its group, than this home verified | other hosts |
| `DISAGREES` (exit 3) | one host lacks what another answered | `bsecret fill` |
| `WITHHELD` (exit 3) | the hosts answer tokens of the vault above the last one that links: a token between is missing | other hosts; `bsecret fill` |
| `REFUSED token`, `REFUSED carrier` (exit 3) | the host named answered something that does not verify: a token, or a carrier whose bytes were substituted or damaged; it is not used, and the value is read from the hosts that answered what does | that host is at fault; tell its operator |
| `another bsecret command is using the home` (exit 2) | one command at a time uses a home, a read too | wait for it, and run the command again |
| `no host answers its carrier` (exit 3) | the vault lists it and no host holds it; proves nothing | `bsecret fill`, or the owner publishes it again |
| `the vault's latest token ... is spent` on a write | another home moved the vault | `bsecret sync` |
| `borg org signer` | the organisation's signer key is not a member of the group | run `borg org signer` in the organisation's borg home |
| `outbox` in `doctor` | something was built and not confirmed at every host | run any writing command: it publishes it first |
| `tree ... signed for coin ... and not recorded as minted` in `doctor` | a command stopped while minting a funding tree | run any writing command: it asks the node and says what it found |
| `fee input: ... no spendable output` (exit 2) | the home has no coin | `bsecret fund`. If it says coins are change not yet mined, or that a funding tree minted ahead still holds the coin, run the command again after a block |
| `the only transitions built are the acknowledgement ...` on a write | the vault is behind its group or in debt: nothing else is built | `bsecret rotate`, with a choice for every secret |

## 17. The kill switch

`bsecret kill -confirm KILL -yes` sweeps every funding
tree the home holds: every version it ever published is retracted at every
honest host, in every crypt the home published in. It is irreversible, it
does not reach a copy anyone kept, and the vaults' tokens stay. It runs
even when earlier work is stuck, and passes over an output another home
already swept. If it exits 1 or 3, run it again: a tree already swept is
passed over.
A reader afterwards sees an absence (`no host answers its carrier`, exit
3), not `retracted`.

## 18. Where to go next

- [usage.md](usage.md): every command, setting and exit code.
- [limits.md](limits.md): every default and cap, why, and what is measured.
- [host.md](host.md): run a host, price a question, settle, back up.
- [spec.md](spec.md) and [frozen.md](frozen.md): the records, and what
  cannot change once published.
