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

## 3. Who runs what

| Role | Has | Runs |
| --- | --- | --- |
| The owner | the organisation's identity key; a borg home and a bsecret home around the same key; some coin | `borg` to manage the group; `bsecret vault create`, `put`, `rotate`, `retire` |
| A member | its own identity key, which the group names; no coin | `bsecret get`, `list` |
| An auditor | nothing but block headers and the vault's identifier; coin only to pay a priced question | `bsecret audit` |
| A host operator | an overlay host with the bsecret module ([host.md](host.md)) | the host; `bsecret payee settle` for its payee |

## 4. Setting up as the owner

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

A vault's label set (`-labels`) and anchor mode (`-anchor`) are fixed when
it is created. A label is a classification the owner writes down
(`confidential`, `restricted`); it decides nothing about who reads.

## 5. Writing and reading

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

Each `put` takes one block: the version is listed by a mined token. To
write many secrets, expect one block each.

A secret larger than about 16 KB of ciphertext does not ride in its
record. `put` writes its ciphertext to the directory named by `content`,
in a file named by its hash, and prints the `uhrp://` address to serve it
under; readers name a directory or a URL where they can fetch it in their
own `content`. The record's hash check tells a reader when a store served
the wrong bytes.

## 6. Giving someone access

Add their key to the group with borg (`borg org add <key> -group
engineering`). Nothing changes in the vault: borg wraps the current
epoch's key to the new member, who then opens every version keyed under
that epoch, including the ones written before they joined.

## 7. Taking access away

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

## 8. Credentials that machines rotate

A token rotated every few minutes cannot wait for a block. Create the
vault with `-anchor interval`. Then `put -defer` publishes a version
without listing it: readers take it by its link to the last listed
version, and are told it is **unanchored**. `bsecret anchor`, run at an
interval of your choosing, lists the latest version of each secret in one
token. The price is assurance: an unanchored version can be withheld by a
host or replaced by the owner without a trace in the audit trail, and a
reader that needs the newest asks more than one host.

## 9. Auditing

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
reads the same tokens one at a time.

## 10. More than one host

Name every host of the crypt in `hosts`. A reader asks them all, verifies
every answer itself, and says `DISAGREES` when one lacks what another
answered; it never merges silently. `bsecret fill` then copies what a host
lacks from the others' answers, verified first. Anyone can run it.

With a multicast plane (`mode = plane`) the owner submits each object
once and the plane delivers it; without one (`mode = unicast`) the owner
submits to each host, and `quorum` says how many must take a carrier.
Tokens and sweeps always need every host: if one is down, the command
stops with exit 2, what it built stays in the home, and the next command
publishes it first.

## 11. A second machine

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

## 12. If something goes wrong

| What you see | What it means | What to do |
| --- | --- | --- |
| `BEHIND` | the group began an epoch the vault has not acknowledged | `bsecret rotate`, with a choice for every secret |
| `IN DEBT` | the vault acknowledged, and some secrets are not re-keyed yet | run `bsecret rotate` again |
| `EXPOSED` | the version is keyed under an epoch before the group's latest | as above; treat the value as known to whoever was removed |
| `undecryptable` | this key was not a member of the epoch the record names | ask the organisation to add the key to the group |
| `hash` | whoever served the ciphertext substituted or cut it | use another host or content source; the record names what is right |
| `commitment`, `tag`, `payload` | the owner wrapped or encrypted something other than what it committed to | this names the owner; nothing a host did |
| `listing` | a host answered another version than the vault lists | another host; `bsecret fill` |
| `retracted` | the owner swept this version | it is gone on purpose |
| `rollback` | the hosts answer an older state than this home verified | other hosts |
| `DISAGREES` (exit 3) | one host lacks what another answered | `bsecret fill` |
| `WITHHELD` (exit 3) | the hosts answer tokens of the vault above the last one that links: a token between is missing | other hosts; `bsecret fill` |
| `REFUSED token` (exit 3) | a host answered something that does not verify; the vault is read from what did | that host is at fault; tell its operator |
| `another bsecret command is using the home` (exit 2) | one command at a time uses a home, a read too | wait for it, and run the command again |
| `no host answers its carrier` (exit 3) | the vault lists it and no host holds it; proves nothing | `bsecret fill`, or the owner publishes it again |
| `the vault's latest token ... is spent` on a write | another home moved the vault | `bsecret sync` |
| `borg org signer` | the organisation's signer key is not a member of the group | run `borg org signer` in the organisation's borg home |
| `outbox` in `doctor` | something was built and not confirmed at every host | run any writing command: it publishes it first |

The kill switch, `bsecret kill -confirm KILL -yes`, sweeps every funding
tree the home holds: every version it ever published is retracted at every
honest host, in every crypt the home published in. It is irreversible, it
does not reach a copy anyone kept, and the vaults' tokens stay. It runs
even when earlier work is stuck, and passes over an output another home
already swept. If it exits 1 or 3, run it again: a tree already swept is
passed over.
