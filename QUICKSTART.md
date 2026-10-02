# Quickstart

In about ten minutes, on one machine: run two overlay hosts that carry a
borg hall and a bsecret crypt, create an organisation with three members
and a group (borg), create a vault on the group, put three secrets that
every member reads, remove one member and watch the vault fall behind,
acknowledge the new epoch and re-key so that the removed member reads none
of the new versions, retire a secret, pay a host's 402 for the audit and
read the exposure window from block headers, and check that the two hosts
hold the same. No coin is needed, because a local chain stands in for the
network; the last section says what changes on the real one.

You need [Docker](https://docs.docker.com/get-docker/) with Compose, and
this repository (or just its `deploy/quickstart/compose.yaml`).

```mermaid
flowchart LR
  B["borg (the organisation)"] -->|"group tokens, wraps"| HA["host-a"]
  B --> HB["host-b"]
  O["bsecret (the owner)"] -->|"carriers, vault tokens"| HA
  O --> HB
  M["bsecret (alice, bob, carol)"] -->|"lookup, both"| HA
  M -->|lookup| HB
  A["bsecret (auditor)"] -->|"audit: BRC-104, 402"| T["host-a terms route"]
  P["bsecret (payee)"] -->|"settle the ledger"| C
  HA --> D[(mysql)]
  HB --> D
  O -->|"settle, proofs, headers"| C["chain (local)"]
  HA -->|headers| C
  HB -->|headers| C
```

## 1. Start the local chain

```console
$ cd deploy/quickstart
$ docker compose up -d chain
$ borg() { who=$1; shift; docker compose run --rm -T -e BORG_HOME=/home/nonroot/.borg/$who borg "$@"; }
$ bs()   { who=$1; shift; docker compose run --rm -T -e BSECRET_HOME=/home/nonroot/.bsecret/$who bsecret "$@"; }
```

`chain` is a stand-in for the network: it serves a node's API, mines every
transaction it is sent at once, and is the header source the hosts and both
commands check proofs against. Nothing it mines is money. `borg org ...`
runs the borg command with the organisation's borg home, and `bs org ...`
the bsecret command with the organisation's bsecret home; each identity has
one of each.

The images are `ghcr.io/lightwebinc/bsecret`, `bsecret-host` and
`bsecret-devchain`, and borg's command image `ghcr.io/lightwebinc/borg`. To
build this repository's from a checkout instead of pulling them: `make
docker-build` and `make docker-build-host BORG_HOST_IMAGE=<borg's host
image>`.

## 2. An organisation and three members, and a home of each for bsecret

```console
$ borg org init | tee org.txt && borg org fund
$ for m in alice bob carol; do borg $m init | tee $m.txt; done
$ key() { sed -n 's/^identity *//p' $1; }
$ ORG=$(key org.txt) ALICE=$(key alice.txt) BOB=$(key bob.txt) CAROL=$(key carol.txt)
$ for m in org alice bob carol; do bs $m init -borg /home/nonroot/.borg/$m; done
created /home/nonroot/.bsecret/org around the identity in /home/nonroot/.borg/org/identity.json
identity     02c6…9a1e
fund address n1Qx…7Wd (regtest)
...
$ bs org fund
$ bs payee init
$ bs auditor init && bs auditor fund
```

The organisation and its members are borg's: each is an identity key in a
borg home. A vault's owner is the organisation, and its readers are the
members of one of the organisation's groups, so each bsecret home is made
**around the identity of a borg home** (`init -borg`): the same key, and
nothing else shared. The two homes keep separate coin: `bs org fund` mines
to bsecret's own fund address. The members need no coin. The payee is
host-a's, and the auditor is anyone at all: it is funded only to pay for
the priced audit later.

## 3. A hall, a crypt, the payee key

```console
$ borg org hall new example | tee hall.txt
hall  example_qzxkvbmwtr
topic tm_borg_example_qzxkvbmwtr
host  BORG_HALLS=example_qzxkvbmwtr
$ bs org crypt new example | tee crypt.txt
crypt example_hmqzvtkwrx
topic tm_bsecret_example_hmqzvtkwrx
host  BSECRET_CRYPTS=example_hmqzvtkwrx
$ sed -n 's/^host *//p' hall.txt crypt.txt > .env
$ echo "BSECRET_ORG=$ORG" >> .env
$ bs payee payee key -out - >> .env
```

A hall is where borg's groups live and a crypt is where vaults live; each
name gets a random suffix, so nobody else's shares its topic. `.env` hands
both to the hosts and to the commands, the organisation's key to the
readers, and the payee key to host-a.

## 4. Start two hosts

```console
$ docker compose up -d
$ bs org doctor
...
mode        unicast: every object to each of 2 host(s); a carrier published once 2 take it (quorum all), a token or sweep once all do
host        http://host-a:8080 answering
host        http://host-b:8080 answering
paid host   http://host-a:8090 serves terms (4 priced class(es))
```

Each host loads the borg module and the bsecret module. The first start
takes a few seconds while MySQL initialises; run `doctor` again until both
hosts answer.

## 5. The organisation, a group, and the signer key

```console
$ borg org org create 'Example Organisation' -member $ALICE -member $BOB -member $CAROL
$ borg org group create engineering -member $ALICE -member $BOB -member $CAROL
group   5a0c4d…9d12
name    engineering
seq     0 3f9a…c410 epoch 0, 3 member(s), wrapped to each
$ borg org org signer
signer  03d1…77c2
```

borg issued each member a grant, created the group with a random epoch key,
and wrapped the key to each member. `org signer` makes the organisation's
own signer key a member of every group, so that the organisation's tooling
holds each epoch's key the way a member does: bsecret opens it from that
wrap, and keeps no epoch key itself.

## 6. A vault on the group, and three secrets

```console
$ bs org vault create engineering -name ops | tee vault.txt
vault   7b1e…04aa
name    ops
crypt   example_hmqzvtkwrx
group   5a0c4d…9d12 in hall example_qzxkvbmwtr
epoch   0
anchor  version
labels  confidential,internal,public,restricted
token   seq 0 9c41…e2d0 mined at height 912
$ VAULT=$(sed -n 's/^vault *//p' vault.txt)
$ printf 'hunter2' | bs org put db/password
secret  db/password version 1 label confidential epoch 0: carrier 41f0…b7a3 (created)
token   seq 1 0e6d…58c1 mined at height 914: 1 secret(s), 0 stale, epoch 0
$ printf 'tok-1' | bs org put api/token
$ printf 'KEY' | bs org put tls/key
```

The vault is a chain of mined tokens bound to the group for good. Each
`put` drew a content key of its own, sealed the value, wrapped the key to
the owner's wallet and under the group's epoch 0 key, published the
carrier to both hosts, and listed the version in the vault's next token. A
value is read from standard input, never from an argument.

## 7. Every member reads

```console
$ bs alice get db/password
hunter2
vault   7b1e…04aa ops seq 3: settled at epoch 0
latest  seq 3 is the latest: its output is unspent per the node
secret  db/password version 1 label confidential epoch 0, read as a member: anchored, current
$ bs alice list
api/token  version 1 label confidential epoch 0
db/password  version 1 label confidential epoch 0
tls/key  version 1 label confidential epoch 0
host http://host-a:8080: 3 secret(s), the set's root reproduced
host http://host-b:8080: 3 secret(s), the set's root reproduced
```

`get` walked the vault's chain from its first token at both hosts, checked
every token against the headers, folded it, checked that the set holds
this version, checked the ciphertext's hash, opened alice's wrap of epoch 0
from borg, opened the content key's wrap under it, checked the key against
its commitment, and only then decrypted. The value goes to standard output
(it is a pipe here; on a terminal it is written only with `-show`), and
everything else to standard error. Bob and carol read the same.

## 8. Revoke bob

```console
$ printf 'correct horse' | bs org rotate -check -set db/password=- -same-all
ready   3 secret(s) owe a re-keying or a retirement (were the group to begin a new epoch now), and each has a choice: a revoke can be finished in 1 token(s)
$ borg org org remove $BOB -group engineering
group   5a0c4d…9d12 seq 2 af36…6acd epoch 1 (a new epoch: a fresh key, wrapped to every member)
$ bs alice get db/password > /dev/null
vault   7b1e…04aa ops seq 3: BEHIND: it acknowledges epoch 0 and the group is at epoch 1
secret  db/password version 1 label confidential epoch 0, read as a member: anchored, EXPOSED: keyed under epoch 0 and the group is at epoch 1, so a key the group has since removed or rotated away from opens it
$ printf 'correct horse' | bs org rotate -set db/password=- -same-all
epoch   1 acknowledged: the group began it at height 917 (a removal)
rekeyed api/token: the same value under epoch 1
rekeyed db/password: a new value under epoch 1
rekeyed tls/key: the same value under epoch 1
token   seq 4 5d77…90be mined at height 918: 3 secret(s), 0 stale, epoch 1
swept   3 version(s) keyed under epochs that have ended, or never listed: retracted at every honest host
vault   7b1e…04aa settled at epoch 1
$ bs alice get db/password
correct horse
$ bs bob get db/password
bsecret: undecryptable: this key holds no key of epoch 1, the epoch the record names: ...
$ echo $?
1
```

A revoke has three parts. The removal is borg's: it begins epoch 1, whose
key bob never receives. Until the vault acknowledges it, every reader
reports the vault **behind** and its values **exposed**, and the owner's
tooling builds nothing else. `rotate` then acknowledges the epoch and
re-keys: every secret needs a new value (`-set`), an explicit same-value
re-keying (`-same`, or `-same-all`) or a retirement (`-retire`), because a
re-keyed credential that keeps its old value is still known to bob.
`rotate -check`, before the removal, says whether the choices cover the
vault. From the acknowledgement on, every host refuses anything else on
the vault's chain until nothing is stale. The old versions are swept, so
the hosts stop answering what bob can still open; a copy he kept stays his.

## 9. Retire a secret

```console
$ bs org retire api/token
retired api/token
token   seq 5 77c0…1e3f mined at height 920: 2 secret(s), 0 stale, epoch 1
swept   1 version(s): retracted at every honest host
```

## 10. The audit, and the payee

```console
$ bs auditor terms
service ls_bsecret, terms 1
history        5 sat a question
history-after  5 sat a question
audit          20 sat a question
audit-after    20 sat a question
$ bs auditor audit
paid 20 sat to 0268…a450 in 9ade…7f2e for audit, recorded by the host for its payee to settle
vault   7b1e…04aa ops
owner   02c6…9a1e
...
token   seq 4 5d77…90be height 918 epoch 1 +0 ~3 -0: 3 secret(s), 0 stale: consistent
token   seq 5 77c0…1e3f height 920 epoch 1 +0 ~0 -1: 2 secret(s), 0 stale: consistent
epoch   1 began at height 917 (a member removed): acknowledged at height 918, settled at height 918
window  epoch 1: 1 block(s) from the block that began it to the token after which nothing was listed under an earlier epoch
secret  41c2…9f0e re-keyed at seq 4, height 918: listed under epoch 0 until then, 1 block(s) exposed
...
ends    seq 5 77c0…1e3f height 920: the audit covers nothing after it; the trail's last token is unspent per the node: it is the vault's latest
audit   OK: 6 token(s) mined, the owner's, linked from the first, lawful, consistent and keyed to the group
$ bs nobody -org $ORG -vault $VAULT audit -free
$ bs payee payee settle /var/lib/bsecret-a/payments.jsonl
1 payment(s) settled, 20 sat; 0 settled before; 0 not settled; 0 refused (0 before); pool 1 output(s), 20 sat
```

The auditor holds no key and reads no secret. It asked host-a's terms route
for the vault's whole chain over BRC-104; host-a answered 402 with its
price, the command paid it (BRC-105) and asked again. It then checked every
token against the headers, and against the group's chain, and derived the
**exposure window**: how many blocks passed between the removal and the
token after which nothing was listed under an epoch bob held. `audit -free`
reads the same tokens one at a time through the free class, with no home
and no coin (`nobody` is a home that does not exist). `payee settle` took
the payment into the payee's wallet: checked, broadcast, mined, pooled.

## 11. Do the hosts agree?

```console
$ bs alice fill
filled  0 object(s) at 0 host(s)
$ bs alice due
vault   7b1e…04aa ops seq 5: settled at epoch 1
nothing is due
```

`fill` compared what the two hosts answer (the vault's chain, its set's
carriers, the sweeps) and found nothing to copy. Had host-b been down while
the owner published, every reading command would say `DISAGREES`, and
`fill` would replay each object to it from host-a's answers, verified
first: anyone can run it, and it needs no coin.

## 12. Clean up

```console
$ docker compose --profile cli down -v
```

## On a real network

- **The chain.** Point `asset`, `settle` and `header_url` at a node, a
  settlement leg and a header source you trust, set `network`, leave
  `delay` at its default of 60 seconds, and fund the owner's home with
  `bsecret fund -txid` from a payment to its fund address (docs/usage.md).
  Every vault token and sweep is then a mined transaction of a few hundred
  bytes, and every secret rides a funding output.
- **The plane.** With a multicast plane, set `mode = plane` and `facade`:
  each carrier is submitted once and every subscribed host receives it;
  tokens and sweeps also go to every host named.
- **Hosts.** A host is the `bsecret-host` image, or the module on any
  reference overlay host (docs/host.md). The hall's hosts may be other
  hosts than the crypt's: name them in `hall_hosts`.
- **Members.** A member's home needs `hosts`, `header_url`, `crypt`, `org`,
  and `asset` to know that what it read is the latest; no coin.
- **A second home.** A home made on another machine with `bsecret init
  -from identity.json` rebuilds the owner's record from the hosts with
  `bsecret sync`.
- **Next.** [docs/user-guide.md](docs/user-guide.md) explains the concepts
  and the day-to-day use; [docs/usage.md](docs/usage.md) every command and
  setting; [docs/limits.md](docs/limits.md) every default and cap.
