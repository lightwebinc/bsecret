# Limits

What an owner publishes, how fast, and what a host answers are bounded twice.
The record bounds every reader accepts ([spec.md](spec.md) section 17) are
protocol and sit above everything here. The limits below are policy:
recommended defaults and caps for the owner's tooling, members' clients and
hosts, none of them a wire format or a frozen bound ([frozen.md](frozen.md)),
and a later version may change any of them without a new record version.
Where a row's cap says "the record bound" or "spec", the cap is the
contract's and only the default is policy.

A **hard cap** is refused by the client before anything is sent: exit 2,
with a message naming the setting, the limit and why, for example

```text
bsecret: tree_count 1200 is over the limit of 1000: every carrier's BEEF carries its whole funding tree (docs/limits.md)
```

A **recommendation** passed is a `warning: ...` line on standard error, and
the command goes on. A **host** limit is the host operator's, set in the
host's environment ([host.md](host.md)); a client cannot change it. The
`bsecret` command applies every row below that concerns the owner's tooling
or a reader ([usage.md](usage.md)).

Each number below is one of three kinds, and the last section says which:
**measured** (a program or a run produced it), **set** (a default or a cap
this version chooses) or **the contract's** (a record bound).

## The table

### A vault and its secrets

| Limit | Default | Hard cap | Why | Plane and unicast |
| --- | --- | --- | --- | --- |
| Value of a secret carried in its record | as needed | 16384 bytes of ciphertext (the record bound): a value of 16092 bytes with a name of 8 and a type of 10 | A credential is far smaller. A larger secret is found by its hash | Plane warns above 4096 bytes of value: its carrier then passes 7 packets |
| Value of a secret found by its hash | as needed | 67108864 bytes of payload, 2^27 of ciphertext (the record bound) | The record names the ciphertext; whoever serves it under its hash stores it (`content`) | Never on the plane: only the record is |
| Ciphertext a reader fetches by hash (`max_fetch`) | 16 MiB | 2^27 bytes (the record bound) | A record is a fetch instruction; a reader bounds it. A read holds the ciphertext and the plaintext in memory at once | Not on the plane |
| Name of a secret | as needed | 128 bytes (the record bound) | Its identifier is a hash of the vault and the name | Same |
| Secrets in a vault | as needed | 4096 (the record bound) | Every secret is re-keyed after every removal from the vault's group, 64 a block at most | Warns above 256: a removal then takes more than 4 blocks to settle even at 64 a token |
| Versions of a secret | as needed | 2^53 - 1 (the record bound) | A version number costs nothing. Each listed version is a token of the vault's chain: see the next row | Same |
| Tokens of a vault's chain (every listed version, rotation, retirement and anchor is one) | as needed | 2^53 (the record bound on `seq`) | A reader that remembers the vault asks only for what came after. A reader with no memory, and every free audit, asks each host for every token: about 15 ms a token a host, measured. The priced `audit` class answers 64 a page. Past a few thousand tokens, begin a new vault, or anchor at an interval | Same |
| Changes per transition (`create`, `update`, `retire`) | as needed | 64 each (the record bound) | A larger change is several tokens, one block apart | Plane warns above 16 in all, except while the vault is in debt: a re-keying after a removal uses the full 64, because every block it takes is a block the removed member can still read |
| Transitions per vault | one at a time | one a block | Each token spends the one before it, mined; the next is built only once the previous is proven in the tooling's own headers. Different vaults move in the same block | Same |
| Vaults of an owner | as needed | none in the records; a client reads 256 pages of 64 a host | Each vault is its own chain; vaults do not slow each other. A vault costs one chain-tree output and one mined token to begin | Same |
| Label set (`-labels`) | `confidential`, `internal`, `public`, `restricted` | 16 labels of 32 bytes (the record bound) | Fixed at the vault's first token. A label decides nothing about who reads | Same |
| Display name of a vault | drawn at random: `vault_` and ten letters | 64 bytes, one line of plain text (the record bound) | It is in every token and printed by every reader, so it is public | Same |
| Anchor mode (`-anchor`) | per version | fixed at the first token | The interval mode is for machine-rotated credentials, and says so to every reader | Same |
| Padding block | 256 bytes | a writer's | A ciphertext's length then says little about a short value's: a short credential is a 272-byte ciphertext | Same |
| Segment size | 16384 bytes | 16 to 1048576 (the record bound) | An inline secret is one segment | Same |

### The group, its members and the wraps

| Limit | Default | Hard cap | Why | Plane and unicast |
| --- | --- | --- | --- | --- |
| Group a vault is keyed to | one, for good | one (the record) | Different readers for different secrets is different vaults on different groups | Same |
| Members who read a vault | the group's | borg's: 1024 a group | A record does not grow with the group: see the next row. What grows with the members is borg's work at each removal, one wrap of the new epoch's key a remaining member | borg's own limits |
| Wraps in a secret's record | two: the owner's own, and one under the epoch's key | two (the record) | Each is 80 bytes. The epoch's key reaches the members through borg's wraps, not through the record, so a version costs the same for 3 readers or 1000 | Same |
| The organization's signer key | a member of every group a vault is keyed to (`borg org signer`, once) | fixed | It is how the owner's tooling opens each epoch's key. Without it `vault create` refuses | Same |
| Epochs a vault can be behind | any number: its next token acknowledges the group's latest | none | Everything keyed under any earlier epoch is then stale, and is re-keyed under the latest. A group that begins another epoch while a vault is re-keying makes `rotate` stop and ask for the choices again | Same |
| Crypts an owner publishes in | as needed | none | A vault lives in one crypt; a sweep is published in every crypt that holds a version it retracts | Same |
| Name of a crypt | `<name>_<suffix>` | 39 bytes: a name of at most 28 and a suffix of exactly 10 random letters | A crypt is a topic, `tm_bsecret_<crypt>`, of at most 50 bytes | Plane: one topic the hosts subscribe to |
| Crypts a host carries (`BSECRET_CRYPTS`) | the operator's list | host policy | Every `tm_bsecret_` topic of the host must be one of them | Same |

### Rotating and revoking

| Limit | Default | Hard cap | Why | Plane and unicast |
| --- | --- | --- | --- | --- |
| What a revoke needs before it starts | for every secret of the vault: a new value, an explicit re-keying of the same value, or a retirement | fixed | A removal mined with nothing to follow it leaves every current value open to the removed member. `rotate -check` says whether the choices cover the vault, before borg removes anyone | Same |
| A write while the vault is behind its group | refused by the tooling: nothing is built but the acknowledgement | fixed | Hosts cannot make an owner acknowledge ([spec.md](spec.md) section 18); the owner's own tooling, every reader and the audit are what stand against it | Same |
| A write while the vault is in debt | re-keyings and retirements of stale secrets only | fixed: every host refuses anything else (`debt`) | From the acknowledgement on, the rule is every replica's | Same |
| Time from a removal to a settled vault | about two blocks and a propagation delay for a vault of up to 64 secrets: the group's token, borg's wraps, then the vault's token; one more block per further 64 secrets. The sweep of the old versions is one block more | none | The new epoch's key must be mined and wrapped before a version can be keyed under it | Same |
| How often a secret can be given a new value, per-version vault | one version a block a vault | one a block | Each version is listed by a token | Same |
| How often a secret can be given a new value, interval vault | as fast as the owner publishes (`put -defer`) | 64 unlisted versions in a row before a reader stops following them | An unlisted version waits for no block. `anchor` lists the latest of each secret in one token: run it at least once per 64 versions of any one secret, and no more often than a block | Same |
| Rotation a secret schedules for itself (`-rotate-every`) | none | none | `due` reports it (exit 3) once elapsed. Set it no shorter than a few blocks in a per-version vault | Same |
| Sweep of versions under ended epochs | after the vault settles | the owner may keep history instead (`-keep`) | A swept version leaves every honest host's answers; a kept one is what a removed member can still fetch | Same |
| Sweeps in flight per home | one | one | A sweep is persisted, settled and waited for before the next is built, so no output is swept twice | Same |
| Sweeps per rotation or retirement | one per funding tree the retracted versions sit on | one a block | A sweep spends outputs of one tree | Same |
| Sweeps per `kill` | one per secret tree the home holds, every output | one a block | A tree at the cap of 1000 outputs is within every host's floor of 1024 sweep inputs | Same |
| Crypts a sweep is published in | every crypt holding a version it retracts | none | A funding tree is the identity's; a host learns of a spend only from a sweep in its own crypt's topic | Same |
| Outputs the chain already shows spent | left out of the sweep; the spender, once mined, is taken as their sweep | none | A sweep naming a spent output is refused whole, for good. One node question an output | Same |

### More than one home of an owner

| Limit | Default | Hard cap | Why | Plane and unicast |
| --- | --- | --- | --- | --- |
| Concurrent changes to one vault | one wins | one mined a block | Two transitions on one tip spend the same output; the loser is discarded (exit 1, `lost`), catches up with `sync` and builds again | Same |
| What a catch-up reads (`sync`) | every token of every vault from seq 0, every current record and, in an interval vault, every unlisted version that links to it, at every host named | the reading caps below | It trusts no host: it folds each chain and reproduces each root itself | Same |
| Funding trees two homes share | none | none | A funding output answers one carrier. A home made with `init` mints its own trees | Same |
| Commands using one home at once | one | one | A second is refused (exit 2), a read too: it would read with no memory of what the home verified | Same |

### Publishing and reading

| Limit | Default | Hard cap | Why | Plane and unicast |
| --- | --- | --- | --- | --- |
| Hosts named (`hosts`, `hall_hosts`) | none | 16 each | A reader asks every host it names; a unicast publisher uploads every object to each | Unicast warns above 5: past that the plane is what removes the cost |
| Quorum (`quorum`) | `all` | the host count | How many hosts named must hold a carrier for it to count as published. Tokens and sweeps always need every host named | Unicast: the hosts that took it; warns below a majority. Plane: the hosts that answer it by lookup after the facade took it |
| Propagation delay before publishing a mined token or sweep (`delay`) | 60 s after its block is in the publisher's headers | 0 s to 10 min | A host whose headers lack the block refuses it, and the plane does not deliver it again | Plane and unicast; the publisher then confirms by lookup and resubmits |
| Confirmation of every object at every named host | on | fixed | An object the plane took can still miss a host, with nothing to show it | Plane: looked for at each host for up to 3.5 s (0.5, 1 and 2 s apart), then offered to it directly. Unicast: an answer that admits nothing is confirmed by lookup before it counts |
| Tries per submission | 4, waiting 1, 2 and 4 s | fixed | A host that fails four tries is reported missed; the object stays persisted and the next command resends it | Plane: the facade, and each host named for mined objects; unicast: each host |
| Request timeout (`timeout`) | 15 s | 1 s to 5 min | Bounds every request | Same |
| Wait for a token, a sweep or a tree to mine | 10 min | fixed | Past the wait it stays persisted and the next command waits again | Same |
| Funding tree outputs (`tree_count`) | 32 | 1000 | Every carrier's BEEF carries its whole tree, about 49 bytes an output; within bcommon's cap of 1023 funding outputs a tree (`mint.MaxFundingOutputs`) | Plane warns above 100 |
| Chain tree outputs (`chain_tree_count`) | 8 | 32 | A vault's first token carries its chain tree whole | Same |
| Trees kept apart | secret and chain trees, each under its own key and basket | fixed | A chain tree's output gives a vault its identifier | Same |
| Tree minted ahead | one secret tree, when 4 outputs are left (half the tree when it has 4 or fewer) | one at a time | The next tree is settled while the last outputs are spent, so a version seldom waits a block for a tree | Same |
| `object_bound` | 1048576 | 8388608 | BRC-149: 1 MiB on the open path, 8 MiB on an authenticated one; no plane admits more | Plane only |
| Answers | 8 a question; 64 tokens or 16 secret carriers a page | spec | Bounds an answer | Same |
| Pages a client reads per question | until an answer is short | 256 pages, 128 outputs a page, 256 MiB in all | Each page is a lookup and its verifications. A page's cursor comes only from an output that verified as the vault's or the owner's own | Same |
| One lookup answer | read whole | 16 MiB | A full page of the largest carriers fits several times over; a host that sends more is not read | Same |
| Object a reader takes | as answered | 1 MiB | No bsecret object is near it | Same |
| Unlisted versions a reader follows above a listed one (interval vaults) | every one answered in a row | 64 | Each is asked for only once the one before it was answered: a version a carrier claims never sets how far a reader walks. Past 64 the reader takes the 64th and says a later one exists | Same |
| First read of a vault | the whole chain from seq 0, folded | none | Descent from the first token is the only proof a token is the vault's; afterwards a reader starts from the token it remembers | Same |
| Rollback memory of a reader | the latest token of each vault and of each vault's group this home verified | the reader's storage | A reader that keeps it refuses an older state from any host. A reader with no home has none: it relies on `WITHHELD`, on the node, and on naming more than one host | Same |
| Writer freshness (`freshness`) | 60 s | 600 s | The age of the evidence that the vault's and the group's latest tokens are unspent when a version is published; every token retakes it as it is built | Same |
| Reader freshness, for a value it acts on | taken at the read | none: a reader that keeps a value keeps its age | The same evidence, for a reader; `get -strict` refuses a value without it | Same |
| `serve`'s walk (`-interval`) | 1 min | at least 1 s | Each walk asks every host for the vault's new tokens and every secret of its set, and a spend source for the latest; a value served is as old as the walk that read it (`read_at`) | Same |
| `serve`'s walks on request (`POST /refresh`) | at most one in 5 s | fixed | A caller cannot make the daemon ask the hosts and the spend source without bound | Same |
| What `fill` copies | every token, carrier of the set and sweep a host lacks and another answered | the reading caps | Each copy is one submit and one lookup at the host that lacks it. A first token also needs its chain tree: from the owner's home when `fill` runs there, else from the node; see the known limits | Off the plane, or a host a publisher missed |

### Coins

| Limit | Default | Hard cap | Why | Plane and unicast |
| --- | --- | --- | --- | --- |
| Coins an owner's home needs | one | none | A first vault from one coin costs one more block: the next row | Same |
| A first token's fee | never the chain tree's own change: another coin, or that change first paid to the home's own fund key in a mined transaction | fixed | A first token spends exactly one output of its chain tree; every host refuses a second input from it (`token-input`) | Same |
| Wait for a fee coin | up to 10 min, when the only coin is held by a tree minted ahead or is change not yet mined | fixed | A tree minted ahead takes the last proven coin and gives its change back when it settles; the change is spendable once mined | Same |
| Coin taken by a run that stopped before it recorded the spend | found by the next command from the pool the state recorded, and put back when the node shows it unspent | none | The pool and the state are two files; the state records the pool before a coin leaves it | Same |
| Funding tree signed by a run that stopped before it adopted the tree | recorded with its kind and its coin before it is sent; the next command that publishes asks the node and adopts the tree, or puts the coin back | none | The pool is saved without the coin when the tree is signed, and the tree is adopted only once it is sent, or, minted ahead, at the switch; the record (`pendingTrees`) spans the gap ([usage.md](usage.md)) | Same |
| Record of a tree the node does not know, whose coin is unspent | kept for one more command after the coin went back, then dropped | fixed | The node's view is a moment's view: see the known limits | Same |
| Funding tree paid through a BRC-100 wallet (bcommon's `Trees.Fund`) | not used: the home pays for its trees from its pool | open | See the known limits | Same |

### Paying and settling

| Limit | Default | Hard cap | Why | Plane and unicast |
| --- | --- | --- | --- | --- |
| Priced classes | none: a host chooses | `history` and `audit`, each with its `-after` form (spec) | Everything a priced class answers is also reachable free, one item at a time | Not on the plane: the terms route is HTTP |
| Page of the `audit` class | 64 tokens | spec | One payment buys one page. A trail of `n` tokens is `ceil(n / 64)` pages | Not on the plane |
| Page of the `history` class | 16 carriers | spec | Every version of one secret the host still holds | Not on the plane |
| Price paid for one priced question (`-max-sats`) | 1000 sat | the flag | A host names its own price in the 402; a client pays no more than it was told to, and pays for one question once | Not on the plane |
| Paid in all by one `audit` (`-budget`) | 16000 sat | the flag | A host sets its own pages as well as its prices; the command bounds what they add up to. A page the budget cannot pay ends the command (exit 2) with what was paid spent, and a page that repeats tokens of an earlier one is refused | Not on the plane |
| Payments for one priced question | one | one | A host that asks for a second payment is refused (exit 1) | Not on the plane |
| A payment that was sent and not answered | kept as made: recorded before it is sent, its coin never returned to the pool | fixed | The host holds a valid transaction that spends the coin; a coin given back would be spent twice | Not on the plane |
| A payer's unmined payments in a row | each spends the change of the last | 16 | Each payment carries the unmined ones under it; a longer run would make every payment's BEEF grow. Past 16 the payer waits for a block | Not on the plane |
| Payments a payee broadcasts and awaits at once (`-in-flight`) | 16 | 1 to 64 | A run then takes about one block, however many payments there are | Not on the plane |
| Wait for a payment to mine | 10 min | fixed | Past it the payment is `NOT SETTLED` and tried again next run. One whose input is spent elsewhere is refused at once, recorded, and never tried again | Not on the plane |

### Hosts

| Limit | Default | Hard cap | Why | Plane and unicast |
| --- | --- | --- | --- | --- |
| BEEF a host admits (`BSECRET_MAX_BEEF`) | 262144 bytes | at least 262144 (a floor, never lowered) | The largest token with its parent is about 34 KB; a carrier on a default tree is under 20 KB, on a 1000-output tree about 51 KB, and 67 KB at the inline bound | Same |
| Sweep inputs (`BSECRET_MAX_SWEEP_INPUTS`) | 1024 | at least 1024 | A sweep of a whole 1000-output tree is admitted | Same |
| Tokens kept per seq of a vault | 8: rooted tokens first, then the lowest txids | spec | Bounds what a fork or a stranger's tokens can make a host keep | Same |
| Commitments kept per funding outpoint | the winner and 8 superseded carriers; the rest are counted | spec | Evidence that an output was used twice, bounded | Same |
| Outpoint rows (`bsecret-rows.jsonl` in `BSECRET_STATE_DIR`) | kept for the host's life | none | It is what keeps a retracted carrier retracted, and a dropped winner dropped, across restarts; back it up ([host.md](host.md)) | Same |
| Spends of outpoints no carrier used (`BSECRET_SPEND_TABLE`) | 65536, oldest dropped first | at least 65536 | A sweep may arrive before the carriers it retracts. A sweep pushed out before its carrier arrived does not retract it at this host | Same |
| Retention of a replaced, retired or unlisted version (`BSECRET_RETENTION_DAYS`) | 31 days after the host first saw what replaced it | at least 31 days | A reader in the middle of a change still finds what it was given; longer is what the `history` class sells, and what a removed member can still fetch | Same |
| Retention of a carrier of a vault the host holds no chain of (`BSECRET_UNHELD_HOURS`) | 24 hours | at least 24 hours (spec) | Any key can publish carriers for a vault that does not exist; a new vault's carriers arrive before its first token | Same |
| A listed version the set still holds | kept for as long as it does | none | It is the vault's current state | Same |
| Tokens and sweeps | kept for the host's life | none | The chain is the audit trail | Same |
| Submissions | host policy | host policy | Funding does not bound what a key can store at a host: the value returns by sweep. A host rate-limits submissions, and may serve only the organizations it chooses | Same |
| BRC-104 sessions the terms route keeps (`BSECRET_SESSIONS`, `BSECRET_SESSION_TTL`) | 10000, each forgotten after 600 s idle | host policy | A handshake is unauthenticated: the store must not grow without end | Not on the plane |
| BRC-104 handshakes the terms route answers (`BSECRET_HANDSHAKES_PER_SEC`, `BSECRET_HANDSHAKE_BURST`, `BSECRET_HANDSHAKES_PER_ADDR_PER_SEC`, `BSECRET_HANDSHAKE_ADDR_BURST`) | 4 a second, 8 at once; per remote address (IPv6 per /64) 1 a second, 4 at once | host policy; over it answered 429 with `Retry-After`, before any signature | The session cap bounds memory, not work; the budget bounds the signatures a flood can make a host compute | Not on the plane |
| Signed responses one session is given (`BSECRET_RESPONSES_PER_SEC`, `BSECRET_RESPONSE_BURST`) | 5 a second, 20 at once | host policy; over it answered 429 with `Retry-After`, with nothing signed; a signed request sent twice is refused | One handshake must not buy signatures without end | Not on the plane |
| Lookups | host policy | answered 429 with `Retry-After` | Lookup is an unauthenticated surface; a client respects it | Same |

## Known limits

These are not settings. Each is something the tooling or the contract does
not do, stated so that nobody finds it by accident.

1. **A first token a host lost is repaired from the owner's home, or from
   the node.** `fill` replays a token in the BEEF a host admits: the token
   and its parent. A first token's parent is its chain tree, which no host
   keeps and no host answers. Run in the owner's home, `fill` takes the tree
   from the home's own record, which keeps every tree it minted with its
   proof, and checks it as it would the node's answer; a second home
   records the tree when `sync` first takes the vault's chain. Run anywhere
   else, or in a home made by `sync` before v0.1.1 (which has no record),
   it reads the tree from the node (`chain`), with its proof. A node that
   has pruned the chain tree cannot serve it: `fill` then says so for seq 0
   (`cannot assemble its BEEF: the chain tree ...`, exit 3, asking for the
   fill to be run from the owner's home), and whatever it replays above
   seq 0 that host holds as pending and never answers as the vault's
   chain, since a host roots a chain at its first token. Hosts do not keep
   chain trees: that would change the host contract.
2. **A home wedged by a first token no host admits is repaired by hand.**
   A client older than the fix for a first token's fee could mine, from a
   home with one coin, a first token with two inputs from its chain tree.
   Every host refuses it (`token-input`), the vault never exists at a host,
   and the home then refuses every writing command at that vault. No
   client since can make one: every token is held to the host's rule on
   its inputs before it is sent. A home already in that state is repaired
   by removing the vault from `state.json`, with the file kept aside; the
   mined token is an orphan nobody holds.
3. **Tree recovery leaves one window.** The node's view is a moment's
   view. A funding tree handed to the settlement leg an instant before a
   run stopped can reach the node after the next command asked about it.
   That command puts the fee coin back and keeps the record for one more
   command; a tree that lands in between is adopted by that next command,
   which takes the coin, now spent, out of the pool. A tree that lands
   only after two commands found nothing is not recovered: its outputs are
   lost to the home (32 satoshis and the tree's fee, on a default tree),
   its change stays out of the pool until `fund -txid` imports the tree,
   and the transaction that next takes the coin is refused and built
   again. While a returned coin is in the pool and the tree lands, a
   transaction that takes the coin is refused the same way; nothing is
   lost by that. A command that restarts at once after a crash makes both
   more likely than one that follows a moment later.
4. **A tree a wallet funded is not covered.** The home pays for its trees
   from its own pool, and everything above is about such trees. A funding
   tree paid through a BRC-100 wallet (bcommon's `Trees.Fund`) is signed
   and broadcast by that wallet inside one call: nothing can be recorded
   before the broadcast, no pool coin exists to put back, and a run that
   stopped after the broadcast leaves a tree only that wallet knows.
   bsecret does not fund trees that way.
5. **A mis-keyed wrap is invisible to the audit.** A version that names
   the new epoch while its content key is wrapped under an old epoch's key
   passes every host, index and audit check: nothing that holds no key can
   tell which key a wrap is under. The members of the new epoch see it at
   once, as a version they cannot open (`undecryptable`, naming the owner),
   and the old epoch's members can open it if they break the rule and try
   their old key. The owner's tooling never writes one. An audit proves
   what the owner signed; that a wrap is under the epoch it names is
   checked by the members who open it ([spec.md](spec.md) sections 6.3 and
   9.3).
6. **A reader after the kill switch sees an absence.** Once every funding
   output is swept and the hosts have dropped the carriers, a read exits 3
   (`no host answers its carrier`), not 1 (`retracted`): a reader cannot
   name the funding outpoint of a carrier no host answers. The sweep is
   answered by the `sweep` class to anyone who knows the outpoint.
7. **Nothing forces the acknowledgement.** An owner's own tooling refuses
   to write while the vault is behind its group; a host cannot. See
   [spec.md](spec.md) section 18 for this and for everything else the
   contract does not do.

8. **A host answers anyone who reaches it, and the chain answers
   everyone.** The free lookup classes need no key, so any client that
   reaches a host can walk a vault's chain and fetch its carriers; a host
   has no setting that limits its answers to chosen organizations or to a
   group's members. An operator who wants that runs the crypt's hosts
   behind its own network controls ([user-guide.md](user-guide.md) section
   12). A vault's tokens are mined, so what they carry
   ([spec.md](spec.md) section 3) is readable from the chain with no host.
9. **Submissions are bounded by the operator.** Any key can publish
   carriers for a vault that does not exist, kept for
   `BSECRET_UNHELD_HOURS`, and funding does not bound what a key stores,
   since a sweep returns the value. The module sets no submission rate of
   its own: a host operator sets one in front of the host
   ([host.md](host.md)).

## Where the numbers come from

**Sizes, measured.** `internal/limits` builds real objects with bcommon
(`go test -v ./internal/limits`, which fails if a row below moves):
carriers minted from a mined funding tree (Atomic BEEF), and vault tokens of
the real shape with a parent of the same shape (the predecessor input is a
stand-in of the right length), each proof a Merkle path of 16 levels (a
block of about 65,000 transactions). A packet carries 1128 bytes of object
(the IPv6 minimum MTU of 1280 bytes less the IPv6, UDP and object fragment
headers).

| Object | Record | BEEF | Packets |
| --- | --- | --- | --- |
| Secret, 32-byte value, tree of 8 | 778 | 2252 | 2 |
| Secret, 32-byte value, tree of 32 | 778 | 3428 | 4 |
| Secret, 32-byte value, tree of 100 | 778 | 6759 | 6 |
| Secret, 1024-byte value inline, tree of 32 | 1802 | 4451 | 4 |
| Secret, 4096-byte value inline, tree of 32 | 4874 | 7523 | 7 |
| Secret, 16000-byte value inline, tree of 32 | 16650 | 19300 | 18 |
| Secret, 1 MiB value not carried, tree of 32 | 504 | 3154 | 3 |
| Vault token, 1 updated | 437 | 2913 | 3 |
| Vault token, 8 updated | 1165 | 3641 | 4 |
| Vault token, 16 updated | 1997 | 4473 | 4 |
| Vault token, 64 updated | 6990 | 9468 | 9 |
| Vault token, 64 created, 64 updated, 64 retired | 15824 | 18300 | 17 |
| Vault token, 16 updated, after a token of 16 updated | 1997 | 6033 | 6 |
| Vault token, 64 updated, after a token of 64 updated | 6990 | 16022 | 15 |

A secret's record is about 500 bytes plus its ciphertext; a payload is
padded to a multiple of 256 bytes, so a short credential is a 272-byte
ciphertext. The largest value that rides in its record is 16092 bytes, with
a name of 8 bytes and a type of 10: a payload of 16128 bytes, sealed as one
segment. A carrier's BEEF carries its whole funding tree, about 49 bytes an
output: on a tree of 1000 outputs a 32-byte secret is 50862 bytes (46
packets) and a 16000-byte one 66732 (60 packets), and a host stores that
BEEF. The largest token, 64 created, 64 updated and 64 retired after
another such, is 33687 bytes (30 packets). A token's BEEF carries its
parent, which is the token before it: a run of large tokens costs each one
twice. Each entry of a change list adds 104 bytes to a token.

**Costs.** Sizes measured on a test network over 121 vault tokens, 136
versions, 21 sweeps, 2 chain trees and 7 secret trees of two owners;
satoshis at the default fee policy, the network's rate of 100 satoshis per
1000 bytes with a floor of 100 a transaction and that rate as the most
paid (`mint.DefaultFees`). A transaction under 1,000 bytes pays the floor; a larger one pays the rate on
its size. A carrier is never mined and rides one funding output of 1
satoshi, which a sweep returns. The rate, the floor and a ceiling are
settings (`fee_rate`, `fee_floor`, `fee_max_rate`, `fee_max_tx`), and
`fee_source = arc` follows the broadcaster's published policy instead
([configuration.md](configuration.md)). About 10,000 satoshis (0.0001 BSV)
covers a vault, its chain tree and about ninety versions; members and free
audits need no coin.

| Operation | Mined | Bytes mined | Satoshis |
| --- | --- | --- | --- |
| A chain tree of 8 outputs (one per 8 vaults) | 1 transaction | 583 | 100, and 8 in its outputs |
| A secret tree of 32 outputs (one per 32 versions) | 1 transaction | 1760 | 176, and 32 in its outputs |
| `vault create` | the first token | 732 to 741 | 100, and 1 in the token, carried from token to token |
| `vault create`, the home's first, from one coin | also the payment to the home's own fund key | about 226, the shape of a payment | 100, the floor, once |
| `put`, `put -defer` then `anchor`, `retire`: one token | 1 token | 769 to 1054; 845 at the median | 100 to 106; 100 at the median |
| `put`: its share of a secret tree | 1/32 of a tree | 55 | 7 |
| `rotate` of `n` secrets | `ceil(n / 64)` tokens, and `n` carriers | about 770 and 104 a secret | 100 a token up to 2 secrets, then the rate on its size |
| A sweep of `k` outputs of one tree | 1 transaction | 353 to 355 for one output, and about 113 for each further one | 100, or the rate on its size over 1,000 bytes; the `k` satoshis of the outputs come back |
| `kill`, a tree of 32 | 1 sweep | 3872 | 388 |
| A paid `audit` or `history` page | the payment | 225 or 226 | the host's price, and 100, the floor: 120 a page at a price of 20 |
| A read, a free audit, `fill`, `due`, `doctor` | nothing | 0 | 0 |

So a version costs about 107 satoshis, and a vault 100 to begin, with 108
more for the chain tree every eighth vault. The walk-through in
[../QUICKSTART.md](../QUICKSTART.md)'s shape (a vault, three secrets, a
removal acknowledged and re-keyed in one token, a retirement, and four
sweeps: six tokens in all) comes to about 1,400 satoshis by this table, and
each paid page of the audit costs the auditor 120.

**Times, measured.** On the same test network, whose blocks are about 30 s
apart, with two hosts on the plane:

- **A transition** (a `put`, a `retire`'s token, an acknowledgement): one
  block and the propagation delay. With the default delay of 60 s, 83 to
  93 s. With a delay of 15 s, 26.8 to 30.8 s (30.1 at the median) over 63
  versions of one secret written one after the other, every one published
  at the first try; the version that also minted its secret tree, 62 s.
- **A removal to a settled vault**: 3 blocks from the block that mined the
  removal to the token after which nothing was listed under the old epoch,
  when the owner rotates at once.
- **A read** of three secrets and a list over two hosts, each walking what
  is new of the chain and checking every answer: 1.3 to 2.3 s in all.
- **A first read with no memory**, and a free audit: a chain of 65 tokens
  at two hosts, every token asked for, verified and folded, and the group
  read: 1.9 s, about 15 ms a token a host.
- **The paid audit**: one page of six tokens, 1.7 to 1.8 s with the
  BRC-104 handshake, the 402, the payment and the verification; two pages,
  65 tokens, 3.4 to 3.6 s.
- **A fill** of one token and one carrier at one host, confirmed: 1.4 s.
- **A host restart** to ready, restoring an index of about 250,000 outputs:
  29 to 47 s.

**Rotation against block time.** Everything a vault lists is mined, so its
pace is the chain's. On a chain with a block every ten minutes: a version
is readable as listed about ten minutes and the propagation delay after
`put` returns its carrier, and a per-version vault takes at most 144
versions a day. A removal is settled, for a vault of up to 64 secrets, two
blocks after borg's removal is mined: about twenty minutes during which
every value is still open to the removed member, and the audit says so.
A credential that must change more often than a block, or whose change
cannot wait for one, belongs in an interval vault: its versions are
published at once and anchored at an interval, at the price that an
unanchored version can be withheld or replaced without a trace in the
trail.

**Why small on the plane.** An object larger than one packet is carried as
fragments. Every lost fragment is repaired, but the whole object must be
reassembled within a fixed window, and a fragment that needs a second or
third repair round at a long round trip can land after the object was given
up. In measurements at 1 % packet loss no object of 1 or 8 packets was lost
and about 1 % of 16-packet objects were. Every bsecret object at its default
(a tree of 32, a credential of a few hundred bytes, up to 16 changes a
token) is at most 4 packets. At the bounds a full re-keying token after
another is 15, and a carrier at the inline bound 18, which is why the plane
warns well below both. A publisher confirms every object at every host
named and offers it directly to a host the plane missed, so a lost object
costs a few seconds, not a version.

**Unicast.** No fragments: a host takes each object in one HTTP request, so
a unicast publisher can use the full bounds. What grows instead is its
upload and its retries, multiplied by the host count, and a host that was
down misses what was sent meanwhile until someone runs `fill`.

**The audit's pages.** The `audit` class answers a vault's rooted tokens 64
a page, in seq order, each as the host stores it. On the test network a
token's stored BEEF was 1288 to 1395 bytes, so a full page was 89,029 bytes
of BEEF, about 300 KiB as the JSON a host answers, and a trail of 65 tokens
was two pages, of 64 and of 1. A budget that pays for the first page and
not the second stops there: the first page's payment is spent, the trail
is not complete, and the command says both (exit 2).

**The terms route.** A BRC-104 handshake costs the host a signature, on the
host's own process. On a test host 40 priced questions from fresh
identities at one address, 8 at a time, were answered in 3.5 to 7.2 s: 6
to 9 with the 402 and the rest refused 429 before any signature, and a
client that paid a moment later was answered. A signed request sent a
second time byte for byte is refused 401 with nothing signed.

**Which numbers are which.** Measured: every row of the sizes table and the
largest inline value (`internal/limits`, held by its tests); the costs
table and the times (a test network, as said). The contract's: every cap
marked "the record bound" or "spec". Set, not measured: every other default
and cap (the propagation delay, the tries and waits, the freshness bounds,
the tree sizes, the payment and settle bounds, the host budgets), and the
recommendation on the length of a vault's chain, which follows from the
measured cost of a walk.

## Known constraint

The ciphers here take IVs a FIPS 140-only runtime refuses: BRC-369's
segments use a 12-byte IV built from the salt and the segment index, and
BRC-2's symmetric form, in the wraps and in the SDK's own `encrypt`, uses a
32-byte IV. Under Go's `GODEBUG=fips140=only`, sealing, both wraps and the
wallet's `encrypt` fail with an error. A deployment that must run in that
mode cannot write or wrap; this is a property of the two standards' IV
layouts, not a setting.
