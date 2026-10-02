# Limits

What an owner publishes, how fast, and what a host answers are bounded twice.
The record bounds every reader accepts ([spec.md](spec.md) section 17) are
protocol and sit above everything here. The limits below are policy:
recommended defaults and caps for the owner's tooling, members' clients and
hosts. None of them is a wire format, and a later version may change any of
them without a new record version. Where a row's cap says "the record bound"
or "spec", the cap is the contract's and only the default is policy.

A **hard cap** is refused by the client before anything is sent. A
**recommendation** passed is a warning, and the command goes on. A **host**
limit is the host operator's; a client cannot change it.

## Measured sizes

Sizes are what `internal/limits` builds and measures (`go test -v
./internal/limits`, which fails if a row below moves): real carriers minted
from a funding tree, and vault tokens of the real shape with a parent of the
same shape (the predecessor input is a stand-in of the right length), each
with a Merkle path of depth 16. A packet is 1128 bytes of object on the plane
at the 1280-byte IPv6 minimum MTU.

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

A secret's record is about 500 bytes plus its ciphertext; a payload is padded
to a multiple of 256 bytes, so a short credential is a 272-byte ciphertext. A
carrier's BEEF carries its whole funding tree, about 49 bytes an output: on
a tree of 1000 outputs a 32-byte secret is 50862 bytes (46 packets) and a
16000-byte one 66732 (60 packets), and a host stores that BEEF. The largest
token, 64 created, 64 updated and 64 retired after another such, is 33687
bytes (30 packets). A token's BEEF carries its parent, which is the token before it: a run of large
tokens costs each one twice.

## The table

### The vault

| Limit | Default | Hard cap | Why | Plane and unicast |
| --- | --- | --- | --- | --- |
| Secrets in a vault | as needed | 4096 (the record bound) | Every secret is re-keyed after every removal from the vault's group, 64 a block at most | Warns above 256: a removal then takes more than 4 blocks to settle even at 64 a token |
| Changes per transition (`create`, `update`, `retire`) | as needed | 64 each (the record bound) | A larger change is several tokens, one block apart | Plane warns above 16 in all, except while the vault is in debt: a re-keying after a removal uses the full 64, because every block it takes is a block the removed member can still read |
| Transitions per vault | one at a time | one a block | Each token spends the one before it, mined | Same |
| Vaults of an owner | as needed | none in the records; a client reads 256 pages of 64 a host | Each vault is its own chain; vaults do not slow each other | Same |
| Inline ciphertext | up to 16384 bytes | 16384 (the record bound) | A larger secret is found by its hash | Plane warns above 4096 bytes of value (7 packets) |
| Ciphertext a reader fetches by hash | 16 MiB | the reader's setting; 2^27 bytes (the record bound) | A record is a fetch instruction; a reader bounds it. A read holds the ciphertext and the plaintext in memory at once | Not on the plane |
| Padding block | 256 bytes | a writer's | A ciphertext's length then says little about a short value's | Same |
| Segment size | 16384 bytes | 16 to 1048576 (the record bound) | An inline secret is one segment | Same |
| Label set | `confidential`, `internal`, `public`, `restricted` | 16 labels (the record bound) | Fixed at the vault's first token | Same |
| Anchor mode | per version | fixed at the first token | The interval mode is for machine-rotated credentials, and says so to every reader | Same |
| Propagation delay before publishing a mined token or sweep | 60 s after its block is in the publisher's headers | 0 s to 10 min | A host whose headers lack the block refuses it, and the plane does not deliver it again | Plane and unicast; the publisher then confirms by lookup and resubmits |
| Funding tree outputs | 32 | 1000 | Every carrier's BEEF carries its whole tree | Plane warns above 100 |
| Chain tree outputs | 8 | 32 | A vault's first token carries its chain tree whole | Same |
| Trees kept apart | secret and chain trees, each under its own key and basket | fixed | A chain tree's output gives a vault its identifier | Same |

### Revoking

| Limit | Default | Hard cap | Why | Plane and unicast |
| --- | --- | --- | --- | --- |
| What a revoke needs before it starts | for every secret of every vault keyed to the group: a new value, an explicit re-keying of the same value, or a retirement | fixed | A removal mined with nothing to follow it leaves every current value open to the removed member | Same |
| Time from a removal to a settled vault | about two blocks for a vault of up to 64 secrets: the group token, then the vault token; one more block per further 64 | none | The new epoch's key must be mined and wrapped before a version can be keyed under it | Same |
| Transitions while the vault is behind its group or in debt | the acknowledgement, re-keyings and retirements only | fixed | A host refuses anything else once the vault acknowledges; a reader reports a vault that does not | Same |
| Sweep of versions under ended epochs | after the vault settles | the owner may keep history instead | A swept version leaves every honest host's answers; a kept one is what a removed member can still fetch | Same |
| Sweeps in flight | one | one | A sweep is settled before the next is built | Same |

### More than one instance of an owner

| Limit | Default | Hard cap | Why | Plane and unicast |
| --- | --- | --- | --- | --- |
| Concurrent changes to one vault | one wins | one mined a block | Two transitions on one tip spend the same output; the loser catches up and builds again | Same |
| What a catch-up reads | every token of every vault from seq 0, every current record, at every host named | the reading caps below | It trusts no host: it folds each chain and reproduces each root itself | Same |
| Funding trees two instances share | none | none | A funding output answers one carrier | Same |

### Publishing and reading

| Limit | Default | Hard cap | Why | Plane and unicast |
| --- | --- | --- | --- | --- |
| Hosts named | none | 16 | A reader asks every host it names; a unicast publisher uploads every object to each | Unicast warns above 5 |
| Quorum (`quorum`) | `all` | the host count | How many hosts named must hold a carrier for it to count as published. Tokens and sweeps always need every host named | Unicast: the hosts that took it. Plane: the hosts that answer it by lookup after the facade took it |
| Confirmation of every object at every named host | on | fixed | An object the plane took can still miss a host, with nothing to show it | Plane: looked for at each host for up to 3.5 s (0.5, 1 and 2 s apart), then offered to it directly. Unicast: an answer that admits nothing is confirmed by lookup before it counts |
| Tries per submission | 4, waiting 1, 2 and 4 s | fixed | A host that fails four tries is reported missed; the object is resent by the next command | Same |
| Request timeout | 15 s | 1 s to 5 min | Bounds every request | Same |
| Answers | 8 a question; 64 tokens or 16 secret carriers a page | spec | Bounds an answer | Same |
| Pages a client reads per question | until an answer is short | 256 pages | Each page is a lookup and its verifications | Same |
| First read of a vault | the whole chain from seq 0, folded | none | Descent from the first token is the only proof a token is the vault's; afterwards a reader starts from the token it remembers | Same |
| Writer freshness (`freshness`) | 60 s | 600 s | The age of the evidence that the vault's and the group's latest tokens are unspent when a version is published; every token retakes it as it is built | Same |
| Reader freshness, for a value it acts on | taken at the read | none: a reader that keeps a value keeps its age | The same evidence, for a reader; `get -strict` refuses a value without it | Same |
| Highest verified `seq` per vault | kept | the reader's storage | A reader that keeps it refuses an older state from any host | Same |
| Price paid for one priced question (`-max-sats`) | 1000 sat | the flag | A host names its own price in the 402; a client pays no more than it was told to | Not on the plane |
| A payer's unmined payments in a row | 16 | fixed | Each payment spends the change of the last and carries it; a longer run would make every payment's BEEF grow | Not on the plane |
| Payments a payee broadcasts and awaits at once (`-in-flight`) | 16 | 64 | A run then takes about one block, however many payments there are | Not on the plane |

### The host

| Limit | Default | Hard cap | Why | Plane and unicast |
| --- | --- | --- | --- | --- |
| BEEF a host admits | 262144 bytes | host policy, at least 262144 | The largest token with its parent is about 34 KB; a carrier on a default tree is under 20 KB, on a 1000-output tree about 51 KB, and 67 KB at the inline bound | Same |
| Submissions | host policy | host policy | Funding does not bound what a key can store at a host: the value returns by sweep. A host rate-limits submissions, and may serve only the organisations it chooses | Same |
| Carriers of a vault the host holds no chain of | kept 24 hours | host policy, at least 24 hours (spec) | Any key can publish carriers for a vault that does not exist; a new vault's carriers arrive before its first token | Same |
| Sweep inputs | 1024 | host policy, at least 1024 | A sweep of a 1000-output tree | Same |
| Spends of outpoints no carrier used | 65536, oldest dropped first | host policy, at least 65536 | A sweep may arrive before the carriers it retracts | Same |
| Retention of replaced and retired versions | 31 days | host policy, at least 31 days | A reader in the middle of a change still finds what it was given; longer is what the `history` class sells, and what a removed member can still fetch | Same |
| Sessions the priced route keeps | 10000, each forgotten after 600 s idle | host policy | A handshake is unauthenticated: the store must not grow without end | Not on the plane |
| Handshakes the priced route answers | 4 a second, 8 at once; per remote address (IPv6 per /64) 1 a second, 4 at once | host policy; over it answered 429 with `Retry-After`, before any signature | The session cap bounds memory, not work; the budget bounds the signatures a flood can make a host compute | Not on the plane |
| Signed responses the priced route gives one session | 5 a second, 20 at once | host policy; over it answered 429 with `Retry-After`, with nothing signed; a signed request sent twice is refused | One handshake must not buy signatures without end | Not on the plane |
| Lookups | host policy | answered 429 with `Retry-After` | A client respects it | Same |

## Known constraint

The ciphers here take IVs a FIPS 140-only runtime refuses: BRC-369's
segments use a 12-byte IV built from the salt and the segment index, and
BRC-2's symmetric form, in the wraps and in the SDK's own `encrypt`, uses a
32-byte IV. Under Go's `GODEBUG=fips140=only`, sealing, both wraps and the
wallet's `encrypt` fail with an error. A deployment that must run in that
mode cannot write or wrap; this is a property of the two standards' IV
layouts, not a setting.
