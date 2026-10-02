# Running a bsecret host

A bsecret host is an ordinary overlay host that loads the bsecret module: one
file, `host/bundle/bsecret-module.js`, which mounts the topic manager
`tm_bsecret_<name>_<suffix>` for each crypt it carries and the lookup service
`ls_bsecret` for all of them ([spec.md](spec.md) sections 10 and 11). The
module imports nothing but `@bsv/sdk` (the host's own copy) and Node's
built-ins; bcommon is inlined. It holds no key and decrypts nothing: the
reader's side of a secret is not in the file.

## Build and deploy

```console
$ (cd host && npm ci)   # once
$ make module           # writes host/bundle/bsecret-module.js
```

Copy the file into a directory beside the host's `node_modules` (for
example `<host>/modules/bsecret/bsecret-module.js`) and name it by absolute
path:

```sh
OVERLAY_TOPICS=tm_bsecret_example_crypt_hmqzvtkwrx
OVERLAY_MODULES=/srv/overlay/modules/bsecret/bsecret-module.js
BSECRET_CRYPTS=example_crypt_hmqzvtkwrx
BSECRET_STATE_DIR=/var/lib/bsecret
BSECRET_HEADERS_URL=https://headers.example.com
```

### As an image

`host/Dockerfile` adds the module to borg's host image, which is a
reference overlay host with the borg module in it, so one image carries a
crypt and the hall its vaults' groups live in:

```console
$ make docker-build-host BORG_HOST_IMAGE=<borg's host image>
```

The image's entrypoint requires `BSECRET_CRYPTS` and, when `OVERLAY_TOPICS`
and `OVERLAY_MODULES` are unset, derives them: `tm_bsecret_<crypt>` for each
crypt and the bsecret module, and, when `BORG_HALLS` is set,
`tm_borg_<hall>` for each hall and the borg module beside it. A host that
carries only crypts, with the groups' hall on other hosts, sets no
`BORG_HALLS` and loads only the bsecret module. `BSECRET_STATE_DIR` is
`/var/lib/bsecret`: mount a volume there. An unset `OVERLAY_ADMIN_TOKEN` is
replaced by a random one for the run.

The host must run with no broadcaster, and must not enable an unordered
synchronisation of unspent outputs for `tm_bsecret_` topics (spec sections
11.1 and 11.6). The module refuses to start on a host whose
`OVERLAY_SYNC_PEERS` names one: such a synchronisation never carries a
chain's spent tokens, and drops what a topic manager refuses without trying
it again. A crypt is joined by replay (below).

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `BSECRET_CRYPTS` | required | the crypt identifiers this host carries, a comma list. Every `tm_bsecret_` topic in `OVERLAY_TOPICS` must be one of them, or the module refuses to start: a bsecret topic left to the host's default manager would admit anything |
| `BSECRET_STATE_DIR` | required | an absolute directory kept for the host's life (below) |
| `BSECRET_HEADERS_URL` | `OVERLAY_CHAIN_TRACKER_URL` when it is an `http` or `https` URL | the header source admission checks proofs against, in the reference host's native shape (`/v1/root/<height>`, `/v1/tip`). Required when the host's own source is another kind |
| `BSECRET_RETENTION_DAYS` | 31 | how long a host keeps a carrier it no longer answers, where it holds the vault's chain (below). At least 31 |
| `BSECRET_UNHELD_HOURS` | 24 | the same for a carrier of a vault whose chain the host does not hold. At least 24 |
| `BSECRET_MAX_BEEF` | 262144 | the host's BEEF bound, in bytes. At least 262144 |
| `BSECRET_MAX_SWEEP_INPUTS` | 1024 | the most inputs of a sweep the host accepts. At least 1024 |
| `BSECRET_SPEND_TABLE` | 65536 | the spends of outpoints no carrier used that the host keeps (below). At least 65536 |
| `BSECRET_LISTEN` | none | `host:port` of the terms route (below) |
| `BSECRET_PRICES` | none | the classes this host prices, for example `history=5,history-after=5,audit=20,audit-after=20`. Only the four priceable classes, each priced by its own name; a price of 0 charges nothing. A class and its `-after` form are priced together or not at all: priced apart, the free one would answer every page but the first for nothing |
| `BSECRET_PAYEE_KEY` | none | the payee's private key, 64 lowercase hex characters: the terms route's BRC-104 identity and the key payments are derived from |
| `BSECRET_SESSIONS` | 10000 | the most BRC-104 sessions the terms route keeps. Past it the least recently used is forgotten |
| `BSECRET_SESSION_TTL` | 600 | seconds a BRC-104 session is kept once idle |
| `BSECRET_HANDSHAKES_PER_SEC` | 4 | BRC-104 handshakes a second the terms route answers; decimals allowed |
| `BSECRET_HANDSHAKE_BURST` | 8 | the most handshakes the terms route answers at once |
| `BSECRET_HANDSHAKES_PER_ADDR_PER_SEC` | 1 | handshakes a second one remote address is answered; decimals allowed |
| `BSECRET_HANDSHAKE_ADDR_BURST` | 4 | the most handshakes one remote address is answered at once |
| `BSECRET_RESPONSES_PER_SEC` | 5 | signed responses a second one BRC-104 session is given; decimals allowed |
| `BSECRET_RESPONSE_BURST` | 20 | the most signed responses one session is given at once |

A price needs `BSECRET_LISTEN` and `BSECRET_PAYEE_KEY`. Any mistake stops
the host before its port opens.

### The header source

The engine checks a token's own proof before the topic manager runs, but
not its parent's, and the reference host hands a module no chain tracker.
So the module reads headers itself, from the same kind of source the host
reads, and reuses a confirmed root for ten minutes. A source that does not
answer refuses a token or sweep `unmined`; the refusal is raised, so the
engine records nothing and the same object is decided again when it is
offered again. The module does not keep an object it refused: a publisher
confirms by lookup and offers it again (spec section 8.3).

## Admission

Every refusal is raised (spec section 11.1), so the engine stores nothing
for it and a later submission of the same txid is decided again: a copy
offered first in a worse BEEF cannot suppress the genuine object, and a
token refused while the host's headers lagged is admitted once they catch
up. A verdict depends on the submission's bytes and the host's headers and
on nothing else: admission never reads another topic, another record, the
group's chain or anything the topic holds. So a carrier is admitted whatever
vault and epoch it names, and a token whether or not the host holds its
predecessor. Everything across records is a status of the index, below.

`bsecret_admitted_total{kind}` counts admitted transactions (`secret`,
`vault-token`, `sweep`) and `bsecret_refused_total{reason}` every refusal by
its label.

## The index

`ls_bsecret` keeps its index in memory and rebuilds it on start from the
engine's storage and the state directory (below), whatever order storage
returns rows in. Tokens the next token spent are not among the unspent rows
the host hands a module; the module reads them back from the rows it keeps,
and failing that walks back from each held token through the input that
spends its predecessor. A token is read as the engine stores it, alone with
its proof and without its parent, so a predecessor is always the token the
host holds at `seq - 1`.

### The vault's chain

A token is **rooted** when the host holds every token from it back to the
vault's first by spends. Only rooted tokens are a vault's chain:

- `vault` and `vaults` answer rooted tokens only: every one at the highest
  `seq`, up to 8, whether or not its stored proof still verifies;
- only rooted tokens are folded into a set, and only they list a carrier;
- `audit` answers rooted tokens only, by `seq` then txid;
- a token that is not rooted is `pending` and is answered by `vault-seq`
  alone. It may be waiting for a predecessor, or it may be built on a
  transaction that was never admissible, in which case it waits for good.

Each rooted token takes the status the fold of its own branch gives it:
`consistent`, `set-mismatch`, `stale-mismatch` or `commitment-reuse`. A
`set-mismatch` or `stale-mismatch` token breaks its branch from it on: every
later token has the same status, tokens from the break on list nothing, and
the set stays that of the last token before it. A `commitment-reuse` token
does not stop the set.

After a reorganisation two rooted tokens can share a `seq`. Each is a branch,
folded on its own. The answers that use a set (`secret`, `secrets`, `label`,
`pending`) use the highest rooted token at or below which nothing broke the
fold; of two at that `seq`, the one whose proof verifies against the header
source, else the lowest txid. The choice is kept for a minute. The context of
every `secret`, `secrets` and `label` answer names the token used, by `seq`
and txid.

At most 8 tokens are kept at one `seq` of one vault: rooted tokens before
others, then the lowest txids. A token that is turned away while it is
pending stays in the engine's storage, and the index keeps its txid under
the predecessor it names: once that predecessor is rooted the token is read
back from storage and takes its place ahead of any pending one. Offering it
again would not do that, because to the engine it is a duplicate. So which
tokens are kept does not depend on the order a chain was replayed in, live
or after a restart.

### Carriers

The first that applies:

| Status | When | Answered by |
| --- | --- | --- |
| `retracted` | an admitted sweep the host holds spends its funding outpoint | no class |
| `superseded` | it is not its funding outpoint's winner, or the winner was dropped | no class |
| `mismatched` | a rooted token lists its identifier and version with another content id or commitment, or lists it under another epoch than the record's, or its label is not one of the vault's | `version`, `history` |
| `listed` | a rooted token lists it | `secret`, `secrets`, `label` when the set holds its version; `version`, `history` |
| `unlisted` | otherwise | `version`, `history`, `pending` |

`listed` and `mismatched` are taken against the branch the answer uses. No
answer carries a status: a reader computes every one itself (spec section
14). A version the set holds whose carrier the host does not hold is simply
not answered, and a reader sees the gap when it checks the root.

### One answered carrier per funding outpoint

Every funding outpoint any admitted carrier spent has a row, kept for the
host's life: its winner (the lowest commitment ever admitted on it, a
running minimum), the lowest 8 of the others, a count of the rest, whether
its winner was dropped, and the admitted sweeps that spend it. Only the
winner can be answered. The 8 others are kept as evidence that the owner
equivocated; a carrier the row does not keep is dropped at once, deleted
from storage before its admission completes, and counted once without its
commitment (a repeat of it that the engine lets through is not counted
again). Once a row's winner is
dropped by retention nothing on that outpoint is answered again, a lower
commitment that arrives later included.

`bsecret_equivocations_total` counts every carrier admitted on an outpoint
that already had one.

### The spend table

A sweep's spend of an outpoint some carrier spent joins that outpoint's row
and is kept for the host's life. A spend of any other outpoint waits in a
table of at most `BSECRET_SPEND_TABLE` outpoints, oldest dropped first: a
carrier that arrives later on a waiting outpoint is retracted at once and
the spend joins its row. A sweep whose every spend has left the table is
dropped and deleted from storage, so a chain of mined sweeps of a
stranger's own outputs costs the host the table and nothing more. This is
the one place where order matters: a sweep pushed out of the table before
its carrier arrived does not retract it here. A sweep admitted in several
crypts answers `sweep` in each.

The table is not written down. On start it is rebuilt from the sweeps the
engine's storage still holds: the unspent tombstones the host hands over,
and, read back by name, the tombstones a later admitted transaction spent
(a carrier funded from a sweep's output, say), which the rows file names
because storage no longer lists them as unspent.

### Retention

Kept for the host's life: tokens, outpoint rows and the sweeps they record.

| Carrier | Kept |
| --- | --- |
| `listed`, and the set holds its version | for as long as it does |
| `listed`, replaced or retired | `BSECRET_RETENTION_DAYS` after the host first saw the token that replaced or retired it |
| `unlisted` or `mismatched`, of a vault whose rooted chain the host holds | `BSECRET_RETENTION_DAYS` after the host first saw it |
| `unlisted` or `mismatched`, of a vault the host holds no rooted chain of | `BSECRET_UNHELD_HOURS` after the host first saw it |
| `superseded` | as an unlisted carrier of its vault |
| `retracted` | the same period after the host first saw the sweep; it is not answered meanwhile |

Retention runs hourly. A dropped carrier is deleted from storage at once
(after every admission and every retention pass); the engine's record that
its transaction was applied remains, so offered again it is a duplicate. On
a host whose storage cannot delete an output the module says so once in the
log, and what it dropped stays in storage, unanswered. Funding does not bound what a key can store at a host
(the value returns by sweep): these floors, the rows and the table do, and
a host rate-limits submissions in front of the engine.

## The state directory

- `bsecret-rows.jsonl` holds what the host keeps for its life beside the
  engine's storage: the carriers each funding outpoint's row took in, a
  count for each it turned away, every drop, every spend of such an outpoint
  by an admitted sweep, when the host first saw each token, and each held
  sweep whose tombstone a later transaction spent. Replayed in order it
  rebuilds every row. A carrier storage holds that the file does not name
  (a line lost to a crash, or a directory restored from a copy) is taken
  into its row again when it is below what the row keeps, so the winner
  stays the lowest commitment the host holds. It keeps a funding output from answering a
  second carrier and keeps retention's clocks, so it is kept for the host's
  life, backed up with the database, and never edited. Each line is flushed
  to disk before the admission it records completes. It names outpoints,
  txids and commitments, never an identity or a secret.
- `payments.jsonl` holds every payment the terms route accepted: the Atomic
  BEEF, the derivation prefix and suffix, the sender's identity key, the
  satoshis, the class and the outpoints the payment spends. The route
  answers once the line is on disk. It does not broadcast the payment.

Both files are append-only, so a copy taken while the host runs is safe: at
worst its last line is cut short, and both readers skip such a line. Any
other line of the rows file that does not parse stops the host, because a
row skipped could let a swept or superseded carrier be answered again. Copy
the directory daily beside the database backup and keep several days.
Restore it only when it is lost or damaged, never to roll the host back:
rows written after the copy are gone.

A payment is money only once it is broadcast and mined; until then the
payer can spend the same coins elsewhere. The route refuses a payment that
spends a coin an accepted payment already spent, across restarts, so two
unbroadcast transactions on one coin buy one answer and not two; it cannot
see a spend it was never shown. Settle each line promptly with
the payee wallet's BRC-100 `internalizeAction` (protocol `wallet payment`,
output 0, the remittance as written), which broadcasts it.

## The terms route

The reference host lets a module add no route of its own, so with
`BSECRET_LISTEN` set the module serves its own, beside the host:

| Route | Answer |
| --- | --- |
| `GET /ls_bsecret/terms` | the terms document of spec section 10.3; 404 when the host prices nothing |
| `POST /.well-known/auth` | the BRC-104 handshake |
| `POST /lookup` | the same BRC-24 questions as the host's `/lookup`, a `secret`, `secrets` or `label` answer's context included |

Its base URL is what the host publishes as `ls_bsecret`'s base (BRC-180
`metanet.overlays`), an origin with no path: a BRC-104 client shakes hands
at the origin's `/.well-known/auth`. A reverse proxy in front of it gives
it an origin of its own and passes the path unchanged, because a BRC-104
signature covers it.

A free question is answered with or without BRC-104. A question of a class
the host prices (`history`, `history-after`, `audit`, `audit-after`, each by
its own name) must be asked here, over BRC-104: the host's own `/lookup`
refuses it with an error that says so. Without a payment it is answered 402
with BRC-105's headers (`x-bsv-payment-version`,
`x-bsv-payment-satoshis-required`, `x-bsv-payment-derivation-prefix`); with
an `x-bsv-payment` header whose transaction's output 0 pays at least the
price to the key BRC-29 derives for the prefix, the suffix and the asker,
and which verifies against the host's headers, it is answered. One payment
buys one question, which is one page. A payment used twice is answered 409,
and so is one that spends a coin an earlier payment spent.

| Status | When |
| --- | --- |
| 400 | the question is not one class's, names a crypt the host does not carry, or the payment is malformed, pays too little or the wrong key, or does not verify |
| 401 | a priced class asked without BRC-104, a request that does not verify, or a signed request sent a second time |
| 402 | a priced class asked without a payment |
| 409 | a payment already used, or one that spends a coin an accepted payment spent |
| 429 | a handshake over the budget, or a request over its session's budget of signed responses, with `Retry-After` |
| 503 | the index is not restored yet |

### The handshake budget

A BRC-104 handshake is unauthenticated and costs the host a signature. The
route answers handshakes from a budget for the route and a budget for each
remote address (an IPv6 address by its /64), checked before the body is read
and before any signature is made, and answers 429 with `Retry-After` over
either. It keeps at most `BSECRET_SESSIONS` sessions and forgets one idle
for `BSECRET_SESSION_TTL` seconds; a client whose session went shakes hands
again. Behind a reverse proxy every client has the proxy's address, so the
per-address budget becomes a second route budget: limit by address at the
proxy.

A handshake buys a session, and every answered request on a session costs
the host another signature. So each session has its own budget of signed
responses (`BSECRET_RESPONSES_PER_SEC`, `BSECRET_RESPONSE_BURST`), taken
only by a request that verified, and a request over it is answered 429
with nothing signed. A signed request sent again byte for byte is refused
401 before anything is verified or signed: the route remembers the last
65536 requests it answered, and the session budget bounds what an older
replay can cost.

`bsecret_handshakes_total{result}` counts `accepted`, `failed`,
`limited_address` and `limited_global`; `bsecret_requests_total{result}`
counts authenticated requests refused before any signature (`replayed`,
`limited`); `bsecret_sessions` is the sessions kept; `bsecret_payments_total{result}` counts `requested`, `accepted`,
`refused` and `replayed`.

## Joining a crypt

A host that starts carrying a crypt, or that missed part of a chain, is
filled by replay (spec section 11.6). A sibling host answers each token
alone with its proof, so a replayer assembles each token's BEEF itself, the
token from `vault-seq` at `seq` and its parent from `seq - 1`, with the
library's `tokenBEEF`, and submits it; at `seq` 0 the parent is the chain
tree, which no host keeps and the publisher supplies. Tokens, carriers and
sweeps may be replayed in any order: a token ahead of its predecessor is
`pending` until the predecessor arrives.

## Metrics

Beside those above: `bsecret_token_status_total{status}` counts each token's
status once it is decided (and `pending` for each that arrived ahead of its
predecessor), and every status other than `consistent` is logged with its
crypt, owner, vault, `seq` and txid; `bsecret_retractions_total` counts
spends that retracted an outpoint; `bsecret_dropped_total{why}` counts
dropped carriers and sweeps (`evidence`, `retention`, `table`);
`bsecret_lookups_total{class}` counts questions. The gauges are
`bsecret_crypts`, `bsecret_vaults`, `bsecret_tokens`,
`bsecret_tokens_pending`, `bsecret_carriers`, `bsecret_sweeps`,
`bsecret_outpoint_rows` and `bsecret_spend_table`.

## What a host cannot tell

A host admits and answers what the contract lets an owner sign. It cannot
tell that a vault is behind its group, that a wrap is under the key of the
epoch its record names, or that a re-keyed version holds a new value (spec
sections 4.1, 6.3 and 18). Those are a reader's checks and an auditor's, and
the tests show the host answering each such record as the contract says it
does.

## Tests

`make test` runs the module's tests on the compiled tree and on the bundle:
every transaction vector through the topic manager and through the overlay
engine, every refusal label, every lookup class, the index rules, retention,
restore in any order, the terms route with a paying client, and the attacks
a review of the contract named. `make e2e REFERENCE_HOST=/path/to/host`
runs the bundle on a local reference overlay host over MySQL: it needs
Docker and a reference host directory holding its compiled `dist/index.js`
and its `node_modules`.
