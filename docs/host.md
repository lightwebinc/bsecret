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
OVERLAY_TOPICS=tm_bsecret_example_hmqzvtkwrx
OVERLAY_MODULES=/srv/overlay/modules/bsecret/bsecret-module.js
BSECRET_CRYPTS=example_hmqzvtkwrx
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
synchronization of unspent outputs for `tm_bsecret_` topics (spec sections
11.1 and 11.6). The module refuses to start on a host whose
`OVERLAY_SYNC_PEERS` names one: such a synchronization never carries a
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
| `BSECRET_PRIVATE` | none | the private crypts and the organizations each is served to: `<crypt>=<org>[,<org>...]`, entries separated by `;`, each crypt one `BSECRET_CRYPTS` carries and each organization an identity key ([below](#keeping-a-crypt-private)) |
| `BSECRET_HALL_URL` | none | the borg hosts asked who is a member of an organization's groups, a comma list of base URLs; required with `BSECRET_PRIVATE` |
| `BSECRET_MEMBER_TTL` | 60 | seconds a membership answer is kept; at least 1 |
| `BSECRET_ARCADE_URL` | none | arcade, which the host broadcasts each payment through before it answers (`POST /tx`, `GET /tx/<txid>`) |
| `BSECRET_ASSET_URL` | none | the node's asset service: the spend view of a payment's inputs and the proof of a held or watched payment. Without both URLs every payment is held until it mines |
| `BSECRET_ACCEPT_THRESHOLD_SATS` | 25000000 | the largest payment answered on the network's acceptance; above it a payment is held until it mines |
| `BSECRET_ACCEPT_PAYER_LIMIT` | the threshold | satoshis one payer may have answered fast and not yet mined; past it, held |
| `BSECRET_ACCEPT_TOTAL_LIMIT` | ten thresholds | the same across every payer |
| `BSECRET_ACCEPT_WINDOW` | `1h` | how long a fast payment counts against the limits unless it mines first (`ms`, `s`, `m`, `h`) |
| `BSECRET_ACCEPT_WATCH` | `0s` | how long the host keeps watching for a conflict after arcade's acceptance before it answers |

A price needs `BSECRET_LISTEN` and `BSECRET_PAYEE_KEY`, and so does a
private crypt, with `BSECRET_HALL_URL`. Any mistake stops the host before
its port opens.

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
`vault-token`, `sweep`) once each, `bsecret_admitted_repeats_total{kind}`
the same txid shown again when two submissions race past the engine's
duplicate check, and `bsecret_refused_total{reason}` every refusal by
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

After a reorganization two rooted tokens can share a `seq`. Each is a branch,
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
log, and what it dropped stays in storage, unanswered. Funding does not
limit what a key can store at a host, since a sweep returns the value;
these floors, the rows and the table do, and submissions are rate-limited
in front of the engine.

## The state directory

Besides the generic `payments.jsonl` and `unsettleable.jsonl` of
[the host module](https://github.com/lightwebinc/bcommon/blob/main/docs/host-module.md#the-state-directory),
`bsecret-rows.jsonl` holds what the host keeps for its life beside the
engine's storage: the carriers each funding outpoint's row took in, a count
for each it turned away, every drop, every spend of such an outpoint by an
admitted sweep, when the host first saw each token, and each held sweep
whose tombstone a later transaction spent. Replayed in order it rebuilds
every row. A carrier storage holds that the file does not name (a line lost
to a crash, or a directory restored from a copy) is taken into its row again
when it is below what the row keeps, so the winner stays the lowest
commitment the host holds. It keeps a funding output from answering a second
carrier and keeps retention's clocks, so it is kept for the host's life,
backed up with the database, and never edited. Each line is flushed to disk
before the admission it records completes. It names outpoints, txids and
commitments, never an identity or a secret. A cut-short last line is
skipped; any other line that does not parse stops the host, because a row
skipped could let a swept or superseded carrier be answered again.

Back up, restore and settle as the host module says; the payee settles
with `bsecret payee settle`.

## The terms route

The route, its session bound, handshake and response budgets, replay
refusal and payment acceptance are bcommon's: see
[the host module](https://github.com/lightwebinc/bcommon/blob/main/docs/host-module.md).
What is bsecret's own:

- the service is `ls_bsecret`, the terms document is spec section 10.3, and
  a `secret`, `secrets` or `label` answer's context is included on the
  route's `/lookup`;
- the priceable classes are `history`, `history-after`, `audit` and
  `audit-after`, each priced by its own name (`BSECRET_PRICES`); asked on the
  host's own `/lookup` they are refused with an error naming the route;
- the variables are the `BSECRET_` ones in [Configuration](#configuration);
- 400 also covers a question naming a crypt the host does not carry, and
  503 is answered until the index is restored.

### Route metrics

`bsecret_handshakes_total{result}` (`accepted`, `failed`, `limited_address`,
`limited_global`), `bsecret_requests_total{result}` (`replayed`, `limited`),
`bsecret_sessions`, `bsecret_sessions_evicted_total{why}` (`cap`, `idle`),
`bsecret_payments_total{decision,reason}`,
`bsecret_payment_events_total{kind}` and `bsecret_payments_unmined`, with the
labels the host module lists.

## The Go module

The same module exists in Go, `module/` in this repository, written to
bcommon's engine-neutral contract (`github.com/lightwebinc/bcommon/module`)
for a Go overlay host that carries the adapter: `tm_bsecret_<crypt>` for
each crypt, `ls_bsecret` for all of them, the journal `bsecret-rows.jsonl`
with the same lines, the terms route (bcommon's `termsroute`, the Go twin of
the TypeScript host entry) with the same routes, codes, bodies, metrics and
ledger lines, and private crypts. It reads the same `BSECRET_` variables as
the table above and refuses the same mistakes. Its admission rules are
`internal/secrec.Admit`, the index rules secrec's folds, listings and rows,
and its tests drive it with the transaction and index vectors. A host hands
the topic manager the submission's bytes exactly as they arrived
(`module.WithSubmission`): the rules decide on the wire form.

## Joining a crypt

A host that starts carrying a crypt, or that missed part of a chain, is
filled by replay (spec section 11.6). A sibling host answers each token
alone with its proof, so a replayer assembles each token's BEEF itself, the
token from `vault-seq` at `seq` and its parent from `seq - 1`, with the
library's `tokenBEEF`, and submits it; at `seq` 0 the parent is the chain
tree, which no host keeps: the publisher's home supplies it, or a chain
source while it still serves the tree. Tokens, carriers and
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

## Keeping a crypt private

`BSECRET_PRIVATE` names a crypt's organizations (spec section 10.4). From
then on the host answers no question about that crypt on the overlay
host's own `/lookup` (an error names the reason), and answers every class
of it on the terms route (`BSECRET_LISTEN`) over BRC-104 only, to an asker
whose identity key is one of the organizations or a current member of one
of their groups. A refusal comes before any price, so a stranger pays for
nothing. Other crypts the host carries are answered as before.

```text
BSECRET_CRYPTS=example_hmqzvtkwrx
BSECRET_PRIVATE=example_hmqzvtkwrx=02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
BSECRET_HALL_URL=http://127.0.0.1:8080
BSECRET_LISTEN=0.0.0.0:8443
BSECRET_PAYEE_KEY=<64 hex characters: the route's BRC-104 identity>
```

Membership is borg's: an asker who is a current member of any group of a
named organization is served, not only of the group a vault is keyed to.
For an asker that is not one of the organizations,
the module asks each `BSECRET_HALL_URL` borg's `member-of` question for
each hall the organization's vaults in the crypt name, as the host's index
holds them; any host that answers a group is enough. The answer is kept for
`BSECRET_MEMBER_TTL` seconds, so a member removed from every group is
refused within that long. A borg host that does not answer leaves the asker
refused, with a reason that says so, until one does. The borg host's word
is taken as it answers, so name hosts you run: this host itself, when it
loads borg's module and carries the hall, at its own base URL. An
organization with no vault in the crypt yet is served, and its members are
not, until the host holds a vault of it.

Readers set `lookup_auth = on` and name the crypt's hosts at a base URL
whose `/lookup` and `/.well-known/auth` reach the terms route. Put the
route and the overlay host behind one origin with a proxy in front of
both, which sends those two paths to `BSECRET_LISTEN` and the rest, the
owner's `/submit` among them, to the overlay host:

```text
location = /lookup             { proxy_pass http://127.0.0.1:8443; }
location = /.well-known/auth   { proxy_pass http://127.0.0.1:8443; }
location /                     { proxy_pass http://127.0.0.1:8080; }
```

That way the open lookup is not reachable from outside at all. The terms
route answers only `ls_bsecret`, so a reader's questions about the group's
hall, which are borg's, go to an origin that reaches the overlay host's own
`/lookup` (or another hall host): name it in the readers' `hall_hosts`.
The rest is still the operator's:

- set a submission rate at the proxy: the module sets none of its own,
  submissions to a private crypt's topic are not gated, and carriers of a
  vault that does not exist are kept for `BSECRET_UNHELD_HOURS`;
- receive by unicast, not from a shared plane topic, whose objects reach
  every host subscribed to it;
- give an auditor you invite a key of one of the organizations' groups, or
  name the auditor's organization in `BSECRET_PRIVATE`.

None of this hides the vault's tokens, which are mined and readable from
the chain by anyone ([limits.md](limits.md), known limit 8).

`bsecret_private_total{result}` counts questions about a private crypt:
`served`, `unauthenticated` (asked off the route, or without BRC-104),
`refused` (a key the crypt is not served to) and `unknown` (no borg host
could say). The gauges are `bsecret_private_crypts` and
`bsecret_private_members_known`.

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
