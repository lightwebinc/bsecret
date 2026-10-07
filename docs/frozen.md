# Frozen at first publish

Every item below is hashed into a key or an identifier, written into a
record, or named by a host. Once one record using it is on a public host,
readers verify against it for as long as anyone reads that record, so
changing it afterwards is a new identifier or a new record version, never an
edit.

**Status: signed.** Every row below is signed and none is provisional. The
six rows of section 2 that no record vector can pin (carrier shape, vault
token shape, script canonicality, signatures, one claiming output and sweep)
are pinned byte for byte by the transaction vectors ([spec.md](spec.md)
section 19) and were signed against them. The
registry rows of section 1 belong in bcommon's registry
(`docs/registry.md`), where they are checked against every registered row;
this repository does not edit that registry. They are registered there
before anything is published under them.

## 1. Registry entries

Checked against the registered prefixes (`bf`, `gw`, `bl`, `bb`, `bo`, and
`vx` for tests), protocols, topic namespaces and baskets: `se` is none of the
prefixes, `[1, "bsecret"]` and `[2, "bsecret self"]` are no registered
protocol, `tm_bsecret_` and `ls_bsecret` are no registered name, and no
basket starts with `bsecret`.

| Kind | Value | Use | Status |
| --- | --- | --- | --- |
| Protocol | `[1, "bsecret"]` | every public bsecret derivation (counterparty anyone) and the funding key | signed |
| Key id | `vault` | a vault token's lock and field signature | signed |
| Key id | `secret` | a secret carrier's record output and field signature, and the outputs of trees that fund secrets | signed |
| Key id | `chain` | the outputs of trees that pay for a vault's first token; never a carrier's | signed |
| Key id | `fund` | the embedded wallet's funding key | signed |
| Protocol | `[2, "bsecret self"]` | the self wrap: a content key encrypted to the owner's own wallet, counterparty `self` | signed |
| Key id | the standard padded base64 of a content id | one self wrap; derived per version, so a wrap is bound to what it carries | signed |
| Tag prefix | `se` (`73 65`) | owned by bsecret | signed |
| Tag | `se` `0x01` | vault token, first field | signed |
| Tag | `se` `0x02` | funding-tree output, its one field | signed |
| Record magic | `sev` `0x01` | vault record, version 1 | signed |
| Record magic | `ses` `0x01` | secret record, version 1 | signed |
| Record magic | `sep` `0x01` | payload (the plaintext inside a secret's ciphertext), version 1 | signed |
| Topics | `tm_bsecret_<name>_<suffix>` | one topic per crypt: a readable `<name>` of at most 28 characters and a 10-letter random `<suffix>` fixed at the crypt's creation (spec section 10.1); the `tm_bsecret_` namespace belongs to bsecret | signed |
| Lookup service | `ls_bsecret` | one per host, all crypts; every question names its crypt | signed |
| Host route | `<base>/ls_bsecret/terms` | the host terms document (spec section 10.3) | signed |
| Baskets | `bsecret fund`, `bsecret secret funding`, `bsecret chain funding`, `bsecret chain`, `bsecret kill tombstone` | wallet baskets: secret trees and chain trees kept apart, vault tokens, tombstones; never on a public host, registered so no two applications share one in a wallet | signed |
| Domain string | `bsecret vault id v1` | hashed into a vault identifier (spec section 3.3). The registry has no row kind for domain strings; a note under the application | signed |
| Domain string | `bsecret secret id v1` | hashed into a secret identifier (spec section 5.2) | signed |
| Domain string | `bsecret epoch wrap v1` | hashed into the key that wraps a content key under an epoch (spec section 6.3) | signed |
| Borrowed, not registered | `metanet keyed content symmetric v1`, `metanet keyed content commitment v1` | BRC-369 section 2's domain strings, used as written | signed (as a note in the registry) |
| Used through borg, not registered | `[2, "keyed content release"]` | BRC-369's release derivation. bsecret derives nothing under it: the epoch keys it uses were released under it by borg | signed (as a note in the registry) |

**The prefix.** The tag prefix is `se`, not `bs`: two applications' names
begin `bs` (this one and a storage application), so `bs` would name neither
unambiguously. `bs` is retired: no application takes it. The storage
application takes `st` and MUST NOT take `se`.

Tag type bytes `0x03` to `0x6f`, `0x71`, `0x72`, `0x74`, `0x75` and `0x77` to
`0xff` under `se`, and record letters other than `v`, `s` and `p`, are
unassigned and stay bsecret's. `0x76`, `0x73` and `0x70` are never assigned
as tag type bytes, because `se 0x76`, `se 0x73` and `se 0x70` are the first
three bytes of the record magics. `0x00` is not assigned.

bsecret registers no certificate type: a reader is a member of a borg group,
and the grant is borg's.

## 2. Mechanism shared with the substrate

| Item | Value | Status |
| --- | --- | --- |
| Derivation setting | BRC-42, counterparty `anyone`, `forSelf = true` on the owner's side | signed |
| PushDrop layout | lock-before, field signature last, over `SHA-256` of the fields concatenated | signed |
| Carrier non-final device | writers use `nLockTime = 4102444800` and input `nSequence = 0`; hosts accept any `nLockTime >= 4102444800` and any `nSequence` below `0xFFFFFFFF` | signed |
| Carrier shape | exactly one input spending an owner funding output of a mined tree, unlocked by exactly one minimal push of a strict low-S DER signature and sighash `0x41`; exactly one output carrying the whole input value, locked and funded under `secret`; the owner is the record's `org`; the BEEF is exactly the carrier and its funding tree with one minimal Merkle path; refused in the order `shape` (one input, one output), `beef`, record rules, `crypt`, `mineable`, `unlock`, `lock`, `signature`, `funding` (the funding output's form and the value carried) (spec section 11.1) | signed, against the transaction vectors |
| Vault token shape | exactly one claiming output, a two-field signed PushDrop of 1 satoshi; mined; published in a BEEF V1 or V2 of exactly the token and its parent, each with its minimal path (one merged path when they share a block; no txid-only entries); `seq > 0`: the parent's txid is `prev` and exactly one input spends the parent's token at `seq - 1`, whose record the host reads from the parent; `seq` 0: a first token spends exactly one input of its parent (exactly one of its inputs spends an output of the parent), a funding output locked to `derive(org, "chain")`; the owner spends a token output only in its successor; other inputs not read, and a token at `seq > 0` may also spend non-token outputs of its parent; a predecessor of another crypt, owner or vault, or at another `seq`, reads `token-input`, never `transition`; admitted whether or not the topic holds the predecessor (`pending` until it does); refused in the order `shape`, `beef`, record rules, `crypt`, `lock`, `signature`, `unmined`, `token-input`, `vault-id`, transition rules | signed, against the transaction vectors |
| Script canonicality | every checked script equals, byte for byte, the one rebuilt from its fields and the derived key | signed, against the transaction vectors |
| Signatures | field and carrier input signatures strict DER, low S; carrier input signatures sighash `0x41` only | signed, against the transaction vectors |
| Classifier | the key push, `OP_CHECKSIG`, then one push: a CBOR definite map head, `00 44` and `ses 0x01` claims a secret; the push exactly `se 0x01` a vault token; the whole script `21 <33> ac 03 73 65 02 75` is funding-shaped (`script-v1.json`) | signed |
| One claiming output | a transaction with more than one claiming output is refused (`shape`) | signed, against the transaction vectors |
| Funding output | `<derive(owner, k)> OP_CHECKSIG <73 65 02> OP_DROP`, unsigned, `k` being `secret` or `chain` by what the tree pays for | signed |
| Sweep | a mined transaction claiming nothing whose output 0 is funding-shaped: output 0 alone admitted; its inputs' spends kept for the host's life where they match a carrier's funding outpoint, otherwise in a bounded table of at least 65536; refused in the order `beef`, `unmined`, `too-large`; an unmined sweep carries the tree it spends, so it reads `beef`; a host accepts at least 1024 inputs; a sweep that left the bounded table before its carrier arrived does not retract it at that host; a transaction that only spends held outputs is refused (`not-bsecret`) | signed, against the transaction vectors |
| Retraction | an admitted sweep a host holds, spending a carrier's funding outpoint, retracts the carrier, whatever the host's view of the best chain; a retracted carrier is never answered | signed |
| Publication | carriers before the token that lists them; tokens and sweeps once, after they mine and a propagation delay, to the plane and directly to every host named; a version keyed under a new epoch only after the group token that began it is mined and its wraps are published; a sweep in every crypt that holds a version it retracts; every object confirmed at every named host by lookup and offered again where missing; on the plane a carrier is published once a quorum of the named hosts answer it by lookup, and a token or a sweep once all do; funding trees only inside the BEEF of what they fund | signed |
| Commitment | `C = txid(K)`, hash byte order in records, display order in JSON | signed |
| CBOR | RFC 8949 section 4.2.1 core deterministic encoding, bcommon's subset, enforced on decode | signed |
| Admission | a verdict depends only on the submission's bytes (the transaction and the transactions its BEEF carries) and the host's headers; never on another topic, on what the topic holds, on the group's chain, or on arrival order; previous coins decide only retention; **a topic manager returns instructions only for what it admits and raises for every refusal** | signed |
| One answered carrier per funding outpoint, over the host's life | the winner is the lowest `C` (hash byte order) on the outpoint; every other carrier is `superseded`, and so is every carrier once the winner is dropped. A dropped winner is sticky: the row stays dropped for the host's life, whatever is admitted on the outpoint later | signed |
| Outpoint rows | one per funding outpoint any admitted carrier spent (the winner as a running minimum, other commitments, a count, dropped, sweeps), kept for the host's life | signed |
| One carrier per funding outpoint, by the owner | an owner makes at most one carrier per funding output | signed |
| Hosts broadcast nothing, decrypt nothing | an engine that carries `tm_bsecret_` topics runs with no broadcaster; a host holds no key | signed |
| Coin retention | every accepted transaction retains every held output it spends | signed |
| Joining a crypt | by replay, the replayer assembling each token's BEEF from the token and its parent; an unordered synchronization of unspent outputs is never enabled for `tm_bsecret_` topics | signed |
| The vault's chain | a token is **rooted** when the host holds every token from it back to the vault's first by spends; only rooted tokens are answered as a vault's latest, folded into its set, or list a carrier. A host admits a token on its parent's bytes alone, so a token can be admitted and never rooted | signed |
| A broken vault | a `set-mismatch` or `stale-mismatch` token breaks the vault's chain from it on, for good; answers use the set of the last rooted token before it; a `commitment-reuse` token does not stop the set. A reader that folds the chain refuses a broken vault entirely, the earlier set included. Where two rooted tokens share a `seq`, each branch is folded on its own, and an answer uses the one whose proof verifies in the host's headers, else the lowest txid | signed |
| Index statuses | tokens `pending`, `set-mismatch`, `stale-mismatch`, `commitment-reuse`, `consistent`; carriers `retracted`, `superseded`, `mismatched`, `listed`, `unlisted` | signed |

## 3. The vault record (magic `sev` `0x01`)

| Item | Status |
| --- | --- |
| Keys: 0 `magic`, 1 `crypt`, 2 `org`, 3 `vault`, 4 `seq`, 5 `prev`, 6 `name`, 7 `hall`, 8 `group`, 9 `epoch`, 10 `epochId`, 11 `labels`, 12 `anchor`, 13 `create`, 14 `update`, 15 `retire`, 16 `count`, 17 `stale`, 18 `root`, 19 `created`; all required | signed |
| Types and bounds of spec section 3; a display name is 1 to 64 bytes of one line of plain text, holding no control character (U+0000 to U+001F, U+007F to U+009F) and neither U+2028 nor U+2029 (`name`); an entry is `[id, version, contentId, commitment]` with a version from 1 to 2^53 - 1; a change list is decided as length (`list`), then each entry (`entry`), then order (`list`); `prev` zero exactly at `seq` 0; the first token only creates, and its `stale` is 0 | signed |
| The refusal order and labels of spec section 3.1 | signed |
| **The owner is the organization:** `org` is the only writer of a vault and of its secrets | signed |
| **The vault identifier:** `SHA-256("bsecret vault id v1" \|\| txid \|\| index as 4 bytes big-endian)` of the outpoint the first token spends from its chain tree, checked at admission (`vault-id`); one identifier has one chain | signed |
| **One vault, one group:** `hall`, `group`, `labels` and `anchor` are fixed at the first token | signed |
| The current set: before, less `retire`, with `update` replacing, plus `create`; its root RFC 6962 over the leaf data `SHA-256(id \|\| version as 8 bytes big-endian \|\| contentId)`, ascending by id; the empty root `SHA-256()` | signed |
| Transition rules, in the order `transition`, `epoch`, `debt`, `count` (spec section 4.2): the epoch never goes back; the same epoch keeps its id and a later one has another | signed |
| **Re-keying is enforced at admission:** with a base of the predecessor's `count` when the transition acknowledges a later epoch and of its `stale` otherwise, `stale` is 0 when the base is 0, and otherwise the base less the secrets updated and retired, which are at most the base; nothing is created unless `stale` is 0 | signed |
| A version listed is above every version an earlier token listed for that identifier, a retired one's included (a fold rule, `set-mismatch`) | signed |
| Anchor modes: `0` per version (a reader takes only listed versions), `1` interval (a reader may take a linked unlisted version, marked unanchored) | signed |
| The owner acknowledges a new epoch of the group in the vault's next transition; with the group ahead of the vault, the only transition its tooling builds is the acknowledgement (not an admission rule: the predecessor names no group state) | signed |

## 4. The secret record (magic `ses` `0x01`)

| Item | Status |
| --- | --- |
| Keys: 0 `magic`, 1 `crypt`, 2 `org`, 3 `vault`, 4 `id`, 5 `version`, 6 `previous`, 7 `label`, 8 `group`, 9 `epoch`, 10 `epochId`, 11 `commitment`, 12 `hash`, 13 `length`, 14 `salt`, 15 `segment`, 16 `created`, 17 `self`, 18 `wrap` required; 19 `inline` optional | signed |
| Types and bounds of spec section 5; `previous` zero exactly at `version` 1; `length` at most 2^27 and one a plaintext of 1 to 67108864 bytes produces (`range`); `inline`, when present, 1 to 16384 bytes (`range`) and exactly `length` bytes hashing to `hash` (`content`, checked at admission) | signed |
| **The content id:** SHA-256 of the record's canonical encoding without keys 17, 18 and 19, unknown keys kept | signed |
| The secret identifier: `SHA-256("bsecret secret id v1" \|\| vault \|\| name)`; the name grammar: 1 to 128 bytes of `a-z`, `0-9`, `.`, `_`, `-`, `/`, no empty path segment | signed |
| The label grammar: 1 to 32 bytes of `a-z`, `0-9` and single hyphens, a letter first, a letter or digit last; a label set of 1 to 16, ascending; the default set `confidential`, `internal`, `public`, `restricted`; a label is a classification and decides no reader | signed |
| Inline bound 16384 bytes of ciphertext; a larger ciphertext, of a payload of at most 67108864 bytes (at most 2^27 bytes of ciphertext), is found by the BRC-26 address of `hash` (`uhrp://` and Base58Check over `ce00` and the hash) and is not carried; no locator is carried | signed |

## 5. Keys and the payload (magic `sep` `0x01`)

| Item | Status |
| --- | --- |
| BRC-369 section 2 verbatim: `k` uniform in `[1, n-1]`, fresh per version, a re-keying included; symmetric key `SHA-256("metanet keyed content symmetric v1" \|\| k)`; commitment `SHA-256("metanet keyed content commitment v1" \|\| k)`, digest form only | signed |
| BRC-369 section 2.3's construction: AES-256-GCM segments of `segment` plaintext bytes, IV the 4-byte salt then the segment index as 8 bytes big-endian, no associated data, a 16-byte tag after each segment; the salt fresh per content key. With bounds BRC-369 leaves open: `segment` 16 to 1048576, a plaintext of 1 to 67108864 bytes, no length whose last segment is a tag alone | signed |
| A read checks the ciphertext's length and hash before it opens any wrap; two faults read as the earlier check (`keyed-v1.json`) | signed |
| The owner's tooling refuses to publish a version whose commitment it has published or listed before, in any of its vaults, and labels the refusal `commitment-reuse` | signed |
| The epoch wrap: key `SHA-256("bsecret epoch wrap v1" \|\| epoch symmetric key \|\| content id)`; BRC-2's symmetric form, a random 32-byte IV, `IV \|\| ciphertext \|\| tag`, 80 bytes | signed |
| The self wrap: BRC-100 `encrypt` under `[2, "bsecret self"]`, key id base64 of the content id, counterparty `self`, 80 bytes | signed |
| Payload keys: 0 `magic`, 1 `name`, 2 `value` required; 3 `type`, 4 `notAfter`, 5 `rotateEvery`, 6 `pad` (at least 1 byte) optional; the name hashes to the record's `id`; a reader decodes at most 67108864 bytes | signed |
| A reader's check order and labels: `listing`, `hash`, `undecryptable`, `commitment`, `tag`, `payload` (spec section 7.2); also `retracted`, `successor` and `rollback`. A host that answers what does not verify makes a read incomplete, not refused | signed |
| **The listing check:** an inclusion path that names the latest token by `seq` and txid takes the leaf to that token's root; the record names the token's crypt, owner, vault, group and one of its labels; it is keyed under the token's epoch and epoch id, or, only while the token's `stale` is not 0, under an earlier epoch with another epoch id. A path proves that the root holds the leaf and nothing else | signed |
| **A wrap is opened only with the key of the epoch the record names.** A wrap that does not open under that key, for a reader that verified the key, names the owner | signed |
| **Descent:** a reader takes a token as the vault's only when it descends by spends from the vault's first token, which it checks from `seq` 0 once and from the token it remembers afterwards; it checks a first token by the outpoint hash alone (an input's outpoint hashes to the vault identifier) | signed |
| A reader checks that the vault's `org` is the group's organization and that every `epoch` and `epochId` it relies on is on the group's canonical chain; a vault that names an epoch the group has not begun is refused | signed |
| A successor (interval vaults only): the next `version` of the same secret of the same vault and group, naming the content id before it, with one of the vault's labels, keyed under an epoch neither before its predecessor's nor before the latest token's, the same epoch with the same epoch id and a later one with another; no commitment repeats in a run, the listed version included; two records at one version are both refused; a run of links ends below a retracted version, and a retracted listed version is refused (`retracted`); a reader follows at most 64 unlisted versions and says that a later one exists | signed |
| Writers build a transition only with positive evidence, no older than a bound of at most 600 seconds (60 by default, which is policy), that the vault's latest token and the group's latest token are unspent per a spend index; without it they do not write. A transition or a sweep that is persisted is given up only when a spend index names another spender of what it spends | signed |
| Readers report a version as exposed when it is keyed under an epoch before the group's latest, and never as current without evidence that the vault's token and the group's token are each the latest, taken at the read (a value kept keeps its age); a reader refuses a latest token below the highest `seq` it has verified, of the vault and of its group (`rollback`). A version read as history is held to the first token that listed it, where commitment reuse is refused too. The states a reader reports: anchored or unanchored; current or exposed; settled, in debt, behind or ahead | signed |

## 6. Names and questions

| Item | Status |
| --- | --- |
| Crypt identifier `<name>_<suffix>`, 12 to 39 bytes: `<name>` 1 to 28 bytes of `[a-z]` and single underscores, starting and ending with a letter; `<suffix>` exactly 10 letters drawn uniformly at random once at the crypt's creation | signed |
| Class names and members: free `vault`, `vault-seq`, `vaults`, `vaults-after`, `secret`, `version`, `pending`, `secrets`, `secrets-after`, `label`, `label-after`, `sweep`; priceable `history`, `history-after` `{crypt, history, vault, secret}`, `audit`, `audit-after` `{crypt, audit, vault}` (spec section 10.2); no priced class is a superset of a free class | signed |
| `vault` and `vaults` answer rooted tokens only, every candidate at the highest `seq` whether or not its stored proof still verifies; `vault-seq` answers every held token at a `seq`; `pending` answers highest version first | signed |
| `secret`, `secrets` and `label` answers carry each record's inclusion path in the set as BRC-24 `context`: CBOR `[seq, token, index, size, [[bytes(32), bool], ...]]`, `token` the txid (hash byte order) of the vault token whose set was used, the bool true when the sibling is on the left, `size` 1 to 4096, `index` below `size`, at most 32 steps and 2048 bytes | signed |
| Query values validated as parsed; every member a string; the value rules of spec section 10.2; an unknown or missing member refused; an unknown crypt refused | signed |
| Answer order: vaults by identifier, secret carriers by identifier, version, txid (display order, as lowercase hex), tokens by `seq` then txid; `-after` strictly after the cursor; a page never splits a `seq`, a secret's or a version's carriers | signed |
| Terms document at `<base>/ls_bsecret/terms`: `service`, `terms` (`1`), `classes` of `{class, satoshis}`; informative; the 402 is authoritative; the payment is output 0 of the BRC-105 transaction, a P2PKH output of at least the price to the key BRC-29 derives for the payee; a host that prices a class bounds handshakes before any signature | signed |
| Retention floors: tokens and outpoint rows for the host's life; a listed carrier while the set holds its version and 31 days after the token that replaced or retired it was first seen; an unlisted carrier 31 days after it was first seen where the host holds the vault's rooted chain, and 24 hours where it does not; a retracted carrier is never answered whatever the floor | signed (floors: a later version may lengthen them, never shorten) |

## 7. Bounds that are a floor

Readers accept every record within these, and a later version may raise them
but never lower them: vault record 20480 bytes, secret record 17408 bytes,
inline ciphertext 16384 bytes, 64 changes per list per transition, 4096
secrets in a vault, 16 labels, 64 keys per record, segments of 16 to 1048576
bytes, a payload of 67108864 bytes, a host's BEEF bound of at least 262144 bytes, a host's sweep input
bound of at least 1024. Signed, as floors.

## 8. Not frozen

- Funding tree sizes and output values; fee sources of tokens.
- Host policy: retention beyond the floors, lookup rate limits, prices, the
  handshake budget's numbers, which organizations a host serves, metric
  names.
- The answer limits (8 per question, 64 tokens or 16 secret carriers per
  page), the tokens kept per `seq` (8; rooted first, then lowest txid), and the superseded carriers and
  commitments kept per outpoint (8), which a later version may raise.
- The default age of a writer's or a reader's freshness evidence (60
  seconds); the bound (600) is frozen.
- The padding block (256 bytes) and the default segment size (16384 bytes),
  which are a writer's.
- `rotateEvery` and `notAfter`, which no host enforces.
- Anything the spec marks as a host's, a publisher's or a reader's choice.
- The limits of [limits.md](limits.md).
