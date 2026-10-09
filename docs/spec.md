# bsecret: the secrets contract

bsecret keeps an organization's secrets on the BEEF object plane, with overlay
hosts as replicas that hold ciphertext and never a key. A secret is a BRC-369
keyed object: encrypted once under a random content key that is committed to
before anyone holds it. The content key is wrapped twice: to the owner's own
wallet, and under the key of one **epoch** of a borg group, so that the
members of that epoch, and nobody else, open it. A **vault** is a chain of
mined tokens that lists every version of every secret it holds and names the
epoch each is keyed under. When the group removes a member it begins a new
epoch whose key the removed member never receives; the vault then
acknowledges the new epoch, and from that token on every host refuses, on
the vault's chain, anything but the re-keying or retirement of what the vault
held until nothing in it is left under an earlier epoch. The chain is the audit trail: anyone
with block headers verifies which versions the owner listed, in what order,
under which epoch, and how long each stayed listed under an epoch a removed
member held. A
host is an ordinary overlay host running the `tm_bsecret_<name>_<suffix>`
topic manager and the `ls_bsecret` lookup service.

This document is normative. MUST, MUST NOT, SHOULD and MAY are used as in
RFC 2119. Every byte-level and name-level choice that cannot change once a
record is on a public host is listed in [frozen.md](frozen.md). The golden
vectors in `testdata/vectors` are part of the contract (section 19).

bsecret is built on borg, the organization and group contract: an
organization is an identity key, a group is a chain of mined tokens whose
every removal begins a new epoch, and each epoch's key is sampled at random,
committed to, and wrapped by the organization to each member. This document
calls those borg's and does not restate them. "Group", "epoch", "epoch id",
"epoch key", "wrap", "hall", "grant" and "current member" mean what they mean
there.

## 1. Objects

| Object | On chain | On the plane | What it is |
| --- | --- | --- | --- |
| **Vault record** `V` | inside a mined token | the token's transaction | canonical CBOR: one transition of a vault's current set (section 3) |
| **Secret record** `S` | never | inside a carrier | canonical CBOR: one version of one secret, with its ciphertext when it is small (section 5) |
| **Payload** `P` | never | only as ciphertext | canonical CBOR: the secret's name and value, the plaintext the ciphertext holds (section 6.5) |
| **Vault token** | mined | a BEEF object | a PushDrop of a tag and a `V`; each spends the one before it (section 12.3) |
| **Carrier** `K` | never mined | a BEEF object | one unmined transaction whose one output holds an `S` (section 12.2) |
| **Commitment** `C` | no | no | `C = txid(K)`, 32 bytes, hash byte order |
| **Content id** `D` | inside a vault token | no | SHA-256 of an `S` without its wraps and ciphertext (section 5.1): the identity of one version |
| **Funding tree** `F` | mined | inside each carrier's BEEF, and inside the BEEF of a vault's first token | one transaction of tagged outputs; each carrier spends one |
| **Sweep** | mined | a BEEF object | a mined spend of funding outputs; it retracts the carriers they funded (section 12.5) |

State that needs an order is mined: a vault is a chain of mined tokens, one
transaction per transition. Everything else rides an unmined carrier: a
secret record is a fact about one version, ordered by the token that lists
it.

```text
 owner (the organisation's wallet)
    │
    ├── secret carriers S (one per version) ──▶ plane ──▶ hosts     ciphertext, wraps; no key
    │
    └── vault chain:  V_0 ──spend──▶ V_1 ──spend──▶ V_2 ──spend──▶ V_3 ──spend──▶ V_4
                     (create a,b;   (update b;    (epoch 1;      (epoch 1;      (epoch 1;
                      epoch 0)       epoch 0)      re-key a;      re-key b;      create c)
                                                   stale 1)       stale 0)
                                         ▲
 borg group chain:  G_0 ───────────────▶ G_1 (remove a member; epoch 1, a new key)
```

A **crypt** is the rendezvous: one topic, `tm_bsecret_<name>_<suffix>`, that
a set of hosts carries and any number of organizations share (section 10.1).
Every record names its crypt, and a vault's chain and carriers all live in
one crypt. The vault's group lives in a borg hall, which the vault names; the
two topics are independent, and a host of one need not carry the other.

**Only the organization writes.** A vault's owner is its organization's
identity key: the key that signs every token and every carrier, and the key
that sampled every epoch key of the group. A member reads. This version has
no delegated writer.

## 2. Conventions

- **CBOR.** Every record is one CBOR map in the core deterministic encoding
  of RFC 8949 section 4.2.1, written and read by bcommon's `cbor` package,
  which enforces it on encode and on decode. The subset is unsigned and
  negative integers, byte strings, UTF-8 text strings, arrays, maps, `false`,
  `true` and `null`; tags, floats, indefinite lengths and nesting deeper than
  16 are refused. One value has exactly one encoding a reader accepts.
- **Record keys.** A record's top-level keys are unsigned integers, at most 64
  of them. A key this version defines is checked as its table says. A key
  above the last defined one is unknown: a reader MUST preserve it verbatim
  when it re-encodes and MUST otherwise ignore it.
- **Hashes.** SHA-256 unless stated. A txid or commitment inside a record is
  in hash byte order (the order SHA-256d produces). A txid in JSON (a lookup
  question, a cursor, an outpoint) is in display order, the byte-reversed hex
  the engine and every explorer print. Both are lowercase hex.
- **Keys.** An identity key is a compressed secp256k1 point: 33 bytes, prefix
  `0x02` or `0x03`, an x-coordinate below the field prime, and a point on the
  curve (bcommon `guard.ParsePubKey`). A reader MUST refuse any other byte
  string, including an x-coordinate at or above the prime that some parsers
  reduce and accept, because that would give one identity two names. In JSON
  a key is its 66 lowercase hex digits. The **anyone key** is BRC-43's anyone
  counterparty, the generator point (private key 1); it is never an owner.
- **Lists** of identifiers and entries in a record are strictly ascending by
  their bytes, so one set has one encoding.
- **Signatures** a host checks are strict DER with a low S value: the bytes
  MUST equal the one canonical serialization of the signature's `(r, s)`.
- **Time.** Times are Unix seconds (UTC) on the writer's clock, from 1 to
  253402300799 (`9999-12-31T23:59:59Z`). They are claims. A host never admits
  or refuses by a time. The only times an auditor proves are block heights
  (section 9).

## 3. The vault record

Magic `"sev"` `0x01`. The second field of a vault token.

| Key | Field | Type and bounds | Rule |
| --- | --- | --- | --- |
| 0 | `magic` | bytes(4) | `73 65 76 01` (`"se"`, `'v'` for vault, version 1). Always the first key |
| 1 | `crypt` | text; the crypt identifier grammar (section 10.1) | MUST equal the topic's crypt |
| 2 | `org` | bytes; the key rule | the owner: the organization's identity key. The token's lock is derived from it (section 12.3), so it is bound, not claimed |
| 3 | `vault` | bytes(32) | the vault identifier (section 3.3), fixed for the vault's life |
| 4 | `seq` | uint, 0 to 2^53 - 1 | 0 for the vault's first token, then one more per token |
| 5 | `prev` | bytes(32) | the txid, hash byte order, of the mined transaction holding the token at `seq - 1`; all zero exactly when `seq = 0` |
| 6 | `name` | text, 1 to 64 bytes, one line of plain text: no control character (U+0000 to U+001F, U+007F to U+009F) and no line or paragraph separator (U+2028, U+2029) | the vault's display name |
| 7 | `hall` | text; borg's hall identifier grammar | the borg hall the vault's group lives in. Fixed at the first token |
| 8 | `group` | bytes(16) | the borg group whose epochs key this vault. Fixed at the first token |
| 9 | `epoch` | uint, 0 to 2^32 - 1 | the epoch the vault acknowledges: every version this token lists is keyed under it |
| 10 | `epochId` | bytes(32) | that epoch's id (borg: SHA-256 of the group record that began it) |
| 11 | `labels` | array of 1 to 16 text; the label grammar (section 5.3), ascending | the vault's label set. Fixed at the first token |
| 12 | `anchor` | uint, 0 or 1 | the anchor mode (section 4.4). Fixed at the first token |
| 13 | `create` | array of 0 to 64 entries, ascending by `id` | secrets entering the current set |
| 14 | `update` | array of 0 to 64 entries, ascending by `id` | new versions of secrets already in the set |
| 15 | `retire` | array of 0 to 64 bytes(32), ascending | secrets leaving the set |
| 16 | `count` | uint, 0 to 4096 | the number of secrets in the set after this transition |
| 17 | `stale` | uint, 0 to 4096 | how many of them are still keyed under an epoch before `epoch` (section 4.3) |
| 18 | `root` | bytes(32) | the set root after this transition (section 3.2) |
| 19 | `created` | uint, 1 to 253402300799 | a claim |

An **entry** is the array `[id, version, contentId, commitment]`: the
secret's identifier (bytes(32)), the version entering the set (uint, 1 to
2^53 - 1; any other version is refused `entry`), the content id of that version's secret record (bytes(32),
section 5.1) and that version's content key commitment (bytes(32), section
6.1).

Keys 0 to 19 are always present; keys 20 and above are unknown to this
version. The encoded record is at most 20480 bytes.

### 3.1 The refusal order

A record that breaks several rules is refused for the first, so that every
implementation reports the same reason. For each record:

1. `too-large`: the encoded length is over the record's bound;
2. `cbor`: the bytes are not exactly one canonical item of the subset, or the
   item is not a map;
3. `too-large`: the map has more than 64 entries;
4. `key-type`: a key is not an unsigned integer;
5. `magic`: key 0 is absent, is not a byte string, or is not the record's
   magic;
6. each defined key in ascending order: `missing` if it is absent (and not
   optional), then `type` if it has the wrong CBOR type, then the key's own
   rule: `crypt` for the crypt, `identity` for a key, `name` for a display
   name or a secret's name, `hall` for the hall, `label` for a label or a
   label set, and `range` for every other bound in the record's table. A
   change list is decided in three steps: `list` when it holds more than 64
   elements; then `entry` when any entry is not four elements of the right
   types and lengths with a version from 1 to 2^53 - 1 (for `retire`, `list`
   when any element is not 32 bytes); then `list` when it is not strictly
   ascending;
7. across fields, in this order. For a vault record: `list` when one
   identifier is in more than one of `create`, `update` and `retire`, or one
   commitment is in two entries; `chain` when `prev` is zero at a `seq` other
   than 0 or not zero at `seq` 0; `count` when a first token's `count` is not
   the length of its `create` or the first token updates or retires anything;
   `debt` when `stale` is above `count`, when a first token's `stale` is not
   0, or when `create` is not empty while `stale` is not 0. For a secret
   record: `chain` when `previous` is zero at a `version` other than 1 or not
   zero at `version` 1; `range` when `length` is one no plaintext produces
   (section 6.2), is one that a plaintext above 67108864 bytes produces, or
   is above 16384 with `inline` present; then
   `content` when `inline` is present and is not exactly `length` bytes that
   hash to `hash`.

`refusal-v1.json` pins every step case by case.

### 3.2 The current set

The **current set** after a token is the set before it (empty before `seq`
0), less `retire`, with each `update` entry replacing its secret's version,
plus `create`. Its root is bcommon `commit`'s RFC 6962 Merkle Tree Hash over
one leaf datum per secret, `SHA-256(id || version || contentId)` with the
version as eight bytes big-endian, in ascending order of the identifiers'
bytes (leaf hashes `SHA-256(0x00 || datum)`, nodes
`SHA-256(0x01 || left || right)`); the empty set's root is `SHA-256()` of
nothing. "Which secrets exist and which version of each is current" is
therefore one committed fact, and one secret is checked against it by an
inclusion path (section 10.2).

A host cannot check `root`, `count` or `stale` against the set while it
admits the token: it reads only the predecessor (section 11.1). The index
folds the change lists along the chain and reports a token whose fold breaks
(section 11.2); a reader that fetches the set checks its root itself
(section 14).

### 3.3 The vault identifier

`vault = SHA-256("bsecret vault id v1" || txid || index)`: the outpoint the
vault's first token spends from its chain tree (section 12.3), the txid in
hash byte order and the output index as four bytes big-endian. A host checks
it when it admits a first token (section 11.1, `vault-id`).

An outpoint is spent by at most one mined transaction, so **one vault
identifier has at most one first token**, and each token output is spent by
at most one mined successor. The vault's chain is the tokens that **descend
by spends from its first token**: there is one, and an auditor handed a chain
that starts at `seq` 0 holds it.

A token that names the vault and does not descend from its first token is not
the vault's. Such tokens can exist: a host admits a token on the bytes of its
parent alone (section 11.1), so an owner can mine a transaction with a
well-formed token output that no host would admit, and build on it a token
every host admits. A host never counts such a token as the vault's (it is not
**rooted**, section 11.2), and a reader MUST NOT (section 14). The rules of
section 4.2 bind the rooted chain; a token off it proves nothing about the
vault and changes nothing in it.

A display name identifies nothing: two vaults may share one, and a reader
holds a vault by its owner and identifier. It is one line of plain text: a
record whose `name` holds a line break or any other control character (the
code points U+0000 to U+001F and U+007F to U+009F, and the line and
paragraph separators U+2028 and U+2029) is refused (`name`), by a host as by
a reader, so that a name never writes a line of its own in a report, or
drives the terminal it is printed on. The set is fixed code points, so every
implementation refuses the same names. An owner's tooling SHOULD refuse more:
whatever a terminal filter would strip (zero-width and bidirectional
controls, characters that do not print). A renderer still filters a name
before it prints it: the record rule bounds what a name may hold, not what a
terminal will do with it.

## 4. Vault transitions

### 4.1 The vault's epoch

A vault is keyed to one borg group, named at its first token and never
changed. Every token names the epoch it **acknowledges**: the epoch every
version it lists is keyed under. The first token names the group's epoch at
the time; a later token keeps its predecessor's epoch or names a later one. A
token that names a later epoch than its predecessor's **re-keys** the vault:
from it on, everything the vault held is keyed under an epoch the vault no
longer writes under, and is **stale** until it is updated or retired.

The owner MUST acknowledge a new epoch of the group in the vault's next
transition after that epoch's token is mined (section 7.1). A host cannot
check this: whether the group has a later epoch is another record's state,
and admission reads no other record (section 11.1). It is a reader's and an
auditor's check (sections 14 and 9), and the organization's tooling's
obligation (section 8.2). Nothing makes an owner acknowledge, and section 18
says so. Nor can a host check that the epoch a token names is one the group
has begun: a reader checks the token's `epoch` and `epochId` against the
group's chain and refuses a vault that names an epoch the group has not
(section 14).

### 4.2 The rules a host checks

A vault token at `seq > 0` spends the vault token at `seq - 1` (section
12.3), and a host checks the new record against the one it spends (the
**predecessor**, read from the predecessor's transaction, which the token's
BEEF carries):

1. `transition`: `crypt`, `org`, `vault`, `hall`, `group`, `labels` and
   `anchor` equal the predecessor's, `seq` is the predecessor's plus 1, and
   `prev` is the txid of the transaction the predecessor's output is in;
2. `epoch`: `epoch` is the predecessor's or later; when it is the
   predecessor's, `epochId` equals the predecessor's; when it is later,
   `epochId` differs from the predecessor's;
3. `debt`: let the **base** be the predecessor's `count` when the transition
   re-keys (its `epoch` is later than the predecessor's) and the
   predecessor's `stale` otherwise. When the base is 0, `stale` is 0. When
   the base is not 0, `update` and `retire` together hold at most the base,
   and `stale` is the base less their number. `create` is empty unless
   `stale` is 0 (section 3.1 step 7 has already refused such a record);
4. `count`: `retire` holds at most the predecessor's `count`, and `count` is
   the predecessor's `count` plus the length of `create` less the length of
   `retire`.

At a host, rule 1 is reached only for `hall`, `group`, `labels` and `anchor`.
A parent whose token is of another crypt, owner or vault, or is not at
`seq - 1`, or whose txid is not `prev`, is not the predecessor at all, and
the token is refused earlier, as `token-input` (section 11.1 rule 8), never
as `transition`. Rule 1 lists those fields for a reader and an auditor, who
hold two tokens and no admission verdict.

Rule 3 is the property the application exists for, checked by every replica:
**once a vault acknowledges a new epoch, its chain (the tokens that descend
from its first, section 3.3) admits nothing but the re-keying or the
retirement of what it held, until nothing it holds is left under an earlier
epoch.** No secret is created, and no secret already
re-keyed is updated again, while one is stale. `vault-v1.json` pins every
rule with an admitted and a refused case.

### 4.3 Stale, and what a host cannot check

`stale` counts the secrets in the set whose current version was listed by a
token of an earlier epoch than this token's. A host checks only its
arithmetic against the predecessor (rule 3): it cannot check that the
secrets a token updates while the vault is in debt are the stale ones, since
the predecessor's record names no set. The index folds the chain and reports
`stale-mismatch` for a token whose `stale` is not the number its fold gives,
which is what an update of a secret already re-keyed produces (section 11.2).

A host cannot check that a version a token lists was written under a fresh
content key, only that no two entries of one token share a commitment
(section 3.1). The index reports an entry whose commitment an earlier token
of the vault listed as `commitment-reuse`, and every entry carries its
commitment so that an auditor checks the same from the tokens alone. The
check is per vault: a content key reused in another vault is reported by
nobody, and is the owner's breach of section 6.1. A reused key is not only
open to the earlier version's readers: with the same salt it gives anyone
the XOR of the two plaintexts and forgeable tags (section 6.2).

A host cannot check that a re-keyed version holds a new value. Nobody can:
the value is encrypted. Re-keying is enforced; changing the value is the
owner's obligation (section 8.2), and section 18 says so.

### 4.4 Anchor modes

A vault's `anchor` is fixed at its first token:

- **`0`, per version.** A reader takes only versions a mined token lists.
  Every version a conforming reader ever accepted is therefore in the trail.
  This is the mode for secrets people manage.
- **`1`, interval.** A reader MAY also take a version no token lists yet: one
  or more records that follow the listed version of the same secret, each the
  successor of the one before it (the next `version`, naming its content id
  as `previous`; the same crypt, owner, vault, secret and group; one of the
  vault's labels; another commitment than the one before; keyed under an
  epoch that is neither before the epoch of the one before nor before the
  vault's latest token's, the same epoch carrying the same epoch id and a
  later one another). No commitment repeats anywhere in the run, the listed
  version included, and a reader that folded the chain refuses a commitment
  any token listed. It MUST mark such a version **unanchored**. A reader
  that finds two different records at one version takes neither and reports
  it: the owner signed both. In a per-version vault nothing is a successor
  (`successor`). A reader that
  holds a later version it cannot link (a link is missing, dropped or
  retracted) takes the highest it can link and says that a later one exists.
  A retracted record is not a link: a run of links ends below the first
  retracted version, and a listed version that is itself retracted is
  refused (`retracted`), with nothing taken through it. A reader follows at
  most 64 unlisted versions above the listed one, asking for each only once
  the one before it was answered, so that a version a carrier claims never
  sets how far it walks; where more exist it takes the 64th and says that a
  later one exists. An owner that defers SHOULD list a secret before 64 of
  its versions are unlisted.
  An owner MUST NOT sweep a version that an unlisted successor links through
  before a token lists a later one. The owner lists the latest version of each changed secret
  in a token at an interval of its choosing; versions that came and went
  between two tokens are reached only through the `previous` links of the
  version that was listed. This is the mode for credentials machines rotate
  faster than blocks are mined. It weakens the audit (section 9.3) and the
  rollback defense (section 14), and a vault says which mode it is in so
  that a reader and an auditor know.

In both modes a token lists at most one version per secret, and versions
rise: a version a token lists is above every version an earlier token listed
for that identifier, a retired identifier's included.

## 5. The secret record

Magic `"ses"` `0x01`. The payload of a secret carrier's one output.

| Key | Field | Type and bounds | Rule |
| --- | --- | --- | --- |
| 0 | `magic` | bytes(4) | `73 65 73 01` (`"se"`, `'s'` for secret, version 1) |
| 1 | `crypt` | text; the crypt grammar | MUST equal the topic's crypt |
| 2 | `org` | bytes; the key rule | the owner, and the carrier's owner |
| 3 | `vault` | bytes(32) | the vault the secret belongs to |
| 4 | `id` | bytes(32) | the secret's identifier (section 5.2), the same for every version |
| 5 | `version` | uint, 1 to 2^53 - 1 | 1 for the first version, then one more per version |
| 6 | `previous` | bytes(32) | the content id of the record at `version - 1`; all zero exactly when `version = 1` |
| 7 | `label` | text; the label grammar | the secret's classification, one of the vault's labels |
| 8 | `group` | bytes(16) | the borg group whose epoch key wraps the content key |
| 9 | `epoch` | uint, 0 to 2^32 - 1 | the epoch |
| 10 | `epochId` | bytes(32) | the epoch's id |
| 11 | `commitment` | bytes(32) | the content key's commitment, BRC-369's digest form (section 6.1) |
| 12 | `hash` | bytes(32) | SHA-256 of the complete ciphertext |
| 13 | `length` | uint, 1 to 2^27 | the byte length of the complete ciphertext. Across fields (section 3.1 step 7): one a payload of at most 67108864 bytes produces at the record's `segment`, and at most 16384 when `inline` is present |
| 14 | `salt` | bytes(4) | the segment salt (section 6.2) |
| 15 | `segment` | uint, 16 to 1048576 | the plaintext bytes of one segment |
| 16 | `created` | uint, 1 to 253402300799 | a claim |
| 17 | `self` | bytes(80) | the content key wrapped to the owner's wallet (section 6.4) |
| 18 | `wrap` | bytes(80) | the content key wrapped under the epoch (section 6.3) |
| 19 | `inline` | bytes, 1 to 16384, optional | the ciphertext, when it is carried |

Keys 0 to 18 are always present, key 19 is optional, and keys 20 and above
are unknown to this version. The encoded record is at most 17408 bytes.

The record is BRC-369 section 4's descriptor laid out as CBOR: `org` is the
author, `epoch` the epoch, `hash`, `length`, `salt` and `segment` the content
block, `commitment` the digest-form key, `previous` the link to the
preceding version, and `inline` the inline ciphertext. It has no `release`
block: the condition is membership of the group's epoch, the releaser is the
organization, and the release of the epoch's key is borg's wrap. Section 16
lists every difference.

### 5.1 The content id

A version's **content id** is SHA-256 of its record's canonical encoding with
keys 17 (`self`), 18 (`wrap`) and 19 (`inline`) left out and every other key
kept, unknown keys included. It takes the place of BRC-369 section 4.2 rule
3's content id:

- it is fixed before any key is wrapped, and both wraps are bound to it
  (sections 6.3 and 6.4), so a wrap cannot be moved to another version;
- a vault token lists it, so the trail names each version by a value anyone
  recomputes from the record;
- it does not cover the ciphertext bytes, which `hash` covers, or the wraps,
  which only a key holder can check (section 7.2).

Two carriers may carry records with one content id (the same version
published again from another funding output). They are the same version.

### 5.2 Names, identifiers and versions

A secret's **name** is 1 to 128 bytes of lowercase ASCII letters, digits,
`.`, `_`, `-` and `/`, with no empty path segment: it neither starts nor ends
with `/` and holds no `//`. One name has one spelling. Its **identifier** is
`SHA-256("bsecret secret id v1" || vault || name)`.

The name is carried only inside the ciphertext (section 6.5); a record and a
token carry the identifier. An identifier hides a name only as far as the
name is hard to guess: anyone who guesses a name computes its identifier and
sees whether the vault holds it. Names are metadata, not secrets (section
18).

Versions of one secret form a chain: version `n`'s `previous` is the content
id of version `n - 1`. A reader that holds both checks the link. A record
whose `previous` is zero at a version other than 1 is refused (`chain`).

### 5.3 Labels

A label is 1 to 32 bytes of lowercase ASCII letters, digits and single
hyphens, starting with a letter and ending with a letter or a digit. A
vault's label set is 1 to 16 labels, fixed at its first token; unless its
owner chooses otherwise it is `confidential`, `internal`, `public`,
`restricted`.

**A label is a classification, not a mechanism.** It says how the owner
classifies the secret, and a reader refuses a record whose label is not one
of the vault's (section 7.2). It does not decide who reads: every secret of a
vault is keyed to the vault's one group, and the members of that group's
epoch read it whatever its label. An organization that wants different
readers for different secrets keeps them in different vaults, each bound to
its own group.

### 5.4 Where the ciphertext lives

- **Inline.** A ciphertext of at most 16384 bytes is carried in `inline`.
  A host checks its length and hash when it admits the record (section 3.1,
  `content`), so an admitted record's inline ciphertext is the committed one.
- **By reference.** A larger ciphertext, of a payload of up to 67108864
  bytes (at most 2^27 bytes of ciphertext, at the smallest segment), is not
  carried. It is published to content-addressed storage under BRC-26 and
  found by its hash: its locator is the `uhrp://` URL of `hash` (Base58Check
  over the prefix `ce00` and the hash), which the record need not carry
  because `hash` determines it. The owner SHOULD host it and keep its
  advertisement alive for as long as the version is current (BRC-369 section
  3.3 rule 3). A reader bounds what it fetches (section 17) and MUST verify
  length and hash before anything else (section 7.2).

## 6. Keys

### 6.1 The content key

These are BRC-369 section 2, adopted verbatim:

- the content key `k` of one version is a scalar sampled uniformly from
  `[1, n-1]` with a cryptographically secure generator, fresh for each
  version, and MUST NOT be derived from any identity key, any epoch key, the
  content, any other version's key or any other reusable secret (BRC-369
  section 2.1 rules 1 and 2);
- the symmetric key is `SHA-256("metanet keyed content symmetric v1" || k)`,
  `k` as 32 bytes big-endian;
- the commitment is `SHA-256("metanet keyed content commitment v1" || k)`,
  BRC-369's digest form. The point form is not used: it rests the content's
  confidentiality on the discrete logarithm problem (BRC-369 section 2.2), and
  a secret is meant to last;
- the symmetric key MUST NOT be derived from the commitment (BRC-369 section
  2.1 rule 4).

A new version always has a new content key, a re-keying included. A version
that reused an earlier version's key would be open to everyone who held the
earlier one, whatever epoch it is wrapped under.

### 6.2 Segments

BRC-369 section 2.3's construction, with bounds it leaves open (the segment
size is 16 to 1048576 bytes, the plaintext is 1 to 67108864 bytes, and a
length with a last segment that is only a tag is refused). The payload is
encrypted in segments
of `segment` plaintext bytes, the last one shorter or equal, each under
AES-256-GCM with the symmetric key, no associated data, and the 12-byte IV
`salt || i` (the 4-byte salt, then the segment index from 0 as eight bytes
big-endian). Each segment's ciphertext is followed by its own 16-byte tag,
and the complete ciphertext is their concatenation. The salt MUST be drawn
fresh for each content key.

`length` MUST be a length some plaintext of at least one byte produces: not
zero, and not one that leaves a last segment of 16 bytes or fewer. A reader
MUST verify every segment's tag before it treats any of the plaintext as
content.

A ciphertext cut at a segment boundary is a shorter ciphertext whose every
tag still verifies. Only `length` and `hash` catch it, which is one reason
the hash check comes first (section 7.2).

**A content key and salt used twice break both versions without any key.**
Two ciphertexts under one key and one salt reuse every IV: anyone who holds
both (and inline ciphertexts are public) has the XOR of the two plaintexts,
segment by segment, and can forge tags for either. A fresh key per version
(section 6.1) is the guard, and the salt is a second one only while the key
is fresh. The owner's tooling MUST refuse to publish a version whose
commitment it has ever published or listed, in this vault or any other of
its own, and labels the refusal `commitment-reuse`, the name the index gives
the same fault; hosts and the index see a repeat only within one vault
(section 4.3).

### 6.3 The epoch wrap

`wrap` is the content key encrypted for the members of the record's epoch:

- the **wrapping key** is
  `SHA-256("bsecret epoch wrap v1" || s || contentId)`, where `s` is the
  epoch's BRC-369 symmetric key, `SHA-256("metanet keyed content symmetric v1"
  || epoch key)`, and `contentId` is the version's content id;
- `wrap` is BRC-2's symmetric form under the wrapping key: AES-256-GCM with a
  32-byte IV drawn at random, written `IV || ciphertext || tag`, 80 bytes for
  the 32-byte scalar.

The epoch's symmetric key is never used as a cipher key here. It is an input
to a hash whose output wraps exactly one content key: the content id covers
the commitment, so another key gives another content id and another wrapping
key. No two versions, no two vaults and no other application's use of the
same epoch key share a wrapping key.

A member opens `wrap` with the key of **the epoch the record names**, and
with no other. It holds that key from borg's wrap (borg's member checks: the
group token that began the epoch verifies against the member's own headers
and hashes to the epoch id; the member's wallet decrypts its wrap; the key
matches the token's commitment). A holder of another epoch's key derives
another wrapping key, and `wrap` does not open.

**Which key a wrap is under is checkable only with that key.** A record
names its epoch, and the content id covers the name, not the wrap. An owner
could name epoch `e + 1` and make the wrap under epoch `e`'s key: every check
a host, an index or an auditor can make passes, and a removed member who
tries its old key opens the version. The members of epoch `e + 1` see it at
once, as a wrap that does not open under a key they verified, which names
the owner (section 7.2); nobody without that key sees it at all. This is why
a reader never tries a key of another epoch than the one named
(`secret-v1.json`, `misKeyed`), and it is a limit of the audit (section 9.3).

### 6.4 The self wrap

`self` is the content key encrypted to the owner's own wallet: a BRC-100
`encrypt` (BRC-2) under BRC-43 protocol `[2, "bsecret self"]`, key id the
standard padded base64 of the content id, counterparty `self`. It is 80
bytes. The owner's wallet `decrypt`s it with the same arguments.

The self wrap is what makes the wallet the owner's only credential: any
instance of the owner's tooling that holds the organization's identity key
opens every version of every secret it ever wrote, from the hosts alone, with
no key file and no epoch key (section 8.5). Only BRC-42 derivation touches
the identity key; the content key is random.

### 6.5 The payload

Magic `"sep"` `0x01`. The plaintext the ciphertext holds.

| Key | Field | Type and bounds | Rule |
| --- | --- | --- | --- |
| 0 | `magic` | bytes(4) | `73 65 70 01` (`"se"`, `'p'` for payload, version 1) |
| 1 | `name` | text; the name grammar (section 5.2) | MUST hash to the record's `id` |
| 2 | `value` | bytes | the secret |
| 3 | `type` | text, 1 to 128 bytes, optional | a media type |
| 4 | `notAfter` | uint, 1 to 253402300799, optional | when the value stops being usable, a claim |
| 5 | `rotateEvery` | uint, 1 to 2^32 - 1, optional | seconds between the rotations the owner intends. Informative |
| 6 | `pad` | bytes, at least 1, optional | padding; its content is ignored |

Keys 0 to 2 are always present; keys 7 and above are unknown to this version.
An encoded payload is at most 67108864 bytes: a record whose `length` is one
that a larger plaintext produces is refused (section 3.1), so every admitted
record describes a ciphertext a conforming reader can open. A writer SHOULD
pad the encoded payload to a multiple of 256 bytes, so that a
ciphertext's length says little about its value's.

## 7. Writing and reading

### 7.1 The writer

The owner's tooling writes a version in this order: sample `k` and the salt;
encode and pad the payload; seal it; build the record without its wraps;
compute the content id; wrap `k` to itself and under the epoch; publish the
carrier; list the version in the vault's next token.

Before it builds any vault transition the tooling MUST hold positive
evidence, obtained within the last 60 seconds (configurable, never more than
600), of two things:

1. **the vault's latest token is the latest:** its proof verifies against the
   tooling's own headers and its 1-satoshi output is unspent according to a
   source that indexes spends;
2. **the group's latest epoch is the latest:** the same, for the group's
   latest token (borg's writer rule).

When the group's latest epoch is later than the vault's, the only transition
the tooling builds is the one that acknowledges it. Without the evidence the
tooling MUST NOT write: it fails closed.

The tooling decides that a transition took effect only when a transaction
spending the predecessor's token output is mined in its own headers **and**
that transaction's vault record is byte for byte the record it built: not
when a broadcast service accepted its transaction (a service's acceptance is
not the network's, and a double spend can be accepted and then never mined),
and not by its own txid alone (a copy of its transaction with re-encoded
unlocking scripts has another txid and the same record, and is the same
transition).

The tooling gives up a transition or a sweep it has persisted only on
positive evidence that another transaction took its place: a source that
indexes spends names a different spender of the predecessor's token output
(for a sweep, of a funding output it spends). With no other spender it is
never given up, whatever a broadcast service answered and however long it
stays unmined: the same bytes are offered again, and nothing else is built
on the output it spends. A node that cannot say, or a spender it cannot
show, is not evidence.

### 7.2 A reader's checks, in order

A reader that wants a secret's value performs these checks in this order and
stops at the first failure. Each failure names its own culprit.

| # | Label | Check | A failure means |
| --- | --- | --- | --- |
| 0 | `listing` | the set of the vault's latest token (section 14) holds this version: an inclusion path that names the token by `seq` and txid takes the leaf of the record's `id`, `version` and content id to the token's `root` (or the reader folded the chain); the record names the token's crypt, owner, vault and group; its `label` is one of the vault's; and it is keyed under the token's epoch and epoch id, or, only while the token's `stale` is not 0, under an earlier epoch with another epoch id. Every epoch and epoch id it relies on is one the group's chain began (section 14). In an interval vault an unlisted record is instead checked as a successor of one that passed (section 4.4, `successor`) | the host answered another version, or the owner listed under a new epoch a record keyed under an old one |
| 1 | `hash` | the ciphertext (inline, or fetched by its locator) is `length` bytes and hashes to `hash` | **the host or store that served the bytes substituted or cut them** |
| 2a | `undecryptable` | a wrap opens: `self` through the owner's wallet, or `wrap` under the wrapping key of the epoch the record names, and of no other epoch; the result is exactly 32 bytes and a scalar in `[1, n-1]`. A reader that was not a member of the named epoch holds no key to try, and stops here | for a reader that holds the named epoch's key, verified against the group's commitment: **the owner wrapped under another key, or wrapped something that is not a key** |
| 2b | `commitment` | the scalar matches `commitment` | **the owner wrapped a key other than the one it committed to** |
| 3 | `tag` | every segment's tag verifies under the scalar's symmetric key | **the owner encrypted under a key other than the one it committed to**; publishing the key proves it to anyone (BRC-369 section 5.4) |
| 4 | `payload` | the plaintext decodes as a payload and its `name` hashes to the record's `id` | the owner published another secret's payload under this identifier |

Checks 1, 2b and 3 are BRC-369 section 5.3's three checks in their order.
Checking the tag first would conflate a substituted ciphertext, a wrong key
and a dishonest owner into one error. The order binds an implementation's
whole read, not each function in it: the ciphertext's length and hash are
checked before any wrap is opened, so that a substituted ciphertext beside a
wrong wrapped key reads `hash`, never `commitment`. The codec's read entry
points do this, and `keyed-v1.json` holds cases with two faults that only the
right order gets right. `keyed-v1.json` pins each failure, and
`brc369-v1.json` runs the same code on BRC-369's own vectors.

A member reads the epoch's key from borg before check 2a. Borg's own checks
apply to it, and a member that cannot verify the token that began the epoch
does not use the key. borg asks a reader to authenticate an object's author
as a member of the epoch it names; here the author is the organization, which
is never a member, so a reader instead checks that the vault's `org` is the
organization of the group the vault names: the group's tokens are locked to
the same identity key.

Beside these labels a reader reports `retracted` (a mined sweep spends the
record's funding outpoint, section 14: checked with the listing, before the
ciphertext is read), `successor` (section 4.4) and `rollback` (section 14).
The codec also labels a refused question `query` and anything it has no
label for `other`.

A check that fails names its culprit and refuses the read. A host that
answers something that does not verify is another matter (section 14): it is
not a check that failed on what is read.

### 7.3 What a reader reports

Beside the value, a reader reports, for the version it read:

- **anchored** or **unanchored** (section 4.4);
- **current** or **exposed**. A version is exposed when it is keyed under an
  epoch before the group's canonical latest epoch: someone the group has
  since removed, or a key the group has since rotated away from, opens it.
  A reader learns the group's latest epoch from borg as it learns the
  vault's latest token (section 14). A consumer that acts on an exposed
  value does so knowing it; a consumer MAY refuse one;
- the vault's state: **settled** (`stale` 0 and its epoch the group's
  latest), **in debt** (`stale` above 0), **behind** (its epoch before the
  group's latest) or **ahead** (it names an epoch the group has not begun,
  or another epoch id than the group's for that epoch). A reader takes
  nothing from a vault that is ahead: its owner wrote a token no honest
  tooling writes.

**Current needs both chains.** A reader reports a version as current only on
positive evidence of two things, as a writer's (section 7.1): the vault's
latest token is unspent, and the group's latest token, as the hall's hosts
answer it, is unspent, each according to a source that indexes spends. The
second matters as much as the first: a removal that the hall's hosts have
not answered yet, or withhold, leaves the vault looking settled and the
value looking current under an epoch that has ended. A reader that cannot
tell (it has no source that says a token is unspent, or the source cannot
say) says so, and does not report a version as current.

**Freshness is taken at the read.** The evidence is taken when the value is
read and covers that moment only. A reader that keeps a value (a process
that reads at its start, a cache, a file) keeps its age with it: the value
is as current as the read was, and a consumer that needs a current value
reads again.

## 8. Changes and revoke

Every change is one or more carriers plus a mined token. The organization's
tooling builds, signs, waits for the proof, and publishes in the order of
section 8.3.

### 8.1 The flows

- **Create a vault.** Mint a chain tree and a secret tree (section 12.4) and
  wait until both are mined; publish the first secrets' carriers; mint vault
  token `seq` 0 spending one output of the chain tree, with the vault
  identifier that outpoint gives, the group and its latest epoch, the label
  set and the anchor mode; once it is mined, publish it with the chain tree
  in its BEEF.
- **Put a secret.** Publish its carrier, then list it in the vault's next
  token: in `create` at version 1, or at a version above the last one a
  retired identifier had.
- **Update a secret.** A new version with a new content key and salt,
  `previous` naming the version before; publish its carrier, then list it in
  `update`.
- **Grant a reader.** The organization adds the reader's key to the vault's
  group (borg). Nothing changes in the vault: borg wraps the current epoch's
  key to the new member, who then opens every version keyed under that
  epoch, the ones written before it joined included. A group that sets
  borg's `rotateOnJoin` begins a new epoch instead; the joiner then reads
  only what is re-keyed under it, and the vault re-keys as after any new
  epoch.
- **Grant a reader that was removed before.** borg requires the transition
  that re-adds a removed key to begin a new epoch, so that the returning key
  reads from that epoch on. A borg host cannot check it (borg's index
  reports a token that does not as `rejoin-unrotated`); the organization's
  tooling MUST rotate. If it did not, the returning key holds the current
  epoch's key and opens everything keyed under it, what was written while it
  was away included.
- **Revoke a reader.** Section 8.2.
- **Rotate on a schedule, or after a suspected leak.** The organization
  rotates the group (borg), and the vault re-keys as after any new epoch.
  Rotation on removal gives forward exclusion, not recovery (BRC-369 section
  8.4): a vault whose epoch key has leaked stays exposed until the group
  rotates and the vault re-keys.
- **Retire a secret.** List its identifier in `retire`, and sweep the
  funding outputs of its versions' carriers (section 12.5) so that honest
  hosts stop answering them. A retirement sweeps only the versions of the
  secrets it retires, whatever epoch they are keyed under (and, as every
  change does, versions published and never listed, section 8.4). It leaves
  every other secret's replaced versions alone: those, where they are keyed
  under an epoch that has ended, are a rotation's to sweep (section 8.2).
- **Retire a vault.** Retire every secret and sweep. The tokens stay: they
  are mined.

### 8.2 Revoke

To **revoke** a reader is to remove its key from the vault's group and to
re-key the vault. It has three parts, and it is complete only when all three
are done:

1. **The removal** (borg). The organization mints a group token that removes
   the key. Every borg host refuses a removal that does not begin a new epoch
   with a new key commitment, and the new key is wrapped only to the members
   who remain. The organization also revokes the reader's grant when it
   leaves the organization.
2. **The acknowledgement.** The vault's next token names the new epoch.
   Every secret the vault holds is then stale, and section 4.2 rule 3 holds
   the vault's chain to re-keying and retiring until none is.
3. **The rotation.** For every secret in the vault: a new version under a
   new content key, wrapped under the new epoch, listed in `update`; or its
   retirement. Up to 64 secrets a token; a larger vault takes several
   tokens, one a block.

**Re-keying is not enough for a credential.** The removed reader could read
the old value, so a secret that is a credential (a password, a token, a key)
MUST be given a new value in its re-keyed version, and the old value MUST be
disabled wherever it was accepted. bsecret stores and distributes the new
value; changing it at the service that accepts it is the owner's, through
whatever produces the new value. A secret whose value cannot change (a
document, a key that cannot be replaced) is re-keyed with the same value, so
that later members and later versions are under the new epoch; the removed
reader still knows it, and nothing makes it unknown.

The organization's tooling MUST NOT begin a revoke it cannot finish: before
it mints the removal it has, for every secret of every vault keyed to a group
the key is removed from, a new value, an explicit choice to re-key the same
value, or an explicit choice to retire. It MUST NOT build any other vault
transition while a vault is behind its group or in debt (a host refuses the
second; a reader and an auditor see the first). After the rotation it SHOULD
sweep the carriers of the versions keyed under epochs that have ended, unless
the owner keeps history on purpose (section 15). A rotation sweeps by epoch,
once the vault is settled: every version a later token replaced or retired
that is keyed under an epoch before the one the vault now acknowledges. It
never sweeps a version the set holds.

The removal is borg's command, and nothing in bsecret can stop it. So the
check that a revoke can be finished is a step of its own, made before the
removal: `bsecret rotate -check`, given the choices, builds nothing and
fails when any secret of the vault has none; it is run for each vault keyed
to the group. It is the documented step before borg removes anyone. An organization that removes
first has begun a revoke it may not be able to finish, and the trail shows
how long it took (section 9.2).

**Rotation debt** is a vault that is behind its group, or whose `stale` is
not 0. Anyone can compute it from the two chains (section 14), and the
tooling reports and clears it.

### 8.3 Publication order

- A carrier is published before the token that lists it, so that a host
  holds the record when it answers the set.
- A token is published only after it is mined, with its proof and with the
  transaction its predecessor input spends (section 11.1), and only once the
  block holding it is in the publisher's headers and a propagation delay has
  passed (60 seconds by default), so that the hosts' headers have it too. A
  host whose headers still lack the block refuses it (`unmined`), raising, so
  nothing is recorded; the publisher confirms the token at every host it
  names by lookup and offers it again to any that lacks it.
- A version keyed under a new epoch is published only after the group token
  that began the epoch is mined in the publisher's own headers and borg's
  wraps of the epoch's key are published. Otherwise the remaining members
  could not open it, or it would be keyed under an epoch the chain never
  began. The tooling checks it before it re-keys: while a current member of
  the group has no wrap of the new epoch answered by any host of the hall,
  the rotation stops as incomplete (exit 3 in the tooling here) and is run
  again once borg has published them. `-unwrapped` is the explicit override,
  for an owner that accepts that a member cannot open the new versions yet.
- A sweep is published after it is mined, under the same delay as a token,
  in every crypt that holds a version it retracts (section 12.5).
- The publisher confirms every object at every host it names by lookup, and
  offers it again where it is missing (section 13). An object the plane took
  is not thereby at every host.

### 8.4 Concurrent changes

Two transitions built on the same tip spend the same output, and at most one
of them is ever mined: the chain is the serialization point, and no host
merges. The losing side reads the new tip (section 8.5) and builds its change
again on top of it. Versions it published and never listed stay unlisted;
it sweeps them. A single instance never builds two transitions on one tip.

### 8.5 More than one instance, and a new machine

Everything an instance of the owner's tooling needs to go on from another
instance's change is at the hosts. An instance **catches up** by reading as
any reader does (section 14): each vault's chain from `seq` 0 against its own
headers, folded; every current secret's record; and each content key from its
self wrap, which needs only the organization's identity key. To write, it
needs the key of the group's latest epoch, which it has from borg's own
catch-up (the wrap to the organization's signer key). It does so after losing
a concurrent change, whenever its spend source shows a vault's latest token
spent, and once when it starts on a new machine.

What catching up cannot bring back: a version published and not yet listed
whose carrier no host kept; another instance's funding trees and unpublished
objects. Two instances MUST NOT fund carriers from one funding tree: of two
carriers on one funding output a host answers one (section 11.2), and one
sweep retracts both.

A member's client keeps nothing it cannot fetch again: the epoch keys come
from borg's wraps, and the records from the hosts. It SHOULD keep, per vault,
the highest `seq` it has verified (section 14).

## 9. The audit trail

### 9.1 What the trail is

A vault's trail is its chain of mined tokens. Each token is a statement the
owner signed and a miner ordered: these secrets were created, these were
given these versions, these were retired; the vault now acknowledges this
epoch; this many secrets are still under an earlier one. The group's chain
(borg) is the other half: who was added and removed, and when each epoch
began.

### 9.2 What an auditor verifies, with block headers alone

An auditor is handed the vault's tokens and the group's, each as a
transaction with its Merkle path. It needs no host's cooperation to get them:
every token names its predecessor's txid, so the chain is walked back from
any token through any source of mined transactions. It holds no key and reads
no secret. With its own block headers it checks, for each token:

1. **Mined.** The Merkle path takes the txid to the root of a header in the
   auditor's best chain. The header's height orders the token and bounds its
   time.
2. **The owner's.** The token's output is the well-formed vault token locked
   to the key derived from `org` (section 12.3), and its field signature
   verifies.
3. **Linked.** The trail starts at `seq` 0. An input of the token at `seq`
   spends the token output of the transaction `prev` names, whose record is
   the token at `seq - 1` of the same vault, mined at the same height or
   below. The chain from `seq` 0 is therefore complete: no token can be left
   out of the middle. The first token spends the outpoint the vault
   identifier hashes (section 3.3), so the auditor holds the vault's one
   chain, and a token that does not descend from that first token is not
   part of it.
4. **Lawful.** Every transition meets section 4.2 against its predecessor.
5. **Consistent.** The fold of the change lists reproduces every `count`,
   `root` and `stale`, no version fails to rise, and no commitment repeats
   (section 11.2).
6. **Keyed to the group.** Every token's `epoch` and `epochId` are those of
   a token that began that epoch on the canonical chain of the group the
   vault names (the vault's `org`, `hall` and `group`; borg: the group
   record's hash is the epoch id), mined at a height not above the vault
   token's.

An audit fails when any of these fails. A token whose fold is not
`consistent` fails it: from that token on, the vault's own counts are not
believed.

From these the auditor derives, for every epoch the group began after the
vault's first token: the height the group began it and whether it removed
anyone; **how many vault tokens mined above that height still named an
earlier epoch** (an owner that went on writing under the old key); the
height of the first vault token that acknowledged it; the height of the
first vault token after which the fold, not the token's own `stale`, holds
nothing listed under an earlier epoch; and, for every secret, the height at
which it was re-keyed or retired. The difference between the first and the
last is the **exposure window** the owner's signed statements give for that
removal: how long each secret stayed listed under an epoch a removed member
held. `audit-v1.json` works the scenario's trail, the same trail cut short, a
vault that never acknowledges, and the trails an audit refuses.

### 9.3 What the trail does not prove

- **That the token it ends at is the latest.** A trail can be cut at its
  end. That a token's output is unspent comes from an index, never from
  headers. An audit states the token it ends at, and covers nothing after
  it.
- **That a listed version's record is what the token says.** A content id is
  a hash. To check that the version is keyed under the epoch of the token
  that listed it, has the commitment the entry names and links to its
  predecessor, the auditor needs the record, from any host that still holds
  it or from the owner; the content id makes it self-certifying wherever it
  comes from. An owner that
  lists a content id whose record is keyed under another epoch has signed a
  false statement in a mined token, which is evidence, but headers alone do
  not show it.
- **Which key a wrap is under.** The trail, and the records behind it, say
  which epoch each version names. That its wrap is under that epoch's key is
  checkable only with the key (section 6.3). The window an audit reports is
  what the owner signed, confirmed every time a remaining member reads the
  version, and not otherwise.
- **That the owner acknowledged in time.** The audit counts the tokens that
  kept an earlier epoch after a later one began, and how long it took; it
  cannot make the owner acknowledge, and an owner that never does keeps a
  chain every host admits.
- **That a value changed.** A re-keyed version may hold the old value.
- **Who read what.** Reads leave no footprint. The trail proves grants (in
  borg), versions and removals, never an access.
- **What was read between tokens, in an interval vault.** Versions that were
  published, read and replaced before a token listed them are reached only
  through `previous` links, and only if their records survive. A per-version
  vault has no such gap: every version a conforming reader accepted is
  listed.
- **Times finer than blocks.** `created` is a claim.

## 10. Crypts and lookup

### 10.1 Crypt identifiers and topics

A crypt's topic is `tm_bsecret_<name>_<suffix>`, and its **crypt identifier**
is `<name>_<suffix>`:

- `<name>` is the readable part: 1 to 28 bytes of lowercase ASCII letters and
  single underscores, starting and ending with a letter;
- `<suffix>` is exactly 10 lowercase ASCII letters, each drawn uniformly at
  random from `a` to `z` by whoever creates the crypt, once, when it creates
  it, and never changed.

The identifier is 12 to 39 bytes and splits at its last underscore. The whole
topic is a BRC-87 topic manager name of at most 50 characters. The
`tm_bsecret_` namespace belongs to bsecret. The identifier, never the
readable part, is what every record's `crypt`, every question and every topic
carries; a renderer that shows the readable part SHOULD show the suffix
beside it.

The object plane is shared: anyone may publish to any topic, and readable
names collide. A suffix drawn at random once per crypt makes an accidental
collision negligible (about 2^-47 for any one pair). It is not a secret and
not an access control. A host advertises the crypts it carries by BRC-88 SHIP
like any other topic.

### 10.2 The lookup service `ls_bsecret`

One lookup service per host answers for every crypt the host carries. It
answers BRC-24 questions of exactly these classes:

| Class | Question (`query` object) | Answer (`output-list`) | Price |
| --- | --- | --- | --- |
| `vault` | `{"crypt": c, "org": o, "vault": v}` | the vault's latest tokens: those at the highest `seq` among its rooted tokens (section 11.2), at most 8 | free |
| `vault-seq` | `{"crypt": c, "org": o, "vault": v, "seq": s}` | every token the host holds for the vault at `seq` `s`, rooted or not, at most 8 | free |
| `vaults` | `{"crypt": c, "vaultsOf": o}` | the latest rooted token of each of `o`'s vaults that has one, first page | free |
| `vaults-after` | `{"crypt": c, "vaultsOf": o, "after": v}` | the same, after the vault identifier `v` | free |
| `secret` | `{"crypt": c, "org": o, "vault": v, "secret": i}` | the carriers of the version of `i` the vault's set holds, at most 8, each with its inclusion path as context | free |
| `version` | `{"crypt": c, "org": o, "vault": v, "secret": i, "version": n}` | the carriers held for version `n` of `i`, at most 8 | free |
| `pending` | `{"crypt": c, "org": o, "vault": v, "pending": i}` | the carriers held for versions of `i` above the one the set holds, highest version first, at most 8; a reader fetches the links below them by `version` | free |
| `secrets` | `{"crypt": c, "org": o, "secretsOf": v}` | the carriers of every version the vault's set holds, first page | free |
| `secrets-after` | `{"crypt": c, "org": o, "secretsOf": v, "after": i}` | the same, after the secret identifier `i` | free |
| `label` | `{"crypt": c, "org": o, "vault": v, "label": l}` | the carriers of the set's versions whose label is `l`, first page | free |
| `label-after` | `{"crypt": c, "org": o, "vault": v, "label": l, "after": i}` | the same, after the secret identifier `i` | free |
| `sweep` | `{"crypt": c, "spent": p}` | the admitted mined transactions that spend the outpoint `p`, at most 8 | free |
| `history` | `{"crypt": c, "history": o, "vault": v, "secret": i}` | the carriers the host holds for every version of `i`, first page | priceable |
| `history-after` | `{"crypt": c, "history": o, "vault": v, "secret": i, "after": n}` | the same, after version `n` | priceable |
| `audit` | `{"crypt": c, "audit": o, "vault": v}` | every token of the vault's chain, first page | priceable |
| `audit-after` | `{"crypt": c, "audit": o, "vault": v, "after": s}` | the same, after `seq` `s` | priceable |

The query is validated as parsed, so hosts in any language reach the same
verdict. A member given twice takes its last value, as JSON parsers do. Every
member is a string: `crypt` meets the crypt grammar; `org`, `vaultsOf`,
`history` and `audit` are 66 lowercase hex digits whose bytes meet the key
rule and are not the anyone key; `vault`, `secretsOf`, `secret` and `pending`
are 64 lowercase hex digits; `seq` is a decimal from 0 to 2^53 - 1 and
`version` from 1 to 2^53 - 1, with no leading zero; `label` meets the label
grammar; `spent` is BRC-100's `OutpointString` (`<txid>.<index>`, txid in
display order, index in decimal from 0 to 2^32 - 1 with no leading zero); `after` is a vault
identifier for `vaults-after`, a secret identifier for `secrets-after` and
`label-after`, a version for `history-after` and a `seq` for `audit-after`. A
question MUST carry exactly the members of one class. A missing member, a
member no class defines, or a value that breaks these rules is refused with
an error, never answered empty and never ignored. A question that names a
crypt the host does not carry is refused with an error too.

**The set an answer uses.** `secret`, `secrets`, `label` and `pending` use
the set of one token: the highest rooted token at or below which, on its own
branch, no token is `set-mismatch` or `stale-mismatch` (section 11.2). Where
two rooted tokens share that `seq` (section 11.5), the host uses the one
whose proof verifies against its headers, or, when it cannot tell, the one
with the lowest txid; the context names the token it used, so a reader that
chose the other asks again or folds; a `commitment-reuse` token
does not stop the set, and a reader that folds refuses the version it lists
(section 14). They answer only carriers whose status is `listed` (for
`pending`, `unlisted`). A version the set holds whose carrier the host does
not hold is simply not answered: a reader sees the gap when it checks the
root. When the answering token is below the vault's latest, the context's
`seq` says so, and a reader's first check fails (section 7.2).

**Latest.** A vault's latest tokens are those at the highest `seq` among its
rooted tokens. A host answers every candidate at that `seq` (up to 8),
whether or not its stored proof still verifies against the host's headers:
after a reorganization a host cannot take a new proof for a token it holds
(section 11.5), so leaving one out would hide the vault's tip for good. A
reader always chooses among them itself, with its own headers (section 14).
A token that is not rooted is answered only by `vault-seq`.

**Which carriers are answered.** `version` and `history` answer the carriers
held for a version whose status is `listed`, `unlisted` or `mismatched`;
`pending` those that are `unlisted`. No class answers a `retracted` or a
`superseded` carrier. `sweep` answers every admitted sweep the host holds
that spends the outpoint, those in the bounded table (section 11.1) while
they are in it.

**Order and pages.** Vaults are in ascending order of vault identifier,
secret carriers by secret identifier then version then txid (display order),
tokens by `seq` then txid. A page holds at most 64 tokens or 16 secret
carriers; the `-after` classes answer only what sorts strictly after the
cursor. An `audit` page never splits a `seq`, and a `secrets`, `label` or
`history` page never splits one secret's or one version's carriers.

**Inclusion paths.** Each output of a `secret`, `secrets` or `label` answer
carries, as its BRC-24 `context`, the canonical CBOR array
`[seq, token, index, size, path]`: the `seq` and the txid (bytes(32), hash
byte order) of the vault token whose set the answer used, the secret's leaf
index in that set, the set's size, and the RFC 6962
inclusion path as an array of `[bytes(32), bool]` steps from the leaf upward,
the bool `true` when the sibling is on the left (bcommon `commit.Prove`). A
reader verifies the path from the leaf of the record's `id`, `version` and
content id to that token's `root` (bcommon `commit.Verify`), so one secret is
checked without reading the set. A context is at most 2048 bytes and 32
steps; `size` is 1 to 4096 and `index` is below `size`. A path that does not
verify is ignored, and the reader falls back to folding the chain or reading
the set. **A path proves that the token's root holds this leaf, and nothing
else:** not that the root holds no second leaf for the same identifier, not
that the chain's counts are true. Only a fold proves those (section 14). `vault-v1.json`
carries one.

An empty answer means only that this host holds nothing that answers: a
reader MUST NOT read it as proof that something does not exist. The engine
hydrates each answered output as BEEF, so a reader verifies a token or a
carrier with its own block headers; after a reorganization a stored proof may
name a block that is no longer in the best chain, and the reader then fetches
the transaction's current proof from a chain source by its txid (section
11.5).

### 10.3 Free and priceable

A price attaches to a question class, never to part of an answer. The twelve
free classes are answered at no price, without authentication, on every
conforming host. No priced class is a superset of a free class: the priceable
classes carry `history` or `audit`, which no free class carries, and lack
`org`, so no spelling turns a free question into a priced one; and an unknown
member is refused, never ignored. Everything a reader needs to read a secret,
check a vault's state or check a retraction is free; the priceable classes
sell the bulk walk of a secret's versions and of a vault's chain, which the
free `version` and `vault-seq` give one at a time.

A priced question is asked on the same BRC-24 `/lookup` route over BRC-104
authentication; the host answers 402 with BRC-105's headers and answers the
question once paid. This contract fixes what BRC-105 leaves open: the payment
is output 0 of the transaction in BRC-105's `x-bsv-payment` header, a P2PKH
output of at least the price to the key BRC-29 derives for the payee
(protocol `[2, "3241645161d8"]`, the asker as counterparty). A host that
prices anything publishes its terms at `GET <base>/ls_bsecret/terms`, where
`<base>` is the base URL of `ls_bsecret` (BRC-180 rule 2: a service defines
its own routes under it), as JSON
`{"service": "ls_bsecret", "terms": 1, "classes": [{"class": c, "satoshis": n}]}`.
The document is informative; the 402's headers are what a client pays
against, and a host that serves no terms (404) charges for nothing. No price
is ever in a record.

**A priced route has a budget.** A BRC-103 handshake is unauthenticated and
costs the host a signature. A host that prices any class MUST bound that
work: it answers handshakes from a budget for the route and a budget for each
remote address, checked before any signature is made, and answers 429 with
`Retry-After` over either; it caps the sessions it keeps and forgets idle
ones. [limits.md](limits.md) gives the defaults. A 402 costs a host nothing
it keeps.

## 11. The host

### 11.1 Admission by `tm_bsecret_<name>_<suffix>`

**What a verdict may depend on.** An admission verdict depends only on the
bytes of the submission (the transaction and the transactions its BEEF
carries, each bound to it by its txid) and the host's block headers. It never
depends on another topic, on anything this topic holds, or on the order
objects arrived in. In particular it never reads the group's chain, a vault's
set or another secret's record. A topic manager that reads another record
while it admits is not stable on the reference engine: the engine checks
every topic before it writes any and holds no lock across submissions, so the
same transaction is admitted or refused by arrival order, and two hosts end
with different sets. So a vault token carries its predecessor's transaction
in its own BEEF, and the topic manager reads the predecessor's record from
those bytes; every question across records (is this the group's latest
epoch? does a token list this record? is this the secret's current version?)
is a status the lookup service computes and a reader checks (sections 11.2
and 14). The engine hands a topic manager the indices of the inputs whose
outputs the topic holds (its previous coins, BRC-22); they decide only which
held outputs an accepted transaction retains, and every spend a rule reads
is checked against the transaction in the BEEF. SPV of the BEEF is the
engine's and runs before the topic manager, including the script of an
unproven transaction's inputs against the outputs they spend. Checks then run
in the order given; a transaction is refused for the first rule it breaks,
with that rule's reason.

**Admit or raise.** An overlay engine records every transaction its topic
manager returns admittance instructions for, empty ones included, and treats
a later submission of the same txid as a duplicate no topic manager sees
again. A recorded refusal would let anyone suppress a genuine object by
submitting it first in a different BEEF, would keep a token refused for a
block the host's headers did not yet have refused forever, and would keep a
host that upgrades from admitting what it refused before. So a topic manager
returns admittance instructions only for a transaction it admits (at least
one output admitted), and **raises for every refusal**; the engine then
stores nothing.

**The BEEF.** Every refusal of a submission's BEEF carries the one label
`beef`: a BEEF over the host's bound (at least 262144 bytes); one that does
not parse as exactly one BEEF V1 (BRC-62), BEEF V2 (BRC-96) or Atomic BEEF
(BRC-95) with nothing after it; one without its subject transaction; one that
holds anything but what the object needs. A BEEF that is over the bound or
does not parse is refused before anything else; what it must hold depends on
what the subject transaction claims, and is decided at the `beef` step of
each list below, after `shape`:

- a **carrier**: exactly two transactions, the carrier and the funding tree
  its input spends, and exactly one Merkle path, the tree's;
- a **vault token**: exactly two transactions, the token and the transaction
  that its predecessor input (at `seq` 0, its funding input) spends, and
  exactly two Merkle paths, one for each, or one merged path when both are in
  one block. This is a BEEF V1 or V2, never an Atomic BEEF: BRC-95 allows in
  one only the subject and the ancestors needed to validate its inputs, and a
  mined token needs none, so its parent would be an unrelated transaction;
- a **sweep**: exactly one transaction and its own Merkle path.

Every path is minimal: at its lowest level exactly the proven txid, flagged
as the txid, and its sibling (a hash, or a duplicate flag); above that exactly
one leaf a level. When a token and its parent are in one block, the BEEF
holds exactly one path, the union of the two minimal paths, flagging exactly
the two txids and holding no other leaf; it MAY omit a sibling that is itself
an ancestor of the other txid, and nothing else. Two separate paths for a
token and a parent mined in one block are refused (`beef`). Every transaction
is carried whole: a txid-only entry (BRC-96) is refused. The counts are those
the BEEF declares on the wire, before any parser merges or collapses
anything.

Every script comparison below is byte for byte against the script rebuilt
from the decoded fields and the derived key, exactly as bcommon `pushdrop`
writes it: the 33-byte compressed key, `OP_CHECKSIG`, each field as one
minimal push, the signature as one minimal push when the output is signed,
and the fewest `OP_2DROP` then `OP_DROP` that clear the fields.

**Classify.** An output's locking script is read only as far as this: it
starts with `0x21`, 33 bytes and `0xac`, then one push (an opcode `0x01` to
`0x4b`, or `OP_PUSHDATA1`, `2` or `4` with its little-endian length, every
declared byte present). The output **claims a secret** when that push's data
starts with a CBOR definite-length map head, `00 44` and `73 65 73 01`, **a
vault token** when the data is exactly `73 65 01`, and it is
**funding-shaped** when the whole script is `0x21 <33 bytes> 0xac 03 73 65 02
75` (`script-v1.json`). A transaction with more than one claiming output is
refused (`shape`).

**Secret carrier.** A transaction whose one claiming output claims a secret.
The owner is the record's `org`:

1. `shape`: it does not have exactly one input and exactly one output;
2. `beef`: the BEEF is not exactly the carrier and its funding tree with the
   tree's minimal path;
3. the record's own rules (section 3.1), with their reasons, the inline
   ciphertext's length and hash among them;
4. `crypt`: the record's `crypt` is not this topic's;
5. `mineable`: `nLockTime < 4102444800`, or the input's `nSequence` is
   `0xFFFFFFFF`;
6. `unlock`: the input's unlocking script is not exactly one minimal push of a
   strict low-S DER signature followed by the sighash byte `0x41` (bcommon
   `carrier.CheckUnlocking`);
7. `lock`: the output script is not the well-formed one-field signed PushDrop
   locked to `derive(owner, "secret")`;
8. `signature`: the field signature is not strict low-S DER, or does not
   verify over `SHA-256(record)` under that key;
9. `funding`: the output the input spends, read from the funding tree in the
   BEEF, is not a well-formed funding output locked to
   `derive(owner, "secret")`, or the carrier's output does not carry exactly
   its value.

A host admits a secret record whatever vault, group or epoch it names and
whether or not the topic holds that vault: those are not facts of the
submission. Only the owner's key could have made the carrier (rules 6 to 9,
with the engine's execution of the input's script), so only an owner fills a
host with its own records, at one funding output each.

**Vault token.** A transaction whose one claiming output claims a vault
token. Its **parent** is the other transaction in its BEEF:

1. `shape`: the claiming output is not a PushDrop of exactly two fields and a
   signature, or does not hold 1 satoshi;
2. `beef`: the BEEF is not exactly the token and its parent, each with its
   minimal path;
3. the record's own rules, with their reasons;
4. `crypt`: not this topic's;
5. `lock`: the output script is not the well-formed two-field signed PushDrop
   locked to `derive(org, "vault")`;
6. `signature`: the field signature is not strict low-S DER, or does not
   verify;
7. `unmined`: the token's or the parent's proof does not verify against the
   host's headers;
8. `token-input`: for `seq > 0`, the parent's txid is not `prev`, or no input
   of the token spends an output of the parent that is a well-formed vault
   token of the same crypt, owner and vault at `seq - 1`, or more than one
   input spends a token output of the parent (an output that classifies as a
   vault token, well formed or not); for `seq` 0, it is not exactly one of
   the token's inputs that spends an output of the parent, or that output is
   not a well-formed funding output locked to `derive(org, "chain")`;
9. `vault-id`: for `seq` 0, `vault` is not the identifier of the outpoint
   that input spends (section 3.3);
10. the transition rules against the predecessor (the parent's token
    output), section 4.2: `transition`, `epoch`, `debt`, `count`.

A **well-formed** vault token output, here and wherever a predecessor is
read, is one that classifies as a vault token, is a PushDrop of exactly two
fields and a signature, holds 1 satoshi, decodes as a vault record, equals
byte for byte the script rebuilt from its fields and the key derived from the
record's `org` (canonical), and whose field signature is strict low-S DER and
verifies under that key. The predecessor's record is not held to its own
transition rules: those were its own admission's.

A token's inputs that do not spend the parent are not read: they pay its fee.
A token at `seq > 0` MAY also spend outputs of its parent that are not token
outputs (the parent's change, for one): they pay its fee like any other
input and are not read either. Only a second spend of a token output of the
parent is refused (rule 8). **A first token spends exactly one input of its
parent:** exactly one of its inputs spends an output of the chain tree, so
that one outpoint gives the vault its identifier, and two are refused (rule
8); its other inputs come from elsewhere, pay its fee, and are not read. The
tree's own change is an output of the parent like any other, so a first
token never pays its fee from it: an owner whose only coin is that change
moves it through a transaction of its own first.

**A predecessor of another crypt, owner or vault reads `token-input`, never
`transition`.** Rule 8 decides whose token is spent before rule 10 compares
anything: a parent whose token names another crypt, another owner or another
vault, or is not at `seq - 1`, is not this token's predecessor, whatever
else the two records share.

A token is admitted whether or not the topic already holds its predecessor;
the index then reports it `pending` until it does (section 11.2), so a token
that arrives before its predecessor is not lost.

**What this admits and does not bind.** Because the predecessor is read from
the BEEF and not held to its own rules, a host admits a token whose parent is
a mined transaction that was never itself admissible: an owner can put a
well-formed token output, with any `seq`, `count` and `stale`, in a
transaction that spends no predecessor, and build on it. Closing that at
admission would need the topic's held state. It is closed after admission
instead: such a token's ancestry never reaches the vault's first token, so it
is never rooted, never the vault's latest, and lists nothing (sections 11.2
and 14).

**Sweep.** A transaction whose outputs claim nothing, whose output 0 is
funding-shaped (under any key: a sweep's owner is whoever could sign its
inputs), and whose proof verifies against the host's headers: output 0 alone
is admitted, and its inputs' outpoints are matched against the funding
outpoints of carriers. A sweep is refused in the order `beef` (the BEEF is
not exactly the sweep and its own minimal path), `unmined`, `too-large` (more
inputs than the host's bound, which is at least 1024). A sweep offered before
it is mined reads `beef`, not `unmined`: a BEEF that carries a transaction
with no proof must carry what it spends, the tree, so it is not the sweep
and its own path. `unmined` is left for a sweep whose own path does not
verify against the host's headers. Either way the refusal raises, and the
sweep is decided again when it is offered mined. A mined funding tree
published on its own has this shape and is admitted as a sweep, which is
harmless: its inputs spend no carrier's funding outpoint. A publisher still
never publishes a tree on its own. A host keeps a spend for its life only
when the outpoint is a carrier's funding outpoint; spends of other outpoints
it keeps in a bounded table (host policy, at least 65536 outpoints, oldest
dropped first), so that a sweep that arrives before the carriers it retracts
still retracts them. A sweep that matches no carrier costs the host that
table entry and the stored transaction; a host MAY drop the stored
transaction of a sweep once its spends leave the table, and rate limits, not
funding, bound a stranger's chain of sweeps. The table is the one place where order matters: a sweep that
arrived before the carrier it retracts, and was pushed out of the table
before that carrier arrived, does not retract it at that host. A reader
checks a record's funding outpoint itself (section 14), and an owner
publishes a sweep only after the carriers it retracts.

Anything else is refused (`not-bsecret`), raising like every refusal. In
particular a transaction that only spends outputs the topic holds is not
accepted: it would let anyone store unmined bytes at every host for nothing.

**Retention and spends.** For every transaction it accepts, the topic manager
lists every input that spends an output the topic holds as a coin to retain,
so no admitted output is deleted when something spends it: a token stays
answerable after the next one spends it. The lookup service records, for each
carrier, the funding outpoint its input spends, and for each admitted sweep,
the outpoints its inputs spend; it does not rely on the engine's spend
notices, which cover only held outputs.

**What a host does not do.** It does not evict unproven carriers: carriers
are unproven by design. It does not broadcast anything: an engine that
carries `tm_bsecret_` topics runs with no broadcaster. It never decrypts and
never holds a key: nothing it is given opens anything. It counts refusals by
reason. A host SHOULD keep a token or sweep it refused `unmined` for a short
while and decide it again once its headers move, since a mined object on the
plane is delivered once.

**What bounds a host's storage.** Not funding: any key may publish carriers,
for vaults that exist or not, at one funding output each, and the value
returns to it by sweep. A carrier's stored BEEF holds its whole funding tree.
A host bounds this by policy, applied before the topic manager runs and
answered as an error, so that nothing is recorded and the same object is
decided afresh when it is offered again: it MAY rate-limit submissions, MAY
refuse a BEEF above a bound of its own that is at least the floor, MAY serve
only the organizations it chooses, and owes no retention to a carrier of a vault
whose chain it does not hold (section 11.3).

### 11.2 The index

The lookup service keeps, per crypt and owner: each vault's tokens by `seq`
(up to 8 per `seq`: rooted tokens before others, then the lowest txids, so
that which are kept does not depend on arrival); the secret carriers by vault, identifier and version
(more than one may be held for one version) and by content id; and one
**outpoint row** per funding outpoint any admitted carrier spends, holding
the outpoint's **winner** (the lowest `C` of every carrier ever admitted on
it, compared as 32 bytes in hash byte order), up to 8 other commitments, a
count of the rest, whether the winner was dropped, and the admitted sweeps
that spend the outpoint.

A token is **rooted** when the host holds every token from it back to the
vault's first by spends: its input spends the token output of the token it
holds at `seq - 1`, and so on to `seq` 0. The first token is rooted by its
own admission (`token-input` and `vault-id`); where the index reads a first
token without its parent (on restore, section 11.4), it checks it by the
outpoint hash alone, as a reader does (section 14). Only rooted tokens are a
vault's chain: only they are answered as latest, only their fold makes a set,
and only they list a carrier.

After a reorganization two rooted tokens can share a `seq`, each spending the
same predecessor (section 11.5). Each is the tip of its own **branch**. The
index folds each branch on its own: the set, the last version of each
identifier and the commitments seen are those of the tokens on that branch
and no other, and a carrier's `listed` or `mismatched` status is taken
against the branch of the token an answer uses (section 10.2).

The index folds each branch from `seq` 0 along the spends it holds and
records per token, the first that applies:

| Status | When |
| --- | --- |
| `pending` | it is not rooted: a predecessor is not held (a token admitted out of order, met first on restore, or built on a transaction that was never admissible). Not a fold result: a reader that holds the whole chain never sees it |
| `set-mismatch` | it creates an identifier the set holds, updates or retires one it does not, lists a version that is not above the last one that identifier had, or does not reproduce `count` and `root`. Sticky: every later token of the chain has it too |
| `stale-mismatch` | its `stale` is not the number of secrets in the set whose version was listed under an earlier epoch. Sticky |
| `commitment-reuse` | an entry's commitment is one an earlier token of the vault listed |
| `consistent` | otherwise |

A carrier's status is a function of the admitted set, the outpoint rows and
the fold, not of arrival order, with the one exception of a sweep that left
the bounded table (section 11.1). The first that applies:

| Status | When |
| --- | --- |
| `retracted` | an admitted sweep the host holds spends the carrier's funding outpoint (section 11.1 gives the one exception, the bounded table) |
| `superseded` | it is not its outpoint's winner, or its outpoint's winner has been dropped |
| `mismatched` | a rooted token of the vault lists its `id` and `version` with another content id or commitment, or lists its content id under another epoch than the record's, or the record's label is not one of the vault's |
| `listed` | a rooted token of the vault lists its `id`, `version`, content id and commitment, under the record's epoch |
| `unlisted` | otherwise |

Statuses act through what a host answers (section 10.2), its metrics and its
logs; no answer carries a status, and a reader computes every one itself
(section 14). Up to 8 superseded carriers per outpoint are kept as evidence
that the owner equivocated; the rest are counted and MUST be dropped, their
commitments with them. The engine's record that a dropped carrier's
transaction was applied remains, one row a carrier, and a carrier costs its
owner a signature: submission rate limits bound that, nothing else does. The winner is the lowest `C` ever admitted on the
outpoint, which a running minimum gives whatever was dropped.

**A dropped winner is sticky.** Once a host drops an outpoint's winner
(section 11.3), its row says so for the host's life, and every carrier on
that outpoint is `superseded` from then on: the ones it holds, and any
admitted later, one with a lower `C` included. A host never answers a
carrier on an outpoint whose winner it dropped. Without this, a second
carrier made on the outpoint after the first was dropped would be answered
as if it were the only one the owner made.

A vault whose chain holds a `set-mismatch` or `stale-mismatch` token is
**broken** from that token on, for good: the status is sticky, hosts go on
answering the set of the last token before it, and no later token repairs
it. The owner made it (every host admitted the token on its arithmetic; its
fold is false), and the only way on is a new vault. The owner's tooling MUST
fold its own transition before it signs it.

### 11.3 Retention

How long a host keeps what it no longer answers is its policy, with floors:

- tokens for the host's life: they are the trail, a few hundred bytes each;
- outpoint rows, and the sweeps they record, for the host's life: without the
  row, a carrier made later on a swept outpoint would be a fresh txid and
  would be answered;
- a `listed` carrier while the vault's set holds its version, and at least 31
  days after the host first saw the token that replaced or retired it;
- an `unlisted` carrier of a vault whose rooted chain the host holds, at
  least 31 days after the host first saw it;
- an unlisted carrier of a vault the host holds no rooted chain of, at least
  24 hours after the host first saw it: long enough for a new vault's first
  token, published after its first carriers, and for a replay in any order.

A retracted carrier is not answered, whatever the floor: an owner that sweeps
a version takes it out of every honest host's answers at once. A longer
retention of old versions is what a host sells (the `history` class), never a
floor; and it is also what a removed reader can still fetch (section 15).

To **drop** a carrier is to delete its outputs from the topic and mark its
outpoint row; the engine's record that the transaction was applied remains,
so a dropped carrier offered again is a duplicate.

### 11.4 Restore

The engine does not replay admissions. On start the service rebuilds its
index from the topic's stored outputs and the outpoints it persisted, and
folds every chain from `seq` 0, whatever order storage returns them in; a
token met before its predecessor is `pending` until the fold reaches it. A
proven token is stored as the token alone, so the service reads a
predecessor from the token it holds at `seq - 1`, not from a BEEF.

### 11.5 Reorganizations

A host learns of a block only through its headers, and an application on the
reference host is given no signal when a block leaves the best chain. So a
host may hold two tokens at one `seq` (the one mined first, orphaned, and the
one mined in its place), may keep a token whose stored proof names an
orphaned block although the same transaction was mined again elsewhere, and
goes on counting as spent an outpoint whose sweep was orphaned: retraction
follows the sweeps a host holds, not its view of the best chain. It answers
every candidate, up to 8, and keeps the outpoint rows as they are. A
submission of a txid a host holds, with a new proof, is a duplicate: the
reference engine takes no proof by submission for a transaction it holds
proven. Readers decide with their own headers (section 14): a token or a
sweep whose proof does not verify against the reader's best chain is not
mined for that reader, who fetches the transaction's current proof from a
chain source by its txid. A content id hashes a record, not a txid, so a
token mined again after a reorganization lists the same versions.

### 11.6 Joining a crypt

A host that starts carrying a crypt, or that missed part of a chain, is given
the chain by replay, from the publisher or from anyone who reads a sibling
host. A host stores a mined token as the token alone with its proof, so a
sibling's answer is not a submission a host admits as it stands. A replayer
assembles each token's BEEF itself: the token from the `vault-seq` answer at
`seq`, and its parent from the answer at `seq - 1`; at `seq` 0 the parent is
the chain tree, which no host keeps, so it comes from the publisher or from a
chain source by its txid, with its proof. A chain source may drop a
transaction once all its outputs are spent, and a chain tree is fully spent
once each of its outputs paid for a vault's first token, so the publisher's
own record of the tree is what lasts. Which of the two a replayer asks first
is its own choice; either way the tree is held to the same checks: its txid
is the one the token's input names, its proof verifies against the
replayer's headers, and the assembled BEEF passes section 11.1. A replayer checks each proof
against its own headers before it submits, and fetches a current proof from a
chain source for a token whose stored proof names an orphaned block.
Tokens, carriers and sweeps are self-verifying and may be replayed in any
order.

A host MUST NOT enable an unordered synchronization of unspent outputs for
`tm_bsecret_` topics: one carries only unspent outputs, so it never carries a
chain's spent tokens, and it drops what a topic manager refuses without
retrying it.

## 12. Carriers, tokens, funding trees and derivations

Everything here is bcommon's, parameterized by the values in section 12.1.

### 12.1 Derivations and tags

| What | Value |
| --- | --- |
| BRC-43 protocol of every public derivation | `[1, "bsecret"]` (security level 1) |
| Vault token lock and field signature | key id `vault`, invoice `1-bsecret-vault` |
| Secret carrier record output and field signature; the outputs of the trees that fund secrets | key id `secret`, invoice `1-bsecret-secret` |
| The outputs of the trees that pay for a vault's first token | key id `chain`, invoice `1-bsecret-chain` |
| Embedded wallet funding key | key id `fund`, counterparty `self` |
| Self wrap | `[2, "bsecret self"]`, key id the base64 of the content id, counterparty `self` (section 6.4) |
| Vault token tag | `73 65 01` (`"se"` `0x01`) |
| Funding-output tag | `73 65 02` (`"se"` `0x02`) |

Every derivation a host or a reader checks (`vault`, `secret`, `chain`) is
BRC-42 derivation with BRC-43's `anyone` counterparty: the owner's wallet
derives with `forSelf = true`, and a reader derives the same public key from
the identity key alone (`derivation-v1.json` checks both sides). The funding
key and the self wrap are the exceptions: both use counterparty `self`, and
no host rule reads either.

### 12.2 Carriers

A secret record rides a carrier built by bcommon `carrier.Mint`:

- **exactly one input**, spending one output of the owner's mined funding
  tree, `nSequence = 0`, unlocked by exactly one minimal push of the owner's
  signature (strict DER, low S, sighash byte `0x41`, `SIGHASH_ALL|FORKID`);
- **exactly one output**, a lock-before PushDrop of one field, the record,
  with the field signature over `SHA-256(record)`, locked to
  `derive(owner, "secret")`, carrying the whole value of the output it spends
  (fee zero);
- **`nLockTime = 4102444800`** (2100-01-01T00:00:00Z) with a non-final input,
  so it cannot be mined.

The owner is the record's `org`. The carrier's input script is executed
against the funding output it spends (SPV of an unproven transaction does
this; a host whose engine does not MUST do it itself), so only the owner's
key could have made it. The unlocking-script rule keeps `C` the owner's:
script verification does not require a canonical unlocking script, so without
it anyone could re-encode the input's script and present the same record
under a new txid. The owner itself can make many carriers from one funding
output, since carriers never conflict on chain; a host answers one of them
per outpoint (section 11.2), and the owner MUST NOT make more than one.

### 12.3 Vault tokens

A vault token is a mined transaction with exactly one output that claims a
token, a lock-before PushDrop of two fields and the field signature, holding
1 satoshi (its other outputs, such as change, claim nothing):

```text
<derive(org, "vault")> OP_CHECKSIG <73 65 01> <V> <signature> OP_2DROP OP_DROP
```

The signature is the wallet's strict low-S DER signature over
`SHA-256(field 1 || field 2)` under the locking key. A token at `seq > 0`
MUST spend the token at `seq - 1` of the same vault; a token at `seq` 0 MUST
spend exactly one output of the owner's chain tree, locked to
`derive(org, "chain")`, whose outpoint gives the vault its identifier
(section 3.3). Only the owner's key can do either. Copying a token's signed
output script into another transaction makes nothing a host admits, because
that transaction cannot spend the predecessor. Two tokens spending one
predecessor are a double spend of which at most one is ever mined. A token's
other inputs pay its fee from any source and are not read. The owner MUST NOT
spend a token's output except in its successor: a token output spent by
anything else ends the chain, and a reader that finds the latest token spent
by a transaction that is not the vault's next token (a well-formed token of
the same vault at the next `seq`) reports the vault **terminated** (section
14).

A token is published with the transaction its predecessor input (or, at `seq`
0, its funding input) spends, each with its own Merkle path, in one BEEF, so
that a host reads the predecessor's record from the bytes it was given and
never from what it holds. The token's own unlocking scripts are not held to a
canonical form: a re-encoded copy of a token transaction mined in its place
has the same outputs and the same record, so it is the same transition, but
its txid differs, so a successor built on the original txid never mines and
is rebuilt (section 7.1).

### 12.4 Funding trees

A funding tree is a mined transaction of equal outputs, each a PushDrop of
the one field `73 65 02` with no signature, locked to `derive(owner, k)`:
`<key> OP_CHECKSIG <73 65 02> OP_DROP`, where `k` is `secret` for a tree that
funds secret carriers and `chain` for one that pays for vaults' first tokens.
A carrier spends only a **mined** tree's output, and its BEEF carries that
tree with its proof, so a carrier's ancestry is one mined parent. A publisher
never publishes a tree on its own. The two kinds are kept apart by their
keys, so hosts enforce the separation, and each sits in its own wallet
basket. A chain tree is small (8 outputs by default), because a vault's first
token carries it whole. bcommon `producer` runs a tree's lifecycle.

### 12.5 Retraction

A **sweep** is a mined transaction spending funding outputs, used and unused
(bcommon `carrier.SweepAt` at the fee policy, whose output 0 is a
funding-shaped tombstone). Once it is mined, every carrier that spent one of
those outputs is a double spend and can never be valid again: hosts retract
it. A sweep is published once, after it mines, to the plane and directly to
every host the publisher names. Hosts learn of spends only from sweeps; only
a mined spend retracts.
**A sweep is published in every crypt that holds a version it retracts.** A
funding tree is the owner's, not a crypt's, and one tree may fund versions
of vaults in several crypts; a host learns of a spend only from a sweep
admitted in the topic of the crypt it carries, and admission reads no other
topic. A sweep published in one crypt alone leaves the versions it spends in
another answered there.
Retraction reaches honest hosts only: it is not erasure, and a copy anyone
kept stays a copy.

A sweep of every tree (a kill switch) retracts every secret record the owner
ever published from every honest host. The vault tokens remain: they are
mined, and they name identifiers, versions, content ids and commitments,
never a value or a name.

## 13. Delivery: plane and unicast

A publisher (the owner's tooling) reaches the crypt's hosts in one of two
ways. The records, the hosts and the readers are the same in both.

| | plane | unicast |
| --- | --- | --- |
| The publisher submits each object | once, to its facade on the plane; mined objects also directly to every host it names | to every host it names, each on its own |
| Every other host receives it | from the plane, which repairs loss | only from the publisher, or from anyone who copies it across later |
| A host that was down | receives what it missed from the plane's repair, within the plane's window; anything older by replay (section 11.6) | misses it until someone submits it again |
| Needs | a plane that carries the crypt's topic | nothing but the hosts |

**Plane.** The publisher submits each object once, with the crypt's topic
first in its topic list; the plane delivers it to every subscribed host and
repairs loss. Nothing in bsecret disables, bypasses or asks for an exception
from repair, for any class, crypt or configuration; lateness is the reader's
to handle. Tokens and sweeps are also submitted directly to every host the
publisher names, because a host off the plane learns of the chain only by
receiving it, and a host whose headers lagged refused it (`unmined`) and does
not receive it from the plane again. An object the plane accepted can still
miss a host, and nothing the publisher sees says so. So a publisher that
names hosts MUST confirm every object at each of them by lookup (a carrier by
the `version` class, a token by `vault-seq`, a sweep by `sweep`) and offer it
directly to a host that still lacks it after a few seconds. That is a copy
across, not a way round the plane's repair, and a direct copy that meets the
plane's is a duplicate.

**Quorum on the plane.** The facade's acceptance is not publication. A
carrier counts as published once a quorum of the hosts the publisher names
answer it by lookup; a token or a sweep counts only once every host named
answers it. Short of that the publisher stops, keeps the object, and offers
it again before it builds anything new.

Objects on the plane are kept small. A secret's carrier with its ciphertext
inline is a few packets for a credential and about 18 at the inline bound; a
token of a few changes is 3 or 4 ([limits.md](limits.md), measured). A large
secret's bytes never ride the plane: its record does, and its ciphertext is
fetched by hash.

**Unicast.** The publisher submits the same bytes to each host it names (at
most 16), retries each on its own, and counts the object published once a
quorum of hosts took it. A host **took** an object when its answer admits it,
or when a lookup at that host answers it: to a submitter a duplicate and a
raised refusal look the same, so an answer that admits nothing is confirmed
by lookup before it counts. Tokens and sweeps must reach every host named.

**In order.** Carriers are published before the token that lists them, and a
host admits either without the other: a carrier before its token is
`unlisted`, a token before its predecessor `pending`. Lateness or reordering
on the plane loses nothing.

**Filling a host that missed something.** Tokens, carriers and sweeps are
self-verifying, so anyone who holds one may submit it to a host that lacks
it: a member that finds a secret at one host and not another copies it
across; anyone who finds a host behind on a chain replays the missing tokens
to it, assembling each token's BEEF as section 11.6 says.

**Reading.** A reader asks one or more hosts the same question and verifies
every answer against its own headers (section 14). A reader that asks several
and receives different sets reports the difference as such, never merges it
silently. A host that answers something that does not verify (a token whose
proof or signature fails, a carrier that breaks the carrier rules, an output
that is not the object asked for) makes the read **incomplete**, not
refused: what does not verify is not used, the host is named, the vault is
read from what did verify, and the reader says that the answer it has proves
nothing either way (exit 3 in the tooling here). Refused is for a check that
failed on what was read and names the owner or a store (section 7.2). One
host at fault does not make a vault fail.

## 14. Verification by a reader

A reader checks everything against its own block headers and fails closed.

**The vault's chain.** A reader takes a token as the vault's only when it
descends by spends from the vault's first token. The first time it meets a
vault it reads the chain from `seq` 0 (`audit`, or the free `vault-seq` token
by token) and checks, for each token: its proof against the reader's best
chain; its output, lock and field signature (section 11.1's well-formed
token); that an input spends the token output of the token before it, whose
txid its `prev` names; the transition rules of section 4.2; and, at `seq` 0,
that an input's outpoint hashes to the vault identifier. **A reader checks a
first token by the outpoint hash alone.** It does not read the transaction
that outpoint is in, which no host keeps: an outpoint is spent by one mined
transaction, so the hash is enough to make the token the vault's one first
token (section 3.3). That the output spent was a chain-tree output of the
owner is a host's rule at admission (section 11.1 rule 8), which a reader
does not repeat. It folds as it goes.
Afterwards it starts from the token it remembers. A host's answer to `vault`
is a claim about which token is latest, never evidence of descent.

**The vault's state.** Ask `vault` (one or more hosts). Among the answered
tokens, keep those whose proof verifies against the reader's best chain and
that descend from the chain the reader holds. The highest is the vault's
latest. Whether a token is the latest is
settled by positive evidence: its 1-satoshi output is unspent according to a
source that indexes spends (a node, a UTXO index, or a service the reader
trusts), checked within the last 60 seconds for anything that acts on the
value. A reader without such a source trusts the highest `seq` any asked host
answers, asks more than one, and says that its answer may be stale. The
evidence is taken at the read, and a value kept after it keeps its age
(section 7.3).

**No going back.** A reader keeps, per vault, the highest `seq` it has
verified and that token's txid. It MUST refuse an answer whose latest token
is below it (`rollback`), and when it is given a higher one it checks that
the new token descends from the one it held (`vault-seq` back to it, or the
`audit` class). When the token it remembers no longer verifies against its
own headers, the reader fetches that transaction's current proof from a chain
source by its txid; if the transaction is no longer mined, a reorganization
displaced it, and the reader forgets it and reads the chain again. A reader
that starts with no memory (a container started
fresh) has only the unspent evidence and the comparison of hosts; a
deployment that cannot keep state SHOULD use a spend source.

A reader keeps the same memory of the vault's group: the `seq` and txid of
the latest group token it verified. Hosts of the hall that answer the
group's chain only below it are answering an older state of the group, one
in which a member since removed is still a member and the epoch that removal
began does not exist; every token of it verifies. The reader MUST refuse it
(`rollback`). It forgets what it remembered of the group only as it does for
the vault: when a chain source says the remembered token is no longer mined.
A source that fails proves nothing, and nothing is forgotten on its account.
A writer holds the group to the same memory before it builds anything.

**A broken chain.** A reader that folds a vault's chain and finds a
`set-mismatch` or `stale-mismatch` token refuses the vault entirely: it takes
nothing from it, the set of the last token before the break included, and
names the owner, who signed a token whose counts its own change lists do not
give. A host goes on answering the earlier set (section 11.2), because an
index has to answer something; a reader fails closed. It refuses a version whose commitment an earlier
token of the vault listed (`commitment-reuse`): its key is one an earlier
version's readers hold. A reader that checks one secret by its inclusion path
alone does not see these, nor a second leaf for one identifier; it folds the
chain when it first meets a vault (above), SHOULD fold the tokens since
whenever the vault's `seq` has moved, and an owner's tooling always does.

**A secret.** Ask `secret`; verify each answered carrier (the carrier rules)
and its inclusion path against the latest token's `root`. Without a path that
verifies, fold the chain (`audit`, or `vault-seq` token by token) or read the
set (`secrets`, all pages) and reproduce the root: a set read from a host
that does not reproduce the root means the host withheld or added a record,
so ask another host; a fold of the tokens that does not reproduce it means
the owner (above). Then the checks of section
7.2. A host that answers an older version of a secret fails here: the leaf
hashes the version and the content id, and the root holds only the current
one.

In an interval vault a reader also asks `pending`, and takes the highest
version it can link to the listed one, successor by successor (section 4.4).
A host that withholds the newest unlisted version hands the reader an older
one that still links; nothing the reader holds shows it. A reader of an
interval vault that needs the newest asks more than one host. It follows at
most 64 unlisted versions, ends a run below a retracted one, and says when a
later version exists that it did not take (section 4.4).

**History.** A reader that reads a version the set no longer holds (the
`version` class, or the `history` class) holds it to the first token of the
chain that lists that identifier at that version. That token is
authoritative: it must list the record as it is, with its content id and
commitment, under the record's epoch, and a later token that names the same
version proves nothing about a record the first did not list. Commitment
reuse is refused there too: a version whose commitment an earlier token of
the vault listed is not read (`listing`). A version read as history is never
reported current.

**The group's state, and exposure.** The reader reads the group's chain from
borg, as borg says, and settles that its latest token is the latest in the
same way. The vault's `org` MUST be the group's organization. The vault's
`epoch` and `epochId`, and each record's, MUST be those of an epoch the
group's canonical chain began; a vault or a record that names another is
refused (`listing`; the vault is **ahead**, section 7.3). This holds for a
stale record too: a record keyed under an earlier epoch names that epoch's
own id. A version keyed under an earlier epoch than the group's latest is
exposed (section 7.3); a vault whose latest token names an earlier epoch is
behind.

**A terminated vault.** A vault whose latest token's output is spent by a
transaction that is not a vault token is terminated: the reader shows it so
and takes nothing new from it.

**A retraction.** A spend is found by the `sweep` class at one or more hosts
or by a chain source, and counts only when its proof verifies. A reader MUST
NOT use a record whose funding outpoint a mined sweep spends (`retracted`),
as a version or as a link to another (section 4.4).

**A host's answer is not authority.** A host can withhold a token or a
record; it cannot forge or alter one, and it cannot make a version read as
current that the latest token does not list. The root makes withholding from
the set detectable from one host; the unspent evidence and the reader's own
memory make a withheld newer token detectable.

## 15. What a removed member can and cannot read

When a member is removed from the vault's group at the group token that
begins epoch `e + 1`:

**They can still read, and nothing takes it back:**

- **every version they ever opened.** They may have kept the plaintext, and
  a credential they read stays valid until its owner changes it where it is
  accepted;
- **every version keyed under an epoch whose key they hold**: epoch `e` and
  every earlier epoch they were a member of, **whether or not they had
  fetched it before they were removed**. They hold those epoch keys for
  good. Any such version that any host still answers, or that anyone kept a
  copy of, opens for them: old versions of secrets, versions replaced long
  before they left, and the versions that were current when they left. A
  sweep takes a version out of honest hosts' answers; it does not reach a
  copy;
- **every current value, for as long as the vault has not re-keyed it.**
  Between the block that mines the removal and the token that lists a
  secret's re-keyed version, the secret's current version is still the one
  they can open. That window is at least the time to publish the new epoch's
  wraps, publish the new versions and mine one vault token, and it lasts, for
  each secret, until its own re-keying is listed; a large vault takes several
  blocks. The trail records it (section 9.2). For a credential the window
  that matters ends later still: when the old value is disabled where it was
  accepted;
- anything the owner keys under epoch `e` after the removal. An honest owner
  that follows section 7.1 does not; an instance with a stale view could,
  until its evidence is fresh;
- anything a current member shows them. Every member of an epoch holds the
  same key, so a leak names nobody (BRC-369 section 9);
- every public fact: the vault's tokens (identifiers, versions, content ids,
  commitments, counts, and when each changed), the vault's and the group's
  names, the label of every record a host answers, each ciphertext's padded
  length, and the membership changes of the group. An identifier is the hash
  of a name, so they can test any name they remember or guess against it,
  for every later version too.

**They cannot read:**

- any version keyed under epoch `e + 1` or later. Its content key is fresh
  (section 6.1) and is wrapped under a key derived from the new epoch's key
  (section 6.3), which was sampled independently and wrapped only to the
  members who remain. Their old epoch keys derive other wrapping keys, and
  the wrap does not open (`secret-v1.json`: the removed member opens every
  version keyed under epoch 0 and none keyed under epoch 1 or 2);
- the self wrap of any version, which only the owner's wallet opens;
- unless the organization adds them to the group again. borg requires that
  transition to begin a new epoch, so that they read from that epoch on; no
  borg host can check it, and an organization whose tooling did not rotate
  has handed them the current epoch's key and everything keyed under it
  (section 8.1);
- unless the owner wraps a later version under a key they hold while naming
  the new epoch, which only the remaining members can see (section 6.3);
- unless a current member or the owner gives them a key or a value outside
  the protocol, which no protocol prevents.

**They cannot write.** Every carrier and every token needs the organization's
key; a removed member's old epoch keys make nothing a reader accepts.

So a removal protects **what is written after the vault re-keys**, and a
credential only once it has been **changed**. It does not make anything they
could read unknown to them.

## 16. Alignment with existing patterns

| Choice | Pattern followed | Where it differs, and why |
| --- | --- | --- |
| A secret is encrypted once under a random content key; the key is committed to before anyone holds it | BRC-369 sections 2.1 and 2.2 (digest form) | adopted verbatim; the point form and split keys (BRC-369 section 6.4) are not used |
| The ciphertext is public, addressed by its hash, inline when small | BRC-369 section 3.1 | a record that does not carry its ciphertext carries no locator either, where BRC-369 section 3.1 rule 2 asks for at least one of the two: the locator is the `uhrp://` form of `hash`. Sections 3.2 and 3.3 are for publications and are not required (below) |
| Content key never derived from an identity key, an epoch key or another version's | BRC-369 section 2.1 rules 1 and 2 ("MUST NOT be derived from the publisher's identity key, from the content, or from any other reusable secret") | none. BRC-42 derivation appears only in the self wrap and in borg's release of the epoch key, where BRC-369 section 2.1 rule 5 puts it |
| Segmented AES-256-GCM, 4-byte salt, `salt \|\| index` IVs, a tag per segment | BRC-369 section 2.3 | the construction is BRC-369's, and `brc369-v1.json` reproduces its ciphertext through this codec. bsecret adds bounds BRC-369 leaves open: a segment of 16 to 1048576 bytes, a plaintext of 1 to 67108864 bytes (so a ciphertext of at most 2^27), and no length whose last segment is a tag alone |
| The descriptor: author, epoch, content hash, length, salt, segment, commitment, `previous`, inline ciphertext | BRC-369 section 4.1 | canonical CBOR with integer keys, not JSON canonicalized by RFC 8785; signed by the carrier's field signature under the owner's derived key, not by the identity key (a BRC-100 wallet cannot sign with its identity key); the author is an identity key, not a handle; the record's magic takes the place of `metanetKeyedContent`, and the cipher is fixed by the record version where BRC-369 names it in `content.cipher`; no `release` block; `previous` links versions of one secret, where BRC-369's links epochs of one room |
| Content id | BRC-369 section 4.2 rule 3 (SHA-256 of the canonical form without the signature) | SHA-256 of the canonical record without the wraps and the inline ciphertext, so that the wraps can be bound to it |
| The three checks, in order, each naming its culprit; a failed third check is a proof | BRC-369 sections 5.3 and 5.4 | a listing check before them and a payload check after; the unwrap sits between checks 1 and 2 |
| Readers are the members of a group's epoch; a removal begins a new epoch; the epoch's key is released linearly | BRC-369 section 8 (the gate profile); borg, which enforces rotation on removal at every host | the gate is a borg group; BRC-369's gate profile encrypts content under the epoch's key itself, where a secret has its own content key, so that one version's key opens one version (BRC-369 section 2.1 rule 2). borg recommends that an application wrap such a key under the epoch's symmetric key; bsecret wraps under a hash of that key and the content id instead, so that no two uses of one epoch key share a cipher key. borg asks a reader to authenticate an object's author as a member of its epoch; the author here is the organization, never a member, and a reader checks that it is the group's organization |
| Encrypt once, wrap the key per reader set | BRC-52's keyring (a field revelation key encrypted to a verifier), which BRC-369 says section 5.2 borrows; the same shape as file-encryption tools that wrap one data key to several recipients | the wrap is to an epoch, not to an identity: one wrap serves every member, and the per-member cost is borg's |
| The wrap's cipher form | BRC-2's symmetric form as both SDKs write it (AES-256-GCM, 32-byte IV, `IV \|\| ciphertext \|\| tag`) | the key is a hash of the epoch's symmetric key and the content id, not a BRC-42 child key: there is no counterparty to derive against |
| The self wrap | BRC-2 through BRC-100 `encrypt` and `decrypt`, as the SDKs implement it (the symmetric key is the x-coordinate of the child keys' shared point; `derivation-v1.json` pins it); BRC-42 and BRC-43 with counterparty `self` | a protocol of its own, `[2, "bsecret self"]`, so that a wallet permits it apart from messaging (the reason BRC-369 section 5.2 rule 2 gives for its own protocol), and a key id derived from the content id, so that a wrap is bound to what it carries; no BRC-78 framing, since sender and recipient are one key and the key id is recomputed |
| Release to a named identity | BRC-369 section 5.2 (`[2, "keyed content release"]`, BRC-78) | not used by bsecret itself: borg releases epoch keys under it. A release of one secret's key to one identity, through a message box, is left for a later version |
| Grants | BRC-52 certificates, issued and revoked by borg; BRC-169 section 9 scopes | bsecret defines no certificate and no scope: a reader is a member of the vault's group |
| Large ciphertext by content address | BRC-26 (UHRP); BRC-369 section 3.1 rule 2 | the locator is derived from the hash and not carried; inline is the default up to 16384 bytes |
| Retention and re-advertisement by recipients | BRC-369 section 3.3 | not required: a secret's owner hosts its ciphertext, and a consumer that keeps what it no longer needs widens what a compromise finds |
| Withdrawal | BRC-369 section 4.4 | a retirement in the chain and a sweep of the carriers |
| Ordered state on a chain of mined tokens; a fork is a double spend | BRC-48 Pay to Push Drop tokens spent forward; BRC-22 topic managers retaining previous coins | the library's layout puts the lock before the pushes, where BRC-48 puts it after; the predecessor is read from the token's BEEF, never from what a host holds; the vault identifier is the hash of the first token's funding outpoint, so one identifier has one chain |
| Records never mined, kept off chain | BRC-60's non-final transaction | turned the other way round: a far-future lock time keeps the record off the chain for good |
| Canonical CBOR records with integer keys; unknown keys preserved | RFC 8949 section 4.2.1; BRC-174 section 3.2 | one codec with every application on the same library |
| Record magic: prefix, type letter, version | BRC-171 section 6 | in the order the library's registry fixes |
| The set root and inclusion paths | RFC 6962 Merkle Tree Hash | none |
| Topic and lookup names | BRC-87; BRC-22; BRC-24 with `output-list` answers | a random suffix per crypt |
| Host discovery | BRC-88 SHIP | a chain is joined by replay, not by an unordered synchronization |
| Priced questions | BRC-105 over BRC-103 and BRC-104; BRC-29; BRC-180 rule 2 | only the bulk history and audit classes are priceable; the payment's output index and script are fixed here; a handshake budget is required |
| Carrier ancestry and proofs | BRC-62, BRC-96 and BRC-95 BEEF; BRC-74 BUMP | exactly what the object needs, so nobody can attach anything to it |
| Objects on the plane | BRC-148 and BRC-149 | none |

### 16.1 Shared code

Code that more than one application uses belongs in the library, not in an
application. bsecret takes from bcommon:

- **the content key** (`keyed`): BRC-369's content key, its symmetric key
  and commitment, the check on a key just unwrapped, and BRC-2's symmetric
  form, in which both wraps are written. borg uses the same functions for
  its epoch keys. They are checked here against BRC-369's own vectors
  (`brc369-v1.json`). The epoch wrap of section 6.3 is `keyed`'s epoch
  wrap under the domain string `bsecret epoch wrap v1`, and a segment's IV
  is `keyed`'s, the same bytes by this contract's vectors;
- **the record reader** (`record`): the bounded, ordered decoding of a
  canonical CBOR record with integer keys, its refusals, and the first look
  a classifier takes (`pushdrop.FirstPush`, `record.Claims`).

What only bsecret uses stays here: the segments of section 6.2, the ordered
checks of section 7.2 and the locator of section 5.4
(`internal/secrec/keyed.go`).

bsecret's tooling also reads borg's chains (a group's epochs, the wraps, the
roll for rotation debt). Those rules are borg's contract, not this one, and
the code that reads them is borg's own: its public Go packages `borgrec`
(a group token and its record, the fold of a group's chain into its epochs,
and the wrap that releases an epoch's key to a member) and `reader`, at the
tag `go.mod` pins. Nothing of them is copied or restated here. This
contract's vectors are bound to borg's group by borg's golden vectors, kept
unchanged under `internal/borgread/testdata`. bsecret pins bcommon v0.20.0
and borg v0.4.4.

## 17. Size and rate bounds

| Quantity | Bound | Why |
| --- | --- | --- |
| Vault record, encoded | 20480 bytes | 64 created, 64 updated and 64 retired take about 17.5 KB |
| Secret record, encoded | 17408 bytes | the inline bound and every other key |
| Inline ciphertext | 16384 bytes | a credential is far smaller; a larger secret is found by hash |
| Ciphertext by reference | 2^27 bytes; a payload of at most 67108864 | a record never describes a ciphertext a conforming reader cannot open; a reader bounds what it fetches below this |
| Memory of one read | the ciphertext and the plaintext at once: up to about 192 MiB at the bound, about 3 times a reader's fetch budget in the codec here | a reader's fetch budget (16 MiB by default) is the bound that matters |
| Segment | 16 to 1048576 plaintext bytes | BRC-369 section 2.3 leaves the size to the descriptor |
| Changes per transition (`create`, `update`, `retire`), each | 64 | bounds one token and the index work it causes; a larger change is several transitions |
| Secrets in a vault | 4096 | every one is re-keyed after every removal; a vault that large takes 64 blocks to settle |
| Labels of a vault | 16, of 32 bytes each | |
| Names | a secret's 128 bytes; a vault's display name 64, one line of plain text | |
| Unlisted versions a reader follows above a listed one | 64 | bounds a read in an interval vault by the records hosts hold in a row, never by a version a carrier claims |
| Entries in a record map | 64 | bounds the work of one record |
| Answers | 8 tokens, carriers or sweeps per question; 64 tokens or 16 secret carriers per page | bounds an answer; not a floor, a later version may raise it |
| Tokens kept per `seq` | 8 | reorganizations |
| Superseded carriers kept per funding outpoint | 8 | evidence of equivocation; the rest are counted |
| Spends of outpoints no carrier used, kept by a host | at least 65536, oldest dropped first | a sweep may arrive before the carriers it retracts |
| Inclusion context | 2048 bytes, 32 steps, `size` 1 to 4096, `seq` at most 2^53 - 1 | a set of 4096 secrets needs 12 |
| Encoded payload | 67108864 bytes | bounds what a reader holds in memory; a larger secret is several |
| Commitments kept per funding outpoint | the winner and 8 others; the rest counted | bounds the row; the engine still keeps one applied-transaction row per carrier |
| Floor for an unlisted carrier of a vault the host holds no chain of | 24 hours | a new vault's carriers precede its first token |
| BEEF | exactly what the object needs (section 11.1); a host's bound is at least 262144 bytes | |
| Object on the plane | the plane operator's object bound (BRC-149) | a publisher checks every object against it before publishing |

A reader accepts every record within these bounds. A later version may raise
a bound, never lower one, so a record published under a bound stays readable.
Below them, what a publisher sends and how a host limits its readers are
policy: [limits.md](limits.md) sets the recommended defaults and caps,
measured. A host MAY rate-limit lookups, answering 429 with `Retry-After`,
and a client MUST respect it.

## 18. What this does not do

1. **Old versions stay readable by whoever could read them.** Section 15.
   Removal is forward only. A removed member opens every version keyed under
   an epoch they held, fetched before or after they left, for as long as any
   host or copy holds its ciphertext.
2. **A removal takes time.** Between the block that mines it and the token
   that lists each re-keyed secret, the current values are open to the
   removed member. The trail records the window; it does not shorten it.
3. **Nothing forces the acknowledgement.** Hosts enforce re-keying from the
   token in which the owner acknowledges the new epoch, not before. An owner
   that never acknowledges keeps creating and updating under the old epoch,
   and every host admits it; so does an owner that opens a second vault on
   the same group, or that publishes unlisted successors under the old epoch
   in an interval vault. What stands against it is the owner's own tooling,
   every reader (which reports the vault behind and its values exposed) and
   the audit (which counts the tokens and the blocks).
4. **A wrap's key is checkable only by those who hold it.** A version that
   names the new epoch while its wrap is under an old one passes every host,
   index and audit check; only the remaining members see it, as a version
   they cannot open (section 6.3). The trail proves what the owner signed.
5. **Re-keying is enforced; changing a value is not.** Nobody but the owner
   knows whether a re-keyed version holds a new value, and nothing here
   changes a credential at the service that accepts it.
6. **Reads leave no footprint.** The trail proves versions, epochs and
   removals. It does not prove who read what, or that anyone did.
7. **Names, sizes and timing are public.** Every host of the crypt, and
   anyone who follows its topic, sees each vault's owner, display name,
   group, how many secrets it holds, each secret's identifier (the hash of a
   guessable name), its versions and when each changed, each record's label
   and padded length, and when the vault re-keyed, which says when the group
   removed someone.
8. **No forward secrecy.** A wrap is under a key derived from the epoch's
   key, and the epoch's key reaches a member under BRC-2 from long-term
   identity keys (borg). Whoever later learns a member's identity key opens
   every epoch that member was in and every version keyed under them that any
   host or copy still holds. Whoever learns the organization's key opens
   everything, through the self wraps.
9. **The organization's key is everything.** It writes every vault, samples
   every epoch key and opens every self wrap. A compromised organization key
   is a new organization.
10. **Leaks name nobody.** Every member of an epoch holds the same keys.
11. **Hosts can withhold.** They cannot forge, alter or decrypt. The root
   makes withholding from the set visible; a withheld newer token is visible
   only to a reader with a spend source, a memory of the vault, or a second
   host.
12. **An interval vault trades assurance for speed.** Its unanchored
    versions can be withheld or replaced without a trace in the trail
    (sections 4.4, 9.3, 14).
13. **An audit ends where its trail ends,** and a mined statement by the
    owner is a claim until its records are checked (section 9.3).
14. **Retraction is not erasure.** Honest hosts stop answering and may drop;
    a copy anyone kept stays a copy, and the tokens stay mined.
15. **A label decides nothing** (section 5.3).
16. **Freshness is as good as the index asked.** SPV cannot prove an output
    unspent. Whether a token is the latest, and whether a carrier's funding
    output is unswept, come from a node or an index, with its lag and honesty.
17. **A large secret is as available as its storage.** A ciphertext found by
    hash is served by whoever hosts it under BRC-26, and is unreadable when
    nobody does. The hash check names a host that serves wrong bytes; nothing
    names one that serves none.
18. **A token's transaction can be re-encoded by a miner.** The transition is
    the same; the owner rebuilds its next one on the copy's txid.
19. **A freshness check is visible.** A reader or a writer that asks a third
    party whether a token is unspent tells it which vaults it uses and when.

20. **One false count ends a vault.** A token whose counts its change lists
    do not give is admitted by every host and breaks the fold for good
    (section 11.2). The only way on is a new vault.
21. **A reader with no memory walks the chain.** Descent from the first token
    is checked token by token (section 14); a vault with a long history costs
    a fresh reader that many lookups, or the price of the `audit` class.

## 19. Vectors

`testdata/vectors` holds the golden vectors, generated by the codec in
`internal/secrec` with `GOWORK=off go run ./cmd/vectors`; `go test`
regenerates them and compares byte for byte, refuses a file nothing
generates, and reads the hex, refusal, query, keyed, secret, vault,
transaction and index files back without the generator. The TypeScript codec
under `host/` reads the derivation, hex, refusal, query, script, vault,
secret, keyed, transaction and index files and reaches the same bytes,
reasons and verdicts, and writes `testdata/ts/ts-v1.json`, which the Go tests read
in turn. The generator fails when a check it makes stops
holding: the owner's wallet opens every self wrap and no other wallet does, a
member opens a version exactly when it held the version's epoch, BRC-369's
own vectors still reproduce, a version opens only under the key of the epoch
it names, every transition case is admitted or refused
by exactly the rule it names, every refused transaction's own scripts still
verify, and the tooling's record of commitments (section 6.2) has seen none
twice.

| File | What it holds |
| --- | --- |
| `derivation-v1.json` | the registry values; the test identities; the keys each derives for `vault`, `secret` and `chain` under counterparty anyone, checked against the owner's own wallet; the SDK's refusal of a protocol name under five characters; a self wrap and who opens it; the vault and secret identifiers; crypts with one readable part and two suffixes, and one suffix drawn from fixed bytes; the group's three epochs |
| `brc369-v1.json` | BRC-369's own test vectors, each printed value beside the value recomputed, 25 in all, the keyed content through this codec and the rest through the SDK's primitives: the three identity keys, the symmetric key, both commitment forms, the salt and segment IVs, the ciphertext opened and sealed again, its hash and locator, the descriptor's content id and signature, the release invoice and the payload's header, the substituted-key ciphertext hash and content id with section 5.3's verdict on it, the split-key sum, the shared-secret proof and the payee division. It records what does not reproduce: the release payload's key and body, which the SDK neither derives nor opens, and the epoch case, printed as commitments only and run on keys of the same shape |
| `keyed-v1.json` | a member's read of one version, case by case: a changed and a cut ciphertext (`hash`), another key wrapped (`commitment`), a wrapped value that is not a scalar (`undecryptable`), an owner that encrypted under a key it did not commit to (`tag`), a payload under another name (`payload`), and four cases with two faults that pin the order of the checks; a three-segment ciphertext written out, and its segments swapped; lengths accepted and refused |
| `secret-v1.json`, `secret-*.hex` | every version of the scenario's secrets: name, identifier, version, epoch, content key, salt, payload, content id, both wraps' keys and IVs, and who opens it (the removed member opens every version keyed under epoch 0 and none after); a wrap moved to another version; an unknown key kept and covered by the content id; each record against the token that lists it, and listings a reader refuses; successors and runs of unlisted versions in an interval vault; epochs the group did and did not begin; and a mis-keyed version, whose wrap is under another epoch's key than the one it names |
| `vault-v1.json`, `vault-*.hex` | the vault's seven tokens: creation, an update, a large secret, the acknowledgement of a new epoch with debt, the debt cleared, a creation, and a second re-keying in one token; every transition admitted, refusals of each transition rule against its predecessor, fold cases (`set-mismatch`, `stale-mismatch`, `commitment-reuse`) with the set after every record, which a record that breaks the fold leaves unchanged, a reader's in-set check case by case, and a `secret` answer's inclusion context |
| `audit-v1.json` | the scenario's trail as an auditor derives it from the tokens and example block heights: every event, every token's status, the window of each epoch, the same trail cut short, a vault that never acknowledges, and the trails an audit refuses |
| `refusal-v1.json` | byte strings each record's rules refuse, each with its reason (section 3.1); records with an unknown key, preserved |
| `query-v1.json` | every class with its members, price and limit; questions, each with its class or refused |
| `script-v1.json` | the classifier of section 11.1 over real locking scripts from bcommon's PushDrop, and scripts that claim nothing |
| `transaction-v1.json` | real transactions against a test chain's headers: a mined chain tree and secret tree, a vault of four mined tokens (two of them in one block) with its carriers, a second vault and a sweep, each as the BEEF submitted and with its previous coins; every rule of section 11.1 refused case by case in its order, each case naming the row of [frozen.md](frozen.md) it pins, each with scripts that verify, and cases that break two rules and are refused for the earlier; a token admitted on a parent that was never admissible; each token as a host stores it, read without its parent, held to the token before it by its spend, and replayed byte for byte |
| `index-v1.json` | what the index computes from those (section 11.2): which held tokens are rooted, in any order and with tokens missing; the chain folded; outpoint rows, bounded and dropped; and a carrier of every status |
| `testdata/ts/ts-v1.json` | written by the TypeScript codec: a crypt drawn from fixed bytes, vault and secret records with unknown keys, secrets sealed and wrapped by the TypeScript side (the self wrap under the key its SDK derives for the owner), a chain of three tokens, an inclusion context, and carriers, tokens and a sweep signed through its SDK. The Go codec re-encodes, opens, folds and admits all of it, and rebuilds each token's BEEF byte for byte |

The transaction vectors pin the rows of [frozen.md](frozen.md) section 2
that no record vector can: the carrier's and the vault token's shape, script
canonicality, signatures, one claiming output and the sweep.

The transaction vectors use a vault of their own, because a vault's
identifier is the hash of a real outpoint and its tokens name real txids:
its secrets are `tx/api-token`, `tx/db-password`, `tx/tls-key` and
`tx/ssh-key`, keyed to the same group and epochs.

The vectors' crypt is `example_crypt_hmqzvtkwrx` and their hall
`example_hall_vkqzmtrwxp`; the suffixes are fixed examples so that the
vectors are reproducible. The test identities' private keys are 32 bytes of
one value (`0x51` the organization, `0x52` to `0x54` the members, `0x56` a
key that is never a member); they are public and never for real use, and they
are the identities of borg's own vectors, whose group and epochs this
scenario is keyed to. Every value a client draws at random (content keys,
salts, IVs) is a fixed stand-in, `SHA-256("bsecret/vector/<label>")`. The
record vectors use stand-ins of the same form for the txids of mined tokens
and example heights for their blocks. Signatures are deterministic (RFC
6979).
