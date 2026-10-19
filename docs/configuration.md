# Configuration

Every setting of the `bsecret` command, from the code (`internal/config`
and `cmd/bsecret`). The overlay host's environment (`BSECRET_CRYPTS`,
`BSECRET_HEADERS_URL`, prices, the payee key and the rest) is in
[host.md](host.md#configuration). The owner's group is borg's, configured
in the borg home ([borg's configuration](https://github.com/lightwebinc/borg/blob/main/docs/configuration.md)).

## Where settings come from

Highest first:

1. global flags, before the command (`bsecret -network test get db/password`);
2. `BSECRET_<KEY>` in the environment, the key in upper case
   (`BSECRET_HEADER_URL=woc:main`);
3. the config file;
4. the built-in defaults below.

The config file is `-config PATH`, else `$BSECRET_HOME/config`, else
`$XDG_CONFIG_HOME/bsecret/config`, else `~/.bsecret/config`. Its grammar is
one `key = value` per line, `#` comments, blank lines ignored. A key it
does not define, a key given twice, or a line without `=` is an error,
never ignored.

The overlay and content addresses (`hosts`, `hall_hosts`, `facade`,
`paid_host`, `content`) have no default on purpose: a default would send an
organization's records, or a member's questions, to a server nobody
configured. A command that needs one and finds none exits 2 naming the key.

The chain services do have defaults on `main` and `test`, so that a home
needs no node of its own ([no node needed](#no-node-needed)): `chain` and
`header_url` default to `woc:<network>` (WhatsOnChain) and `settle` to
`arcade:<network>` (GorillaPool's public arcade). Each is a setting, and a
node of your own is the better option for each. `regtest` has no public
services and no defaults.

## Keys

| Key | Default | Meaning |
| --- | --- | --- |
| `arcade_key` | none | bearer token for an arcade installation named in `settle` |
| `asset` | none | a Teranode node's asset HTTP API base URL (`/api/v1/...`). The older spelling of `chain = asset:<URL>`, and still read as that; set one of the two, not both. Also the node coinbase is mined through on a regtest chain |
| `chain` | `woc:<network>` on `main` and `test`; none on `regtest` | the chain view: where raw transactions, proofs and spends are read ([chain views](#chain-views)). Its spend answers are a writer's evidence, and a reader's that a token is the latest |
| `chain_tree_count` | `8` | outputs of a new chain tree, 1 to 32: a vault's first token carries its chain tree whole |
| `content` | none | where a ciphertext over the inline bound is kept, comma separated: a directory (a writer stores into the first one; a reader reads from each) or an `http(s)` base URL a reader fetches `<base>/<hash>` from. A file is named by the lowercase hex of its SHA-256 |
| `crypt` | none | the crypt identifier a command uses; an owner whose vaults are all in one crypt uses it |
| `delay` | `60s` | the propagation delay: a mined token or sweep is published this long after its block is in this home's headers, so the hosts' headers have it too (spec section 8.3); `0s` to `10m` |
| `facade` | none | mode `plane`: the overlay host a publisher submits to, from which the plane delivers to every subscribed host. Refused in mode `unicast` |
| `fee_dust` | `100` | the least change kept as an output, in satoshis; less goes to the fee |
| `fee_floor` | `100` | the least fee one transaction pays, in satoshis |
| `fee_max_rate` | `100/1000` | the most the fee rate may be, `SATS/BYTES`; a rate above it, a live policy's included, is lowered to it, so a broadcaster that raises its rate refuses the transaction until this is raised |
| `fee_max_tx` | none | the most fee one transaction may pay, in satoshis; a build above it is refused, not paid |
| `fee_min_rate` | `100/1000` | with `fee_source = arc`, the least a live policy's rate is taken as |
| `fee_policy_urls` | the `settle` arcade or ARC | with `fee_source = arc`, the broadcasters whose `GET /policy` is read, comma separated; the highest rate of those that answer is used |
| `fee_rate` | `100/1000` | the miner fee rate, `SATS/BYTES` (100 satoshis per 1000 bytes is the network's rate); a bare number is satoshis a byte |
| `fee_source` | `static` | `static` (the rates above) or `arc`: the policy the broadcaster publishes, fetched at most every 5 minutes, held to `fee_min_rate` and `fee_max_rate`, and the static rate when it cannot be read |
| `freshness` | `60s` | how old a writer's evidence that the vault's and the group's latest tokens are unspent may be when it publishes a version (spec section 7.1); at most `600s`. Every token retakes the evidence as it is built |
| `fund_unmined` | `accept` | `accept` or `refuse`: whether `fund -beef` takes a payment that has not mined yet, when every parent it spends is proven |
| `hall` | none | the borg hall a new vault's group lives in (`vault create`); a vault names its own afterwards |
| `hall_hosts` | `hosts` | the overlay hosts asked about the group's hall, comma separated, at most 16 |
| `header_token` | none | a bearer token sent to the header source (block-headers-service requires one unless its operator turned authentication off) |
| `header_url` | `woc:<network>` on `main` and `test`; none on `regtest` | the header source every proof is checked against ([header sources](#header-sources)): `woc:main`, `woc:test`, `bhs:URL`, `arcade:URL`, `chaintracks:URL`, or an overlay bridge's base URL |
| `home` | `~/.bsecret` | the identity's home |
| `hosts` | none | the crypt's overlay hosts, comma separated, at most 16: every host a reader asks and compares; in mode `unicast` every host a publisher submits to; in mode `plane` the hosts every mined object is also sent to directly |
| `max_fetch` | `16777216` | the most ciphertext a reader fetches by hash, in bytes; at most 134217728 |
| `mode` | `plane` | `plane` or `unicast`: how a publisher's objects reach the hosts (spec section 13) |
| `network` | `main` | `main`, `test` or `regtest`: the fund address prefix and the header source's proof-of-work floor |
| `object_bound` | `1048576` | the plane's object bound in bytes, at most 8388608; a carrier or token whose BEEF is larger is not published |
| `org` | none | the owner a reader reads: the organization's identity key |
| `originator` | `bsecret` | the BRC-100 originator presented to the wallet |
| `paid_host` | none | the base URL of `ls_bsecret` on the host the priced questions are asked of (`audit`, `history`, `terms`): the host's terms route (spec section 10.3). An origin, with no path |
| `quorum` | `all` | how many of `hosts` must hold a carrier for it to count as published: `all`, `majority`, `one`, or a number up to the host count. In mode `unicast` they are the hosts that took it; in mode `plane`, the hosts that answer it by lookup once the facade took it. A token or a sweep always needs every host |
| `rpc` | none | the node's JSON-RPC URL: `fund` without `-txid` or `-beef` (coinbase: only on a regtest chain you run, for development and tests) |
| `rpc_pass`, `rpc_user` | `bitcoin` | the node's basic auth, also for `settle = rpc:` |
| `settle` | `arcade:<network>` on `main` and `test`; none on `regtest` | the broadcaster for what is mined (funding trees, tokens, sweeps, a payment a payee takes): `arcade:main`, `arcade:test` (GorillaPool's public arcade), `arcade:<url>` (an arcade installation, your own included), `arc:<url>` (an ARC installation; with `arcade_key` where it needs a token), `rpc:<url>` (a node's JSON-RPC, with `rpc_user` and `rpc_pass`) or `tcp:<host:port>` (raw transactions to an ingress, no acknowledgement). An arcade's "accepted" is held to the chain view's spends |
| `timeout` | `15s` | bounds each request; `1s` to `5m` |
| `tree_count` | `32` | outputs of a new secret tree, 1 to 1000 |
| `vault` | none | the vault a command uses: its identifier, or its display name when that names one vault |
| `woc_key` | none | a WhatsOnChain API key, for a `woc:` chain view |
| `woc_rate` | `3` | the WhatsOnChain requests a second the chain view paces itself to: 3 is the free tier; raise it to a key's plan |

Every cap, with its reason, is in [limits.md](limits.md). A value out of
range exits 2 naming the key and the limit.

## What each role needs

On `main` and `test`, `chain`, `header_url` and `settle` take their
defaults when unset, so a role needs only what is left.

| Role | Keys |
| --- | --- |
| A member reading (`get`, `list`, `vault show`, `due`) | `hosts`, `header_url`, `crypt`, `org`, `vault`; `hall_hosts` when the hall's hosts are others; `chain` to know that what it read is the latest; `content` for a secret over the inline bound |
| An auditor (`audit -free`) | the reader's, with no home; `paid_host`, `chain`, `settle` and coin to pay for the priced class instead |
| The owner (every command that publishes) | the reader's, `hall` (for `vault create`), `chain`, `settle`, and `facade` in mode `plane` |
| Funding a home on mainnet or testnet (`fund -txid`, `fund -beef`) | `header_url`; `chain` for `-txid` |
| A host's payee (`payee settle`) | `header_url`, `chain`, `settle` |
| A local regtest chain only (`fund` without `-txid` or `-beef`) | `rpc`, `chain = asset:<URL>`; coinbase: only on a regtest chain you run (development and tests) |

## No node needed

On `main` and `test` a home runs with no infrastructure of its own:

| Role | Default | What it is |
| --- | --- | --- |
| Headers (`header_url`) | `woc:<network>` | WhatsOnChain's headers, each hashed and held to its proof of work |
| Chain view (`chain`) | `woc:<network>` | WhatsOnChain: transactions, proofs and spends |
| Broadcast (`settle`) | `arcade:<network>` | GorillaPool's public arcade |
| Miner fee | `fee_rate = 100/1000` | the network's rate, static |

What is checked and what is trusted:

- **Transactions and proofs** are checked: a transaction must hash to its
  txid, and every proof must verify against your header source.
- **Headers** come from a third party, but each one must carry the proof of
  work its bits claim (on mainnet at least the network's floor), so a lie
  costs a mined block.
- **"Unspent", "not known" and "not mined"** cannot be checked and are
  WhatsOnChain's word. bsecret acts on "unspent" only where WhatsOnChain
  tells an unspent output from an unknown one. A node of your own
  (`chain = asset:<URL>`, or `chain = woc:main,spend=asset:<URL>` for its
  spend answers alone) removes that trust.
- **Broadcast** is arcade's policy and verdict. An arcade can answer
  "accepted" for a transaction whose input another transaction already
  spent, so its verdict is held to the chain view's spends.

WhatsOnChain's free tier allows 3 requests a second, and the chain view
paces itself to that. A home that publishes a lot needs `woc_key` (with
`woc_rate` raised to the plan's rate) or a node.

## Chain views

`chain` is bcommon's chain view grammar: `woc:<network>` (the default, no
node), `asset:<URL>` (a Teranode node's asset API), comma lists such as
`asset:<URL>,woc:main`, and per-method entries such as
`woc:test,spend=asset:<URL>`. Spends come from one entry only, so an absence
answer never falls through. See
[chain views](https://github.com/lightwebinc/bcommon/blob/main/docs/configuration.md#chain-views-nodeapi-interfaces).

## Networks

| `network` | Fund address | Header source | Coinbase funding |
| --- | --- | --- | --- |
| `main` (default) | starts with `1` | `woc:main` (default), or your own block-headers-service, arcade, chaintracks or bridge | refused |
| `test` | starts with `m` or `n` | `woc:test` (default), or your own | not answered by a public testnet node; use `fund -txid` or `fund -beef` |
| `regtest` | starts with `m` or `n` | the regtest chain's own (the sandbox's `devchain`) | `fund` mines it (coinbase: only on a regtest chain you run, for development and tests) |

A `woc:` header source or chain view, and `arcade:main` or `arcade:test`,
must name the configured network, or the command exits 2.
bsecret's fund address is derived under its own protocol: coin paid to a
borg home made around the same identity is not bsecret's.

## Header sources

| `header_url` | Source |
| --- | --- |
| `woc:main`, `woc:test` | the public WhatsOnChain API (the default): each header is hashed here and must carry the work its bits claim |
| `bhs:https://host:8080` | a [block-headers-service](https://github.com/bsv-blockchain/block-headers-service) you run, checked the same way; `header_token` is its bearer token |
| `arcade:https://host` | the header server an [arcade](https://github.com/bsv-blockchain/arcade) installation embeds, checked the same way |
| `chaintracks:https://host/v2` | a chaintracks v2 service, public or your own, checked the same way |
| `https://host:port` | an overlay bridge's header read API (`GET /v1/tip`, `GET /v1/root/<height>`). It serves roots, not headers, so run it yourself |

```console
$ bsecret -network main doctor | grep headers
headers     woc:main tip 970084
```

## Global flags

| Flag | Key | Meaning |
| --- | --- | --- |
| `-config PATH` | none | the config file |
| `-home DIR` | `home` | the identity's home |
| `-crypt CRYPT` | `crypt` | the crypt identifier |
| `-org KEY` | `org` | the owner a reader reads |
| `-vault VAULT` | `vault` | the vault: its identifier, or its display name |
| `-hosts URLS` | `hosts` | the crypt's overlay hosts, comma separated |
| `-hall-hosts URLS` | `hall_hosts` | the hosts of the group's hall |
| `-chain SPEC` | `chain` | the chain view |
| `-header-url SOURCE` | `header_url` | the header source |
| `-settle SPEC` | `settle` | the broadcaster |
| `-fee-rate R` | `fee_rate` | the miner fee rate, `SATS/BYTES` |
| `-fee-source S` | `fee_source` | `static` or `arc` |
| `-fee-floor N` | `fee_floor` | the least fee one transaction pays |
| `-fee-max-rate R` | `fee_max_rate` | the most the rate may be |
| `-fee-max-tx N` | `fee_max_tx` | the most fee one transaction may pay |
| `-mode MODE` | `mode` | `plane` or `unicast` |
| `-network NET` | `network` | `main`, `test` or `regtest` |
| `-quorum Q` | `quorum` | `all`, `majority`, `one` or N |
| `-timeout DUR` | `timeout` | per request |
| `-v` | none | verbose; also accepted after the command |
| `-version` | none | print the version and exit |

## Command flags

`bsecret <command> -h` prints them; every one is listed here.

| Command | Flag | Default | Meaning |
| --- | --- | --- | --- |
| `init` | `-borg DIR` | none | make the home around a borg home's identity key |
| `init` | `-from FILE` | none | make the home around an `identity.json` carried by hand |
| `fund` | `-txid TXID` | none | import this mined payment you sent to the fund address, read from the chain view (mainnet, testnet) |
| `fund` | `-beef FILE` | none | import that payment as the BEEF your wallet handed over; `-` reads standard input (mainnet, testnet) |
| `fund` | `-refuse-unmined` | `fund_unmined` | with `-beef`, take only a mined payment |
| `fund` | `-blocks N` | `101` | coinbase: only on a regtest chain you run (development and tests); blocks to mine, or with `-rescan` to re-read |
| `fund` | `-batch N` | `30` | coinbase: only on a regtest chain you run (development and tests); blocks per `generatetoaddress` call |
| `fund` | `-rescan` | off | coinbase: only on a regtest chain you run (development and tests); re-read recent blocks for coinbase the pool lacks |
| `vault create` | `-name N` | drawn at random (`vault_` and ten letters) | the vault's display name, 1 to 64 bytes; public |
| `vault create` | `-hall HALL` | `hall` | the borg hall the group lives in |
| `vault create` | `-anchor` | `version` | `version` or `interval` |
| `vault create` | `-labels` | `confidential,internal,public,restricted` | the vault's label set |
| `put` | `-file FILE` | standard input | read the value from this file |
| `put` | `-label` | the vault's last label, or `confidential` | the secret's classification |
| `put` | `-type` | none | a media type, kept inside the ciphertext |
| `put` | `-not-after` | none | when the value stops being usable, RFC 3339 (a claim) |
| `put` | `-rotate-every DUR` | none | how often the owner intends to rotate (a claim, reported by `due`) |
| `put` | `-defer` | off | an interval vault: publish the version and list nothing yet |
| `retire` | `-keep` | off | do not sweep the retired secrets' versions |
| `rotate` | `-set NAME=FILE` | none | a new value for a stale secret; repeatable |
| `rotate` | `-same NAME` | none | re-key a stale secret with the value it holds; repeatable |
| `rotate` | `-retire NAME` | none | retire a stale secret; repeatable |
| `rotate` | `-same-all` | off | re-key every stale secret not named otherwise with its value |
| `rotate` | `-keep` | off | do not sweep the versions keyed under ended epochs |
| `rotate` | `-check` | off | build nothing: would these choices finish a revoke? |
| `rotate` | `-unwrapped` | off | go on although some member holds no wrap of the new epoch's key |
| `get` | `-show` | off | write the value to standard output although it is a terminal |
| `get` | `-version N` | the latest | read this version, as history |
| `get` | `-strict` | off | refuse an exposed value, a vault not settled, or a state that may be stale |
| `due` | `-within DUR` | `720h` | list values that stop being usable within this long |
| `audit` | `-free` | off | read the trail through the free class, paying nothing |
| `audit` | `-at URL` | `paid_host` | the host's terms route |
| `audit` | `-max-sats N` | `1000` | the most one page of the priced class is paid |
| `audit` | `-budget N` | `16000` | the most the audit pays in all |
| `audit` | `-json` | off | print the report as JSON |
| `history` | `-at URL` | `paid_host` | the host's terms route |
| `history` | `-after VERSION` | none | the page after this version |
| `history` | `-max-sats N` | `1000` | the most one question is paid |
| `payee key` | `-out FILE` | none | the file to write `BSECRET_PAYEE_KEY` to (`-` for standard output) |
| `payee settle` | `-in-flight N` | `16` | the most payments broadcast and not yet mined at once |
| `kill` | `-confirm KILL` | none | must be the literal `KILL` |
| `kill` | `-yes` | off | actually sweep |

## Environment variables

| Variable | Effect |
| --- | --- |
| `BSECRET_<KEY>` | one per key above, for example `BSECRET_HEADER_URL`, `BSECRET_SETTLE`. Overrides the file; a flag overrides it |
| `BSECRET_HOME` | the home **and** where the config file is looked for first |
| `XDG_CONFIG_HOME` | the second place the config file is looked for |
| `HOME` | the default home is `$HOME/.bsecret` |

## Example files

An owner on mainnet with no node, publishing to two hosts in unicast
(headers, chain view and broadcaster are the defaults):

```text
# ~/.bsecret/config
network      = main
crypt        = example_crypt_hmqzvtkwrx
hall         = example_hall_vkqzmtrwxp
mode         = unicast
hosts        = https://host-a.example.com,https://host-b.example.com
content      = /srv/bsecret/content
```

On a multicast plane, `mode = plane` and `facade = https://host-a.example.com`.
With a node and an arcade of your own, and the broadcaster's live fee
policy, add:

```text
chain        = asset:https://asset.example.com
header_url   = bhs:https://headers.example.com
header_token = <your block-headers-service token>
settle       = arcade:https://arcade.example.com
fee_source   = arc
```

A member on testnet:

```text
network      = test
crypt        = example_crypt_hmqzvtkwrx
org          = 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
vault        = ops
hosts        = https://host-a.example.com,https://host-b.example.com
content      = https://content.example.com
paid_host    = https://terms.host-a.example.com
```

## The container image

`ghcr.io/lightwebinc/bsecret` (built locally by `make docker-build`) is the
static binary on a distroless nonroot base, entrypoint `bsecret`. The home
is `/home/nonroot/.bsecret`: mount a named volume there, and pass settings
as `BSECRET_<KEY>` variables. The image carries an empty content directory
at `/var/lib/bsecret-content`. Licenses are in `/usr/share/doc/bsecret/`.

```console
$ docker run --rm -v bsecret-home:/home/nonroot/.bsecret \
    -e BSECRET_NETWORK=main \
    ghcr.io/lightwebinc/bsecret doctor
```

`ghcr.io/lightwebinc/bsecret-devchain` (the `devchain` build target) is the
sandbox's local regtest chain, and `bsecret-host` borg's host image with
the bsecret module added ([host.md](host.md)).
