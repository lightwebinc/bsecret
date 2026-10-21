# Examples

Task-oriented commands for mainnet and testnet. Every command and flag
here is the code's own; keys, txids and suffixes are placeholders. Output
lines are abbreviated with `…`. The concepts are in
[user-guide.md](user-guide.md), every setting in
[configuration.md](configuration.md).

## 1. What you need

| For | You need |
| --- | --- |
| reading a secret as a member | a home around your identity key and the crypt's hosts (and the hall's) |
| auditing a vault | the hosts; no home and no coin with `audit -free` |
| owning vaults | a borg organization with a group and `borg org signer` run once, and about 20,000 sat in a wallet you control |
| hosts | borg's host image with the bsecret module added, or the module on a reference overlay host ([host.md](host.md)) |

No node is needed. On mainnet and testnet bsecret reads headers,
transactions, proofs and spends from WhatsOnChain and broadcasts through
GorillaPool's public arcade, each checked as
[configuration.md](configuration.md#no-node-needed) describes; a node of
your own (`chain = asset:<URL>`) is the better option where you have one.

There is no coinbase on mainnet or testnet for you to mine: a home is
funded by a payment you send from your own wallet. `bsecret fund` without
`-txid` or `-beef` is for a regtest chain you run (coinbase: only on a
regtest chain you run, for development and tests).

## 2. Check the network from your machine

Reads only, needs no coin and no hosts:

```console
$ bsecret -network main doctor
home        /home/you/.bsecret
network     main
crypt       not configured
chain       woc:main
…
headers     woc:main tip 970084
fee         100/1000 sat/bytes, floor 100 sat (static)
…
settle      arcade:main
```

On testnet:

```console
$ bsecret -network test doctor | grep -E 'chain|headers|settle'
chain       woc:test
headers     woc:test tip 1761989
settle      arcade:test
```

## 3. Configure the owner's home

```console
$ mkdir -p ~/.bsecret && cat > ~/.bsecret/config <<'CONF'
network    = main
mode       = unicast
hosts      = https://host-a.example.com,https://host-b.example.com
hall       = example_qzxkvbmwtr
CONF
```

For testnet: `network = test`. When the hall's hosts are other hosts than
the crypt's, add `hall_hosts`. With a node and a broadcaster of your own:
`chain = asset:<URL>` and `settle = arcade:<URL>` (or `arc:<URL>`,
`rpc:<URL>`).

## 4. Create the home and fund it

The owner's borg home already runs the organization, with a group and
`borg org signer` done:

```console
$ bsecret init -borg ~/.borg
created /home/you/.bsecret around the identity in /home/you/.borg/identity.json
identity     02c6…9a1e
fund address 1BnB…3xET (main)
```

The fund address is bsecret's own: coin sent to the borg home does not
count here. Send about 20,000 sat from your own wallet to it (on testnet
the address starts with `m` or `n`), then import the payment one of two
ways.

After one confirmation, by its txid:

```console
$ bsecret fund -txid 9ade…7f2e
imported 1 of 1 output(s) paying 1BnB…3xET, 20000 sat, mined at height 970090; pool 1 output(s), 20000 sat
```

`fund -txid` reads the transaction and its proof from the chain view
(WhatsOnChain by default) and checks the proof against the header source.

Or at once, from the BEEF your wallet handed over (a file, or `-` for
standard input), with no lookup at all:

```console
$ bsecret fund -beef payment.beef
imported 1 of 1 output(s) paying 1BnB…3xET, 20000 sat, from 9ade…7f2e, not mined yet: held back until it mines; pool 1 output(s), 20000 sat
```

A payment not mined yet is taken when every parent it spends is proven and
it verifies against them; it is also sent to the broadcaster, in case your
wallet did not, and spent only once it mines. `-refuse-unmined` (or
`fund_unmined = refuse`) takes only a mined one. A payment that pays the
fund address nothing is refused:

```console
$ bsecret fund -txid 3281…2d86
bsecret: the payment pays nothing to the fund address 1BnB…3xET
```

On mainnet, `fund` without `-txid` or `-beef` is refused:

```console
$ bsecret fund
bsecret: fund without -txid or -beef mines coinbase, which only a chain you run does; on network main, import a payment with fund -txid or fund -beef
```

## 5. Create a crypt and give it to your hosts

```console
$ bsecret crypt new example
crypt example_hmqzvtkwrx
topic tm_bsecret_example_hmqzvtkwrx
host  BSECRET_CRYPTS=example_hmqzvtkwrx
$ echo 'crypt = example_hmqzvtkwrx' >> ~/.bsecret/config
$ bsecret doctor
…
host        https://host-a.example.com answering
host        https://host-b.example.com answering
```

## 6. Create a vault and put secrets

```console
$ bsecret vault create engineering -name ops
vault   7b1e…04aa
name    ops
crypt   example_hmqzvtkwrx
group   5a0c4d…9d12 in hall example_qzxkvbmwtr
epoch   0
anchor  version
labels  confidential,internal,public,restricted
token   seq 0 9c41…e2d0 mined at height 912410
$ bsecret put db/password < db-password.txt
secret  db/password version 1 label confidential epoch 0: carrier 41f0…b7a3 (created)
token   seq 1 0e6d…58c1 mined at height 912412: 1 secret(s), 0 stale, epoch 0
$ bsecret put api/token -file token.txt -label restricted -not-after 2027-01-01T00:00:00Z
```

A value is read from standard input or `-file`, never from an argument.
Each `put` takes about a block and a minute and costs about 107 sat.

## 7. As a member: read a secret

A member makes a home around its own borg home (`bsecret init -borg
~/.borg`, no coin) and configures:

```text
network    = main
crypt      = example_hmqzvtkwrx
org        = 02c6…9a1e
vault      = ops
hosts      = https://host-a.example.com,https://host-b.example.com
```

```console
$ bsecret get db/password | psql …
vault   7b1e…04aa ops seq 3: settled at epoch 0
latest  seq 3 is the latest: its output is unspent per the node
secret  db/password version 1 label confidential epoch 0, read as a member: anchored, current
$ bsecret get -strict db/password > /run/secrets/db   # refuse an exposed or possibly stale value
$ bsecret get -version 1 db/password                  # an earlier version
$ bsecret list                                        # names only, no values
```

The value goes to standard output (only when it is not a terminal, or with
`-show`); the checks go to standard error.

## 8. Revoke a member

```console
$ printf 'correct horse' | bsecret rotate -check -set db/password=- -same-all
ready   3 secret(s) owe a re-keying or a retirement (were the group to begin a new epoch now), and each has a choice: a revoke can be finished in 1 token(s)
$ borg org remove $BOB -group engineering
$ printf 'correct horse' | bsecret rotate -set db/password=- -same-all
epoch   1 acknowledged: the group began it at height 912417 (a removal)
rekeyed api/token: the same value under epoch 1
rekeyed db/password: a new value under epoch 1
token   seq 4 5d77…90be mined at height 912418: 3 secret(s), 0 stale, epoch 1
swept   3 version(s) keyed under epochs that have ended, or never listed: retracted at every honest host
vault   7b1e…04aa settled at epoch 1
```

A re-keyed credential that keeps its value is still known to the removed
member: give it a new value (`-set`) where that matters.

## 9. Retire a secret, check what is due

```console
$ bsecret retire api/token
$ bsecret due                    # an acknowledgement, re-keyings, scheduled rotations (exit 3 when due)
$ bsecret due -within 168h       # values that stop being usable within a week
```

## 10. Audit a vault

Anyone, with no home and no coin:

```console
$ bsecret -network main -header-url woc:main -hosts https://host-a.example.com,https://host-b.example.com \
    -crypt example_hmqzvtkwrx -org 02c6…9a1e -vault 7b1e…04aa audit -free
…
epoch   1 began at height 912417 (a member removed): acknowledged at height 912418, settled at height 912418
window  epoch 1: 1 block(s) from the block that began it to the token after which nothing was listed under an earlier epoch
audit   OK: 6 token(s) mined, the owner's, linked from the first, lawful, consistent and keyed to the group
```

`audit -json` prints the report as JSON. A host may sell the whole trail
in pages (`paid_host`, `-max-sats`, `-budget`); a funded home pays its 402.

## 11. Hosts that disagree: fill

```console
$ bsecret fill
filled  0 object(s) at 0 host(s)
```

Anyone can run it; it needs no coin and signs nothing.

## 12. A second machine for the owner

```console
$ bsecret init -from identity.json    # the organization's key, carried by hand
$ bsecret fund -txid <a payment you sent to this home's fund address>   # or fund -beef FILE
$ bsecret sync
```

## 13. A host's payee

```console
$ bsecret payee key -out payee.env    # BSECRET_PAYEE_KEY for the host's environment
$ bsecret payee settle /var/lib/bsecret/payments.jsonl
```

## 14. The kill switch

```console
$ bsecret kill -confirm KILL          # lists the sweeps; sends nothing
$ bsecret kill -confirm KILL -yes     # retracts every version the home published
```

## 15. In a container

```console
$ docker run --rm -v bsecret-home:/home/nonroot/.bsecret \
    -e BSECRET_NETWORK=main \
    ghcr.io/lightwebinc/bsecret doctor
```

## 16. A reader that stays running, and Kubernetes

`bsecret serve` holds a member's home, walks the vault on an interval and
serves the values it verified over HTTP ([usage.md](usage.md#serving)).
On one machine, beside the process that reads:

```console
$ bsecret serve                         # 127.0.0.1:8250, walked every minute
$ curl -s 127.0.0.1:8250/secrets/db/password | jq -r .value
$ curl -s 127.0.0.1:8250/v1/secret/data/db/password | jq -r .data.data.value
```

A Vault Agent template reads the second shape unchanged
(`{{ with secret "secret/data/db/password" }}{{ .Data.data.value }}{{ end }}`,
with the agent's address set to the daemon's).

In Kubernetes, run it as a Deployment with one replica (one process holds
one home), its home on a volume, the member's `identity.json` and a token
from Secrets, and read it with the
[External Secrets Operator](https://external-secrets.io/)'s webhook
provider. `bsecret init -from identity.json`, run once in an init
container, makes the home around the member's key from the Secret.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bsecret
spec:
  replicas: 1
  strategy: { type: Recreate }
  selector: { matchLabels: { app: bsecret } }
  template:
    metadata: { labels: { app: bsecret } }
    spec:
      containers:
        - name: serve
          image: ghcr.io/lightwebinc/bsecret:<version>
          args: ["serve", "-listen", "0.0.0.0:8250", "-token-file", "/run/bsecret/token"]
          envFrom: [{ configMapRef: { name: bsecret } }]   # BSECRET_NETWORK, _CRYPT, _ORG, _VAULT, _HOSTS
          ports: [{ containerPort: 8250 }]
          readinessProbe: { httpGet: { path: /healthz, port: 8250 }, periodSeconds: 30 }
          volumeMounts:
            - { name: home, mountPath: /home/nonroot/.bsecret }
            - { name: token, mountPath: /run/bsecret, readOnly: true }
      volumes:
        - { name: home, persistentVolumeClaim: { claimName: bsecret-home } }
        - { name: token, secret: { secretName: bsecret-serve, items: [{ key: token, path: token }] } }
---
apiVersion: v1
kind: Service
metadata:
  name: bsecret
spec:
  selector: { app: bsecret }
  ports: [{ port: 8250, targetPort: 8250 }]
---
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: bsecret
spec:
  provider:
    webhook:
      url: "http://bsecret:8250/secrets/{{ .remoteRef.key }}"
      headers:
        Authorization: "Bearer {{ print .auth.token }}"
      result:
        jsonPath: "$.value"
      secrets:
        - name: auth
          secretRef: { name: bsecret-serve, key: token }
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: db
spec:
  refreshInterval: 5m
  secretStoreRef: { name: bsecret, kind: SecretStore }
  target: { name: db }
  data:
    - secretKey: password
      remoteRef: { key: db/password }
```

The daemon answers 409 for a value its policy refuses (by default an
exposed value, a vault behind or in debt, or one not known to be latest:
what `get -strict` refuses), so the operator keeps the last value it
synced and reports the sync as failed. For a value that is not UTF-8,
use `$.value_base64` with the ExternalSecret's `decodingStrategy: Base64`.
Keep the Service reachable only from the operator's namespace, with a
network policy.

## 17. Exit codes in scripts

| Code | Meaning |
| --- | --- |
| 0 | done, or verified |
| 1 | refused: the evidence contradicts what was asked (for example, this key holds no key of the epoch a record names) |
| 2 | usage, configuration or transport error; persisted work is finished by the next command |
| 3 | incomplete: hosts disagree or did not answer, or something is due; proves nothing either way |
