# bsecret

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Secrets management on Bitcoin, replicated by overlay hosts that hold
ciphertext and never a key. A secret is encrypted once under a random key;
the key is wrapped to the members of a group's current epoch; and when the
group removes a member, the vault must re-key everything it holds before it
does anything else.

## How it works

- **A secret is a keyed object.** Each version is encrypted under its own
  random content key, committed to before anyone holds it (BRC-369). The
  ciphertext is public; the key is wrapped to the owner's wallet and under
  the key of one epoch of a borg group.
- **Readers are a group's members.** Adding a reader is adding a member.
  Removing one begins a new epoch whose key the removed member never
  receives.
- **Revoke forces rotation, checked by every host.** A vault is a chain of
  mined tokens. Once it acknowledges a new epoch, no host admits anything
  onto that chain but the re-keying or retirement of what it held, until
  nothing is left under an earlier epoch. Hosts cannot make an owner
  acknowledge: readers and auditors see a vault that has not.
- **The chain is the audit trail.** Anyone with block headers verifies which
  versions the owner listed, in what order, under which epoch, and how long
  each stayed listed under an epoch a removed member held. No cooperation
  from a host or the owner is needed. The trail proves what the owner
  signed; that a version's key is wrapped under the epoch it names is
  checked by the members who open it.
- **Hosts are replicas, not authorities.** A host can withhold; it cannot
  forge, alter or decrypt.
- **Honest about what removal does.** A removed member keeps everything it
  could read. Removal protects what is written after the vault re-keys.

## Documentation

| If you want to | Read |
| --- | --- |
| Implement a compatible owner, reader, auditor or host | [docs/spec.md](docs/spec.md) (the specification) |
| Know what cannot change once published | [docs/frozen.md](docs/frozen.md) |
| Know the defaults and caps, and why each is set where it is | [docs/limits.md](docs/limits.md) |

## Build and test

```console
$ make verify    # gofmt, vet, dependency set, vectors, tests
$ make vectors   # regenerate the golden vectors
```

Go 1.27.1 or later. The direct dependencies are go-sdk v1.5.2 and bcommon
v0.6.0, and nothing else.

## License

Apache License 2.0. See [LICENSE](LICENSE).
