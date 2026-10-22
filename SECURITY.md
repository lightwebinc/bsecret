# Security

Please report a vulnerability privately through GitHub: the repository's
**Security** tab, **Report a vulnerability**. Do not open a public issue for
it.

A report is most useful with the version (`bsecret -version`), what you ran,
what you expected, and what happened instead. We aim to acknowledge within
three working days. Supported: the latest release.

In scope:

- anything that lets anyone other than the owner or a member of the
  group's current epoch recover a secret's plaintext or content key;
- anything that lets a vault admit a write after a removal without first
  re-keying, or lets a host accept one, against
  [docs/spec.md](docs/spec.md);
- anything that lets a reader accept a secret version that the vault did
  not write or that no mined anchor commits;
- anything that leaks a key held by the owner or a member, or spends coin
  other than as its owner asked;
- the images and the host module bundle.

Not in scope, because the design states them as limits
([docs/limits.md](docs/limits.md)): a removed member keeps what it could
read before the re-key; metadata on the chain and at an open host is
pseudonymous, not hidden; reads leave no footprint.
