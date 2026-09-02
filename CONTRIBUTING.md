# Contributing

Thank you for looking at GitCellar's cryptographic core. This repository exists so that the
encryption GitCellar ships can be read, built, and tested by anyone.

## What this repository is

These five crates are published from GitCellar's main (private) source tree. Every commit here
is a projection of the code that runs in the product, with the same file contents.

## Security issues

**Do not open a public issue for a vulnerability.** See [SECURITY.md](SECURITY.md) for the private
reporting channel, the PGP key, and the response commitments.

## Bug reports and questions

Open an issue. A minimal reproduction or a failing `cargo test` is the most useful thing you can
include. Questions about the design are welcome too; the
[security whitepaper](https://gitcellar.com/security/whitepaper) is the reference for algorithm
choices, key hierarchy, and threat model.

## Pull requests

We read every pull request, and we will credit you in the commit that lands your change. Because
the canonical source lives in the private tree, a fix is applied there and re-published here
rather than merged directly, so a PR may be closed with a commit that carries your change instead
of a merge. Please open an issue first for anything larger than a small fix so we can agree on
the approach.

By submitting a contribution you agree that it is licensed under the same terms as the
repository: MIT OR Apache-2.0, at your option.

## Building and testing

```bash
cargo build --workspace
cargo test --workspace
cargo audit          # cargo install cargo-audit
```

Linux and macOS need Nettle for the Sequoia OpenPGP backend (`apt install nettle-dev libclang-dev
pkg-config`, or `brew install nettle pkg-config`). Windows uses the built-in CNG backend. The
minimum supported Rust version is 1.85.
