# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this library, please report it responsibly.

**Email:** security@gitcellar.com

**PGP Key Fingerprint:** `18CD 743B 8466 AC30 E0F2 906D 0F86 4367 649D 627D`

The PGP public key is committed in this repository as [`security-pgp-key.asc`](security-pgp-key.asc) and is also published at https://gitcellar.com/.well-known/security-pgp-key.asc (linked from the site's `security.txt`).

We will acknowledge your report within 2 business days and confirm within 5 business days whether it is a valid vulnerability, with an initial severity. We keep you informed of the fix timeline and publish an advisory, with credit, once the fix has shipped. The full policy — scope, safe-harbour terms and recognition — is at https://gitcellar.com/security/responsible-disclosure.

## Scope

This policy covers the cryptographic implementation in this repository:

- Key generation and management (`passkey-core`)
- Encryption and decryption (`gitcellar-crypto`, `vault-core`)
- Content-defined chunking and pack assembly (`vault-core`)
- Bounded reads of storage-provider responses (`bounded-http`)
- Identity and authentication primitives (`passkey-core`)

## What We Consider Vulnerabilities

- Weaknesses in key derivation or generation
- Encryption/decryption bypasses
- Information leakage through side channels
- Authentication bypasses in challenge-response
- Flaws in BIP39 recovery code implementation

## Recognition

We will credit researchers who report valid vulnerabilities (unless they prefer to remain anonymous).
