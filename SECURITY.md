# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this library, please report it responsibly.

**Email:** security@gitcellar.com

**PGP Key Fingerprint:** `18CD 743B 8466 AC30 E0F2 906D 0F86 4367 649D 627D`

The PGP public key is available at: https://gitcellar.com/.well-known/security-pgp-key.asc

We will acknowledge your report within 48 hours and aim to provide a fix within 7 days for critical issues.

## Scope

This policy covers the cryptographic implementation in this repository:

- Key generation and management (`passkey-core`)
- Encryption and decryption (`gitcellar-crypto`, `vault-core`)
- Content-defined chunking (`vault-core`)
- Identity and authentication primitives (`passkey-core`)

## What We Consider Vulnerabilities

- Weaknesses in key derivation or generation
- Encryption/decryption bypasses
- Information leakage through side channels
- Authentication bypasses in challenge-response
- Flaws in BIP39 recovery code implementation

## Recognition

We will credit researchers who report valid vulnerabilities (unless they prefer to remain anonymous).
