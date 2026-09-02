# bounded-http

Size-bounded reads of untrusted HTTP response bodies.

## Purpose & Responsibilities

One implementation of "read this response body, but never buffer more than N
bytes", shared by every code path that talks to a **storage provider** — the
party GitCellar's threat model treats as hostile by construction.

It does one thing and deliberately holds no opinions about storage, retries,
auth or chunking. Its whole reason for existing is that the guard must be *one*
implementation rather than a copy in each crate.

## File Index

| File | Description |
|------|-------------|
| `src/lib.rs` | The crate — `read_body_bounded`, `read_text_bounded`, `BoundedReadError`, the two default ceilings |
| `tests/hostile_provider.rs` | The guards driven against a real loopback server playing a malicious provider |

## Public API & Usage

```rust
use bounded_http::{read_body_bounded, read_text_bounded,
                   DEFAULT_MAX_OBJECT_BYTES, DEFAULT_MAX_DIAGNOSTIC_BYTES};

// Object read — refuses over the ceiling, returns Err.
let data = read_body_bounded(response, DEFAULT_MAX_OBJECT_BYTES).await?;

// Diagnostic read on an error path — never fails, yields a short marker
// instead of an unbounded body.
let text = read_text_bounded(response, DEFAULT_MAX_DIAGNOSTIC_BYTES).await;
```

| Constant | Value | Use |
|---|---|---|
| `DEFAULT_MAX_OBJECT_BYTES` | 64 MiB | A real object (pack blob, manifest, listing) |
| `DEFAULT_MAX_DIAGNOSTIC_BYTES` | 64 KiB | An error body about to be logged or wrapped |

## Constraints & Business Rules

- **Two guards, and both are required.** A declared `Content-Length` over the
  ceiling is refused on the header alone (cheap; costs the attacker the whole
  transfer). Bytes are then counted as they stream, which is what catches a
  response that declares nothing (chunked transfer encoding) or declares a lie.
  Either guard alone is trivially evaded.
- **Never pre-allocate from the declared length.** That would hand the peer an
  allocation primitive up to the ceiling for free. The buffer grows as bytes
  actually arrive.
- **`read_text_bounded` never returns an error.** Its caller is already
  reporting a different failure and must not have that failure replaced by this
  one. An over-long or unreadable body yields an explicit marker — truncation is
  always visible in the returned text, because a silently cut error message
  sends the next reader chasing a phantom.
- **`reqwest` only.** `aws-sdk-s3` yields a `ByteStream`, not a
  `reqwest::Response`, so the Service's R2 backend applies the same two-guard
  rule at its own call site.

## Relationships & Dependencies

Consumers: `vault-core` (here) and GitCellar's other provider-facing storage clients. Depends on `reqwest` (with
`stream`, required for `Response::chunk`) and `thiserror`. Nothing else — that
is the point.

## Decision Log

**Why this is a crate and not a module.** A hardening review (Aug 2026) found
that the per-object download ceiling had been added to `vault-core`'s S3
backend — a backend with no production consumer at the time — while the
backends actually in production stayed unbounded. The guard existed and
protected nothing.

The provider-facing clients that need the guard do not depend on each other,
and should not: a self-contained object-storage client must not drag chunking,
AEAD, Argon2 and HKDF into an HTTP client. A leaf crate with two dependencies
is the only shape that yields one implementation without a wrong-way
dependency.

The alternative was a copy per crate. That is precisely the mechanism by which
the original ceiling came to live somewhere nothing called it.

**Why the diagnostic ceiling is separate and much tighter.** The error path
*inside* the hardened download function was itself unbounded
(`response.text()`), so a hostile provider defeated the object ceiling in the
same call by answering `500` with a huge body instead of `200`. 64 KiB is far
more than any real provider error payload, and the value is never shown to a
user — it exists to make a hostile error response cheap.

**Why the ceiling is a parameter, not a constant.** Callers own the policy:
`B2Config::max_object_bytes`, `S3Config::max_object_bytes` and
`R2Storage::max_object_bytes` each default to `DEFAULT_MAX_OBJECT_BYTES` and can
be raised per deployment. A hard-coded limit here would force a fork the first
time someone legitimately stored a larger object — and a fork is the failure
mode this crate exists to prevent.
