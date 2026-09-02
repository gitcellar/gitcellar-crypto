//! Size-bounded reads of untrusted HTTP response bodies.
//!
//! In the storage path the **provider is the adversary** — that is the premise
//! of zero-access hosting. A hostile provider answering an ordinary object GET
//! (or a `500`) with a multi-gigabyte body must not be able to make the client
//! allocate all of it before a single AEAD tag is checked. This crate is the
//! one implementation of "read this body, but never buffer more than N bytes",
//! shared by every code path that talks to a storage provider, so the guard
//! cannot silently exist on one backend and be missing on another.
//!
//! It is deliberately a leaf crate with two dependencies and no opinions about
//! storage, retries, auth or chunking: several crates need the guard and none
//! of them should depend on each other to get it.
//!
//! Scope: `reqwest` responses. Backends whose body type is not a
//! `reqwest::Response` apply the same two-guard rule at their own call site.

use thiserror::Error;

/// Default per-object ceiling: 64 MiB.
///
/// Matches `vault_core::storage::s3::DEFAULT_MAX_OBJECT_BYTES` deliberately —
/// one number for every backend, so "what is the ceiling here?" has a single
/// answer. Comfortably above any legitimate pack blob.
pub const DEFAULT_MAX_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

/// Ceiling for a *diagnostic* body read (an error message we are about to log
/// or wrap). 64 KiB is far more than any real provider error payload, and the
/// value is never returned to a user — it exists to make a hostile 500 cheap.
pub const DEFAULT_MAX_DIAGNOSTIC_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error)]
pub enum BoundedReadError {
    /// The provider *declared* a body larger than the ceiling. Cheap to detect
    /// and it costs the attacker the whole transfer.
    #[error("response declared {declared} bytes, over the {max}-byte ceiling")]
    DeclaredTooLarge { declared: u64, max: u64 },

    /// The body exceeded the ceiling while streaming — which is what catches a
    /// response that declares nothing (chunked transfer encoding) or declares a
    /// lie. Both guards are needed; either alone is defeatable.
    #[error("response body exceeded the {max}-byte ceiling (a declared length, if any, was a lie)")]
    StreamedTooLarge { max: u64 },

    #[error("failed to read response body: {0}")]
    Io(#[from] reqwest::Error),
}

/// Read `response`'s body, refusing to buffer more than `max` bytes.
///
/// Two guards, because either alone is defeatable:
///
/// 1. Refuse a declared `Content-Length` over the ceiling — cheap, and it costs
///    the attacker the whole transfer.
/// 2. Count bytes as they stream and abort past the ceiling — this is what
///    covers a response that declares nothing or declares a lie.
///
/// Memory is bounded by `max`, not by what the peer sends.
pub async fn read_body_bounded(
    response: reqwest::Response,
    max: u64,
) -> Result<Vec<u8>, BoundedReadError> {
    if let Some(declared) = response.content_length() {
        if declared > max {
            return Err(BoundedReadError::DeclaredTooLarge { declared, max });
        }
    }

    let mut response = response;
    // Pre-allocating from the declared length would hand the attacker an
    // allocation primitive up to `max`, so grow as the bytes actually arrive.
    let mut data: Vec<u8> = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if data.len() as u64 + chunk.len() as u64 > max {
            return Err(BoundedReadError::StreamedTooLarge { max });
        }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}

/// Read at most `max` bytes of a body as lossy UTF-8, for **diagnostics**.
///
/// This is the replacement for `resp.text().await.unwrap_or_default()` on error
/// paths. It never fails: an unreadable or over-long body yields a short marker
/// rather than an error, because the caller is already reporting a different
/// failure and must not have that failure replaced by this one.
///
/// Truncation is explicit in the returned text — a silently cut error message
/// sends the next reader chasing a phantom.
pub async fn read_text_bounded(response: reqwest::Response, max: u64) -> String {
    match read_body_bounded(response, max).await {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(BoundedReadError::DeclaredTooLarge { declared, max }) => {
            format!("<error body suppressed: declared {declared} bytes, over the {max}-byte diagnostic ceiling>")
        }
        Err(BoundedReadError::StreamedTooLarge { max }) => {
            format!("<error body truncated at the {max}-byte diagnostic ceiling>")
        }
        Err(e) => format!("<error body unreadable: {e}>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_ceiling_is_far_below_the_object_ceiling() {
        // A diagnostic read must never be able to buffer an object-sized body:
        // the error path was the hole that defeated the object ceiling in the
        // same call, so its own limit has to be much tighter.
        assert!(DEFAULT_MAX_DIAGNOSTIC_BYTES < DEFAULT_MAX_OBJECT_BYTES / 100);
    }

    #[test]
    fn errors_name_the_ceiling_they_enforced() {
        // The message has to say what the limit was, or a legitimate object that
        // grows past the ceiling is undiagnosable in the field.
        let declared = BoundedReadError::DeclaredTooLarge { declared: 999, max: 10 }.to_string();
        assert!(declared.contains("999") && declared.contains("10"), "{declared}");
        let streamed = BoundedReadError::StreamedTooLarge { max: 10 }.to_string();
        assert!(streamed.contains("10"), "{streamed}");
        // And it must say the declared length was untrustworthy, so the reader
        // does not conclude the provider is merely misconfigured.
        assert!(streamed.contains("lie"), "{streamed}");
    }
}
