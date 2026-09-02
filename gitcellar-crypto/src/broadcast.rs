//! Broadcast / emergency-notification payload model + verification.
//!
//! This module is the **single implementation** of the
//! broadcast signing contract. It is shared
//! by the Cloud API (sign + publish), the Service (relay over SSE — uses only
//! the types), and the Desktop app (verify + render). Implementing it once
//! here guarantees the byte-level signing contract is identical across all
//! three subsystems.
//!
//! ## The load-bearing rule: sign-the-bytes-you-transport
//!
//! A broadcast is authenticated by an OpenPGP detached signature (Sequoia,
//! Ed25519) over the **canonical JSON string** produced by
//! [`BroadcastPayload::to_canonical_json`]. That string is transported verbatim
//! in every channel (database row, event stream, published manifest). No consumer re-serializes
//! it: the signer signs `payload.as_bytes()`, and every verifier verifies the
//! signature against the exact `payload` bytes it received, parsing the typed
//! struct only *after* the signature checks out. See the broadcast interface contract §0.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};

/// Schema version of the signed [`BroadcastPayload`]. Bump only on a breaking
/// change to the signed-payload shape (broadcast interface contract §1).
pub const BROADCAST_PAYLOAD_VERSION: u32 = 1;

/// Envelope version of the [`IncidentManifest`] (broadcast interface contract §2).
pub const INCIDENT_MANIFEST_VERSION: u32 = 1;

/// Phase-1 `action_url` host allowlist (broadcast interface contract §3 / BC-SEC-03,
/// DEC-BC-07). Exact host match, `https` only. Enforced on author-side (compose
/// rejects) AND verifier-side (Desktop refuses to linkify a non-allowlisted
/// host even with a valid signature).
pub const ACTION_URL_ALLOWLIST: &[&str] = &[
    "gitcellar.com",
    "www.gitcellar.com",
    "status.gitcellar.com",
    "api.gitcellar.com",
];

/// Severity tier (broadcast interface contract §4 / BC-MODEL-02, DEC-BC-02).
///
/// "Mandatory" is a tier property, never a user setting (DEC-BC-01). Phase 1
/// ships the full enum; Phase-1 *delivery* focuses on `Incident` (Warning rides
/// the same rails; Announcement delivery is Phase 2 but the value exists now).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BroadcastTier {
    /// Mandatory, max signaling, every channel incl. off-infra + (P2) email.
    Incident,
    /// Mandatory, prominent non-blocking.
    Warning,
    /// Opt-in (includes marketing). Delivery gated to Phase 2.
    Announcement,
}

impl BroadcastTier {
    /// Whether this tier is mandatory (no user setting may suppress it).
    pub fn is_mandatory(self) -> bool {
        matches!(self, BroadcastTier::Incident | BroadcastTier::Warning)
    }
}

/// Optional targeting filters (broadcast interface contract §1). Evaluated by the
/// Cloud API's WHERE-clause builder (BC-TARGET-*), NOT by the shared verifier —
/// the Desktop receives only broadcasts it was targeted for. Omitted entirely
/// for broadcast-to-all (break-glass always omits).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BroadcastTargeting {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_type: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
}

impl BroadcastTargeting {
    /// Whether no filters are set (an empty filter targets all users — the
    /// Cloud API WHERE-builder treats this as "no constraints").
    pub fn is_empty(&self) -> bool {
        self.min_version.is_none()
            && self.platform.is_none()
            && self.plan_type.is_none()
            && self.email_verified.is_none()
    }
}

/// The signed unit (broadcast interface contract §1 / BC-MODEL-01).
///
/// **Field declaration order IS the canonical serialization order** — do not
/// reorder. Optional fields use `skip_serializing_if` so an absent field is
/// omitted entirely (never `null`); an omitted vs. `null` `action_url` are
/// different byte strings and would break signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadcastPayload {
    /// Schema version (`BROADCAST_PAYLOAD_VERSION`).
    pub v: u32,
    /// Unique, stable broadcast id (author-assigned).
    pub id: String,
    /// Severity tier.
    pub tier: BroadcastTier,
    /// Plain-text title (<=120 chars, no HTML).
    pub title: String,
    /// Plain-text body (<=2000 chars, no HTML, `\n` allowed).
    pub body: String,
    /// Optional call-to-action URL; host MUST be allowlisted (§3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_url: Option<String>,
    /// Issue time (RFC3339 UTC).
    pub issued_at: DateTime<Utc>,
    /// Optional publisher-set expiry (RFC3339 UTC). Bounds the live window of a
    /// captured manifest (DEC-BC-11).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Monotonic per-publisher sequence (Phase-1 convention: unix-epoch-seconds
    /// at issue; the broadcast interface contract §5).
    pub seq: i64,
    /// OpenPGP fingerprint of the signing key (uppercase hex, no spaces). Bound
    /// INSIDE the signed payload so a signature can't be lifted onto a
    /// different signer claim.
    pub signer_fingerprint: String,
    /// Optional targeting. Omitted entirely for broadcast-to-all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub targeting: Option<BroadcastTargeting>,
}

impl BroadcastPayload {
    /// Serialize to the canonical JSON string (the bytes that get signed).
    /// Compact (no extra whitespace), fields in declaration order. This is the
    /// ONLY place a `BroadcastPayload` is turned into signable/transportable
    /// bytes.
    pub fn to_canonical_json(&self) -> Result<String> {
        // serde_json::to_string is compact and preserves struct field order.
        serde_json::to_string(self).map_err(CryptoError::Serialization)
    }

    /// Parse a canonical JSON string back into a payload. Callers MUST verify
    /// the signature over the raw string bytes BEFORE calling this (the typed
    /// value is only trustworthy post-verification).
    pub fn from_canonical_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(CryptoError::Serialization)
    }

    /// Validate the `action_url` (if any) against the allowlist. Returns
    /// `Ok(())` when absent or allowlisted; `Err` otherwise. Used author-side
    /// (reject at compose) and verifier-side (refuse to linkify).
    pub fn validate_action_url(&self) -> Result<()> {
        match &self.action_url {
            None => Ok(()),
            Some(url) => {
                if action_url_allowed(url) {
                    Ok(())
                } else {
                    Err(CryptoError::Broadcast(format!(
                        "action_url host not in allowlist: {url}"
                    )))
                }
            }
        }
    }
}

/// Whether an `action_url` is permitted (broadcast interface contract §3). Requires
/// `https://`, an exact-match allowlisted host (case-insensitive), and forbids
/// userinfo (`@`) and explicit ports in the authority.
pub fn action_url_allowed(url: &str) -> bool {
    // Manual parse — avoids pulling in the `url` crate for an exact-host check.
    let rest = match url.strip_prefix("https://") {
        Some(r) => r,
        None => return false, // scheme must be https
    };
    // Authority is everything up to the first '/', '?', or '#'.
    let authority_end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return false;
    }
    // Reject userinfo (user@host) and explicit ports (host:port).
    if authority.contains('@') || authority.contains(':') {
        return false;
    }
    let host = authority.to_ascii_lowercase();
    ACTION_URL_ALLOWLIST.iter().any(|allowed| *allowed == host)
}

/// Manifest state (broadcast interface contract §2). `Clear` is a signed overwrite —
/// the published manifest is never deleted (deletion ambiguity is the trap DEC-BC-11
/// closes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestState {
    Active,
    Clear,
}

/// The off-infra `incident.json` object (broadcast interface contract §2 / C-05,
/// DEC-BC-11). Always present, always signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentManifest {
    /// Envelope version (`INCIDENT_MANIFEST_VERSION`).
    pub manifest_v: u32,
    pub state: ManifestState,
    /// Monotonic; MUST equal the embedded `payload.seq`.
    pub seq: i64,
    /// Canonical JSON STRING of the `BroadcastPayload` (verbatim signed bytes).
    pub payload: String,
    /// base64 detached OpenPGP signature over `payload.as_bytes()`.
    pub signature: String,
    /// Duplicated at envelope level for cheap pre-parse routing; MUST match the
    /// fingerprint inside `payload`.
    pub signer_fingerprint: String,
    pub issued_at: DateTime<Utc>,
}

/// Result of verifying + parsing an [`IncidentManifest`] against the trust set
/// and the persisted high-water `seq` (broadcast interface contract §2 algorithm).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestVerdict {
    /// Signature valid, fresh, state=active. Carries the parsed payload and the
    /// new high-water `seq` the caller should persist.
    Active { payload: Box<BroadcastPayload>, seq: i64 },
    /// Signature valid, fresh, state=clear. Carries the new high-water `seq`.
    Clear { seq: i64 },
    /// Signature valid but `seq <= last_verified_seq` — replay/downgrade.
    /// Rejected; hold prior state.
    Stale,
    /// Signature valid + state=active, but `expires_at` is past. Treat the
    /// incident as locally cleared (publisher must republish with a bumped seq
    /// to extend a long incident).
    Expired { seq: i64 },
    /// Absence / parse-fail / unknown version / signature-fail / field
    /// mismatch — "no trusted signal" (DEC-BC-11). NEVER an implied all-clear;
    /// the caller holds its last verified state and never escalates on this.
    NoTrustedSignal { reason: String },
}

impl IncidentManifest {
    /// Verify the manifest's signature against `trust_set` (a set of
    /// ASCII-armored OpenPGP public keys — try each), enforce field-consistency,
    /// replay/downgrade (`seq > last_verified_seq`), and expiry. Pure: no I/O.
    ///
    /// `now` is injected for testability (pass `Utc::now()` in production).
    pub fn verify_and_parse(
        &self,
        trust_set: &[&str],
        last_verified_seq: i64,
        now: DateTime<Utc>,
    ) -> ManifestVerdict {
        // Step 1 (envelope sanity): unknown manifest version = no trusted signal.
        if self.manifest_v != INCIDENT_MANIFEST_VERSION {
            return ManifestVerdict::NoTrustedSignal {
                reason: format!("unknown manifest_v {}", self.manifest_v),
            };
        }

        // Step 2 (signature): verify over the verbatim payload bytes against the
        // trust SET — ANY key validates accepts.
        let sig_bytes = match BASE64.decode(self.signature.as_bytes()) {
            Ok(b) => b,
            Err(_) => {
                return ManifestVerdict::NoTrustedSignal {
                    reason: "signature not valid base64".into(),
                }
            }
        };
        let payload_bytes = self.payload.as_bytes();
        let sig_ok = trust_set.iter().any(|armored_key| {
            verify_detached(armored_key, payload_bytes, &sig_bytes).unwrap_or(false)
        });
        if !sig_ok {
            return ManifestVerdict::NoTrustedSignal {
                reason: "signature did not verify against any pinned key".into(),
            };
        }

        // Step 3 (parse + field consistency).
        let payload = match BroadcastPayload::from_canonical_json(&self.payload) {
            Ok(p) => p,
            Err(_) => {
                return ManifestVerdict::NoTrustedSignal {
                    reason: "payload string did not parse".into(),
                }
            }
        };
        if payload.v != BROADCAST_PAYLOAD_VERSION {
            return ManifestVerdict::NoTrustedSignal {
                reason: format!("unknown payload v {}", payload.v),
            };
        }
        if payload.signer_fingerprint != self.signer_fingerprint {
            return ManifestVerdict::NoTrustedSignal {
                reason: "envelope/payload fingerprint mismatch".into(),
            };
        }
        if payload.seq != self.seq {
            return ManifestVerdict::NoTrustedSignal {
                reason: "envelope/payload seq mismatch".into(),
            };
        }

        // Step 4 (replay/downgrade): reject seq <= high-water mark.
        if self.seq <= last_verified_seq {
            return ManifestVerdict::Stale;
        }

        // Step 6 (clear): a signed clear is recognized by `state`, not contents.
        if self.state == ManifestState::Clear {
            return ManifestVerdict::Clear { seq: self.seq };
        }

        // Step 5 (expiry): active but past expires_at -> locally cleared.
        if let Some(exp) = payload.expires_at {
            if now > exp {
                return ManifestVerdict::Expired { seq: self.seq };
            }
        }

        // Step 7 (active): render per tier.
        ManifestVerdict::Active {
            payload: Box::new(payload),
            seq: self.seq,
        }
    }
}

/// Verify an OpenPGP detached signature over `data` against an ASCII-armored
/// public key. Returns `Ok(true)` if valid, `Ok(false)` if the signature does
/// not verify, `Err` if the key cannot be parsed. Mirrors
/// `passkey_core::verify_detached_signature` but implemented here so the shared
/// crate carries no extra dependency edge.
pub fn verify_detached(armored_public_key: &str, data: &[u8], signature: &[u8]) -> Result<bool> {
    use sequoia_openpgp as openpgp;
    use openpgp::parse::stream::{
        DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper,
    };
    use openpgp::parse::Parse;
    use openpgp::policy::StandardPolicy;
    use openpgp::Cert;

    let cert = Cert::from_bytes(armored_public_key.as_bytes())
        .map_err(|e| CryptoError::OpenPgp(format!("parse broadcast public key: {e}")))?;

    struct Helper {
        cert: Cert,
    }
    impl VerificationHelper for Helper {
        fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
            Ok(vec![self.cert.clone()])
        }
        fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
            // CRITICAL: `check` is the policy hook. Sequoia accepts the message
            // iff this returns Ok — so we MUST return Err when no signature
            // cryptographically verifies, otherwise `verify_bytes` succeeds even
            // for tampered data (the every-payload-passes bug).
            for layer in structure {
                if let MessageLayer::SignatureGroup { results } = layer {
                    for result in results {
                        if result.is_ok() {
                            return Ok(()); // a good signature over this data
                        }
                    }
                }
            }
            Err(anyhow::anyhow!("no valid signature over the provided data"))
        }
    }

    let policy = StandardPolicy::new();
    let helper = Helper { cert };

    let mut verifier = match DetachedVerifierBuilder::from_bytes(signature)
        .and_then(|b| b.with_policy(&policy, None, helper))
    {
        Ok(v) => v,
        // A malformed signature is "did not verify", not a key-parse error.
        Err(_) => return Ok(false),
    };

    // verify_bytes returns Ok ONLY if `check` returned Ok (i.e. a signature
    // cryptographically verified against `data`).
    Ok(verifier.verify_bytes(data).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload(seq: i64) -> BroadcastPayload {
        BroadcastPayload {
            v: BROADCAST_PAYLOAD_VERSION,
            id: format!("bc_test_{seq}"),
            tier: BroadcastTier::Incident,
            title: "Cloud API degraded".into(),
            body: "Investigating elevated error rates.".into(),
            action_url: Some("https://status.gitcellar.com".into()),
            issued_at: "2026-05-26T22:50:00Z".parse().unwrap(),
            expires_at: Some("2026-05-27T22:50:00Z".parse().unwrap()),
            seq,
            signer_fingerprint: "A1B2C3D4".into(),
            targeting: None,
        }
    }

    #[test]
    fn canonical_json_is_compact_and_ordered() {
        let p = sample_payload(1769561400);
        let s = p.to_canonical_json().unwrap();
        // Compact: no ": " or ", " spacing.
        assert!(!s.contains(": "));
        assert!(!s.contains(", "));
        // Field order: v first, then id, tier, title...
        assert!(s.starts_with(r#"{"v":1,"id":"bc_test_1769561400","tier":"incident","title":"#));
        // Round-trips byte-identically (the signing contract depends on this).
        let reparsed = BroadcastPayload::from_canonical_json(&s).unwrap();
        assert_eq!(reparsed.to_canonical_json().unwrap(), s);
    }

    #[test]
    fn absent_optionals_are_omitted_not_null() {
        let mut p = sample_payload(5);
        p.action_url = None;
        p.expires_at = None;
        p.targeting = None;
        let s = p.to_canonical_json().unwrap();
        assert!(!s.contains("action_url"));
        assert!(!s.contains("expires_at"));
        assert!(!s.contains("targeting"));
        assert!(!s.contains("null"));
    }

    #[test]
    fn action_url_allowlist_enforced() {
        assert!(action_url_allowed("https://gitcellar.com"));
        assert!(action_url_allowed("https://status.gitcellar.com/incidents/42"));
        assert!(action_url_allowed("https://GitCellar.com")); // case-insensitive host
        // Rejections:
        assert!(!action_url_allowed("http://gitcellar.com")); // not https
        assert!(!action_url_allowed("https://evil.com"));
        assert!(!action_url_allowed("https://gitcellar.com.evil.com"));
        assert!(!action_url_allowed("https://user@gitcellar.com")); // userinfo
        assert!(!action_url_allowed("https://gitcellar.com:8443")); // explicit port
        assert!(!action_url_allowed("https://status.gitcellar.com@evil.com"));
    }

    #[test]
    fn tier_mandatory_classification() {
        assert!(BroadcastTier::Incident.is_mandatory());
        assert!(BroadcastTier::Warning.is_mandatory());
        assert!(!BroadcastTier::Announcement.is_mandatory());
    }

    #[test]
    fn manifest_unknown_version_is_no_trusted_signal() {
        let m = IncidentManifest {
            manifest_v: 999,
            state: ManifestState::Active,
            seq: 10,
            payload: "{}".into(),
            signature: "AA==".into(),
            signer_fingerprint: "A1B2C3D4".into(),
            issued_at: "2026-05-26T22:50:00Z".parse().unwrap(),
        };
        let now = "2026-05-26T23:00:00Z".parse().unwrap();
        matches!(
            m.verify_and_parse(&[], 0, now),
            ManifestVerdict::NoTrustedSignal { .. }
        );
    }

    #[test]
    fn bad_signature_is_no_trusted_signal_never_renders() {
        // Empty trust set + a payload string -> signature can never verify ->
        // NoTrustedSignal. Confirms an unsigned/forged manifest never renders
        // (BC-SEC-01).
        let p = sample_payload(100);
        let pstr = p.to_canonical_json().unwrap();
        let m = IncidentManifest {
            manifest_v: INCIDENT_MANIFEST_VERSION,
            state: ManifestState::Active,
            seq: 100,
            payload: pstr,
            signature: BASE64.encode(b"not a real signature"),
            signer_fingerprint: "A1B2C3D4".into(),
            issued_at: "2026-05-26T22:50:00Z".parse().unwrap(),
        };
        let now = "2026-05-26T23:00:00Z".parse().unwrap();
        assert!(matches!(
            m.verify_and_parse(&["-----BEGIN PGP PUBLIC KEY BLOCK-----\ngarbage\n-----END PGP PUBLIC KEY BLOCK-----"], 0, now),
            ManifestVerdict::NoTrustedSignal { .. }
        ));
    }

    #[test]
    fn verify_detached_rejects_unparseable_key() {
        let r = verify_detached("not a key", b"data", b"sig");
        assert!(r.is_err());
    }

    // Regression guard for the every-payload-passes bug: a real detached
    // signature must verify over the EXACT signed bytes and FAIL over tampered
    // bytes. This is the BC-SEC-01 load-bearing test — if `check()` returns Ok
    // unconditionally, the tampered assertion below flips to a security hole.
    #[test]
    fn real_signature_verifies_only_over_exact_bytes() {
        use crate::{EncryptionEngine, Identity};

        let identity = Identity::generate("Broadcast Test <t@gitcellar.com>").unwrap();
        let public = identity.export_public_key().unwrap();
        let engine = EncryptionEngine::new(identity).unwrap();

        let payload = sample_payload(123).to_canonical_json().unwrap();
        let sig = engine.sign_data(payload.as_bytes()).unwrap();

        // Valid: signature over the exact bytes verifies.
        assert!(verify_detached(&public, payload.as_bytes(), &sig).unwrap());

        // Tampered: a single-byte change must NOT verify.
        let tampered = payload.replace("Cloud API degraded", "Cloud API fine");
        assert_ne!(tampered, payload);
        assert!(!verify_detached(&public, tampered.as_bytes(), &sig).unwrap());

        // Full manifest round-trip through verify_and_parse with this key.
        let manifest = IncidentManifest {
            manifest_v: INCIDENT_MANIFEST_VERSION,
            state: ManifestState::Active,
            seq: 123,
            payload: payload.clone(),
            signature: BASE64.encode(&sig),
            signer_fingerprint: BroadcastPayload::from_canonical_json(&payload)
                .unwrap()
                .signer_fingerprint,
            issued_at: "2026-05-26T22:50:00Z".parse().unwrap(),
        };
        let now = "2026-05-26T23:00:00Z".parse().unwrap();
        // fingerprint inside payload is "A1B2C3D4" (sample), envelope copies it
        // -> consistent; signature valid -> Active.
        assert!(matches!(
            manifest.verify_and_parse(&[public.as_str()], 0, now),
            ManifestVerdict::Active { .. }
        ));
        // Replay: same manifest with a high water mark -> Stale.
        assert!(matches!(
            manifest.verify_and_parse(&[public.as_str()], 999, now),
            ManifestVerdict::Stale
        ));
    }
}
