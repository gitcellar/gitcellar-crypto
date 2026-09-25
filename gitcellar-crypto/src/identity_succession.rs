//! Identity succession statements (`gc-identity-succession-v1`) — KTR-5, DEC-KT-03.
//!
//! When an account replaces its identity key (recovery from the phrase on a new
//! machine, cutting off a lost one), the Cloud must accept the new key only on
//! the say-so of the account's **recovery authority**: the Ed25519 master key
//! derived from the recovery phrase ([`MaterializedMaster::from_phrase`]), whose
//! private half is never stored and so is not on a stolen machine. A succession
//! statement is that say-so: the master signs "for this account, identity
//! `old` is succeeded by identity `new`, at key version `n`".
//!
//! ## The canonical (frozen)
//!
//! ```text
//! lp("gc-identity-succession-v1") ‖ lp(account) ‖ lp(old_fingerprint)
//!                                 ‖ lp(new_fingerprint) ‖ lp(new_key_version)
//!                                 ‖ lp(issued_at_unix)
//! ```
//!
//! `lp` is [`crate::canonical::lp_push`]. The tag is distinct from every other
//! signed canonical in the crate, and the signature is a raw 64-byte Ed25519
//! signature by the master (the same key shape as device and revocation certs),
//! verified with `verify_strict`. `account` is the account's key-directory label
//! — the lowercased verified email the Cloud key directory keys accounts on —
//! trimmed and lowercased here; fingerprints are normalized with
//! [`normalize_fingerprint`], so rendering differences never change the bytes.
//!
//! ## What verification refuses
//!
//! [`verify_identity_succession`] takes the account's registered master public
//! key and the account's *current* identity key version, and refuses — each with
//! its own [`SuccessionError`] variant — a statement that:
//!
//! - names the same identity as old and new ([`SuccessionError::SameIdentity`]);
//! - has an empty account or fingerprint ([`SuccessionError::EmptyField`]);
//! - does not move the key version forward ([`SuccessionError::NotNewerVersion`]),
//!   so an old statement replayed after a later succession does nothing;
//! - is not signed by that master ([`SuccessionError::SignatureInvalid`]).
//!
//! It does not check that `old_fingerprint` is the account's current identity:
//! the caller holds that record and compares it (a statement is about one
//! transition, and the Cloud decides whether it is the transition it is at).

use crate::canonical::lp_push;
use crate::grant_signing::normalize_fingerprint;
use crate::master::{verify_with_pubkey, MasterKeyError, MaterializedMaster};
use thiserror::Error;

/// Versioned domain tag for the succession canonical. Bump only with a
/// coordinated signer + verifier change — old statements stop verifying.
pub const IDENTITY_SUCCESSION_VERSION: &str = "gc-identity-succession-v1";

/// Why a succession statement was refused. One variant per check.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SuccessionError {
    /// The account, old fingerprint or new fingerprint is empty.
    #[error("succession statement has an empty {0}")]
    EmptyField(&'static str),
    /// Old and new identity fingerprints are the same — not a succession.
    #[error("succession statement names the same identity as old and new")]
    SameIdentity,
    /// The statement's key version is not greater than the account's current
    /// one — a replay of an older statement, or a statement for a past state.
    #[error("succession key version {statement} is not greater than the current version {current}")]
    NotNewerVersion { statement: u32, current: u32 },
    /// The supplied master public key is not a valid Ed25519 point.
    #[error("invalid master public key: {0}")]
    InvalidPublicKey(String),
    /// The signature does not verify under the account's master public key.
    #[error("succession signature does not verify under the account's master key")]
    SignatureInvalid,
    /// The transported signature could not be decoded to 64 bytes.
    #[error("succession signature is malformed: {0}")]
    MalformedSignature(String),
}

/// "For `account`, identity `old_fingerprint` is succeeded by
/// `new_fingerprint` at identity key version `new_key_version`" — signed by the
/// account's phrase-derived master key. See the module docs for the canonical.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IdentitySuccession {
    /// The account's key-directory label (lowercased verified email). Normalized.
    pub account: String,
    /// Fingerprint of the identity being retired. Normalized.
    pub old_fingerprint: String,
    /// Fingerprint of the identity taking over. Normalized.
    pub new_fingerprint: String,
    /// The account's identity key version after this succession; must be greater
    /// than the version the verifier currently holds.
    pub new_key_version: u32,
    /// Issuance time, unix seconds.
    pub issued_at_unix: i64,
}

impl IdentitySuccession {
    /// Build a statement, normalizing the account and both fingerprints.
    pub fn new(
        account: &str,
        old_fingerprint: &str,
        new_fingerprint: &str,
        new_key_version: u32,
        issued_at_unix: i64,
    ) -> Self {
        IdentitySuccession {
            account: normalize_account(account),
            old_fingerprint: normalize_fingerprint(old_fingerprint),
            new_fingerprint: normalize_fingerprint(new_fingerprint),
            new_key_version,
            issued_at_unix,
        }
    }

    /// Deterministic, injection-safe canonical bytes — what the master signs.
    /// Re-normalizes, so a struct built by literal canonicalizes like `new`'s.
    pub fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(192);
        lp_push(&mut out, IDENTITY_SUCCESSION_VERSION);
        lp_push(&mut out, &normalize_account(&self.account));
        lp_push(&mut out, &normalize_fingerprint(&self.old_fingerprint));
        lp_push(&mut out, &normalize_fingerprint(&self.new_fingerprint));
        lp_push(&mut out, &self.new_key_version.to_string());
        lp_push(&mut out, &self.issued_at_unix.to_string());
        out
    }

    /// The version-independent checks: no empty field, old != new.
    fn validate_shape(&self) -> Result<(), SuccessionError> {
        if normalize_account(&self.account).is_empty() {
            return Err(SuccessionError::EmptyField("account"));
        }
        let old = normalize_fingerprint(&self.old_fingerprint);
        let new = normalize_fingerprint(&self.new_fingerprint);
        if old.is_empty() {
            return Err(SuccessionError::EmptyField("old_fingerprint"));
        }
        if new.is_empty() {
            return Err(SuccessionError::EmptyField("new_fingerprint"));
        }
        if old == new {
            return Err(SuccessionError::SameIdentity);
        }
        Ok(())
    }
}

fn normalize_account(account: &str) -> String {
    account.trim().to_ascii_lowercase()
}

/// Sign a succession statement with the account's phrase-derived master key.
/// Refuses a statement that could never verify (empty field, old == new).
pub fn sign_identity_succession(
    master: &MaterializedMaster,
    statement: &IdentitySuccession,
) -> Result<[u8; 64], SuccessionError> {
    statement.validate_shape()?;
    Ok(master.sign(&statement.canonical()))
}

/// Verify a succession statement for an account whose registered master public
/// key is `expected_master_pubkey` and whose identity key is currently at
/// `current_key_version`. `Ok(())` means the Cloud may accept the new identity
/// key named in the statement (after checking `old_fingerprint` is the current
/// identity — see the module docs).
pub fn verify_identity_succession(
    expected_master_pubkey: &[u8; 32],
    statement: &IdentitySuccession,
    signature: &[u8; 64],
    current_key_version: u32,
) -> Result<(), SuccessionError> {
    statement.validate_shape()?;
    if statement.new_key_version <= current_key_version {
        return Err(SuccessionError::NotNewerVersion {
            statement: statement.new_key_version,
            current: current_key_version,
        });
    }
    verify_with_pubkey(expected_master_pubkey, &statement.canonical(), signature).map_err(|e| match e {
        MasterKeyError::InvalidPublicKey(m) => SuccessionError::InvalidPublicKey(m),
        _ => SuccessionError::SignatureInvalid,
    })
}

/// Base64 (standard) for transporting a succession signature.
pub fn encode_succession_signature(signature: &[u8; 64]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(signature)
}

/// Decode a transported succession signature; anything but 64 bytes of valid
/// base64 is [`SuccessionError::MalformedSignature`].
pub fn decode_succession_signature(signature_b64: &str) -> Result<[u8; 64], SuccessionError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| SuccessionError::MalformedSignature(e.to_string()))?;
    <[u8; 64]>::try_from(bytes.as_slice())
        .map_err(|_| SuccessionError::MalformedSignature(format!("{} bytes, expected 64", bytes.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_canonical_is_frozen() {
        let s = IdentitySuccession::new(" Alice@B.com ", "aa bb", "cc dd", 2, 1_750_000_000);
        let expected = b"25:gc-identity-succession-v1\n11:alice@b.com\n4:AABB\n4:CCDD\n1:2\n10:1750000000\n"
            .to_vec();
        assert_eq!(s.canonical(), expected);
    }

    #[test]
    fn every_field_is_bound() {
        let base = IdentitySuccession::new("a@b", "AA", "BB", 2, 7);
        let variants = [
            IdentitySuccession { account: "c@d".into(), ..base.clone() },
            IdentitySuccession { old_fingerprint: "CC".into(), ..base.clone() },
            IdentitySuccession { new_fingerprint: "CC".into(), ..base.clone() },
            IdentitySuccession { new_key_version: 3, ..base.clone() },
            IdentitySuccession { issued_at_unix: 8, ..base.clone() },
        ];
        for v in &variants {
            assert_ne!(v.canonical(), base.canonical(), "{v:?}");
        }
    }
}
