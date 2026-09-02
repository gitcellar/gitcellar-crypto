//! Recovery Key System
//!
//! Generates and validates 24-word BIP39 mnemonic phrases for account recovery.
//! The recovery key allows users to regain access to their encrypted identity
//! after losing access to their machine.
//!
//! # Key Properties
//!
//! - 24 words = 256 bits of entropy
//! - User must save it (shown only once during setup)
//! - Derives deterministic 32-byte key material for encryption via
//!   domain-separated HKDF-SHA256 (`gitcellar-passkey-recovery-v1`)
//!
//! # Example
//!
//! ```ignore
//! use passkey_core::recovery::{RecoveryCode, generate_recovery_code};
//!
//! // Generate new recovery code
//! let code = generate_recovery_code()?;
//! println!("Save these words:\n{}", code.format_for_display());
//!
//! // Later, derive key material for encryption/decryption
//! let key_material = code.derive_key_material();
//! ```

mod bip39_impl;
mod derive;

pub use bip39_impl::*;
pub use derive::*;

use crate::error::{PasskeyError, Result};
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use tracing::{debug, info};
use zeroize::Zeroizing;

/// Number of words in a recovery code
pub const RECOVERY_CODE_WORD_COUNT: usize = 24;

/// Algorithm identity for the recovery key-material derivation scheme.
///
/// Mirrors `MasterKeyDerivation` in gitcellar-crypto's `master.rs`
/// (the house HKDF idiom): a zero-sized anchor exposing the canonical
/// derivation constants. Bumping [`Self::VERSION`] requires a corresponding
/// bump to [`Self::DERIVATION_INFO`] so older and newer derivations cannot
/// collide.
///
/// # Why domain separation (added pre-launch, 2026-07-20)
///
/// The same 24-word phrase / BIP39 seed feeds two independent keys:
///
/// 1. The **master keypair** (`gitcellar-crypto::master`) — HKDF-SHA256 with
///    `info = b"gitcellar-master-v1"`.
/// 2. This **recovery/escrow key material** — which, before 2026-07-20, was
///    the raw seed's first 32 bytes with **no** domain tag.
///
/// The untagged form was not a live collision (the two derivations were
/// separate by construction), but it left a latent hazard: any future third
/// use of the seed could collide with the escrow key that guards the
/// `identity_backups` cloud blob — the only cloud account-recovery path.
/// The derivation was switched to domain-separated
/// HKDF-SHA256 while there were **zero production escrow blobs** — so the
/// cutover was free.
pub struct RecoveryKeyDerivation;

impl RecoveryKeyDerivation {
    /// HKDF `info` parameter for domain separation. Bumping this makes every
    /// existing escrow bundle and recovery identifier underivable — after
    /// launch, only do this in a planned migration.
    pub const DERIVATION_INFO: &'static [u8] = b"gitcellar-passkey-recovery-v1";

    /// Schema version of the derivation.
    pub const VERSION: u32 = 1;
}

/// A BIP39 recovery code (24-word mnemonic)
///
/// Provides deterministic key derivation for account recovery.
#[derive(Clone)]
pub struct RecoveryCode {
    mnemonic: Mnemonic,
}

impl RecoveryCode {
    /// Parse a recovery code from a phrase
    ///
    /// Validates the phrase as a proper BIP39 mnemonic with 24 words.
    ///
    /// # Arguments
    /// * `phrase` - Space-separated list of 24 BIP39 words
    pub fn from_phrase(phrase: &str) -> Result<Self> {
        let normalized = normalize_phrase(phrase);

        // Check word count
        let word_count = normalized.split_whitespace().count();
        if word_count != RECOVERY_CODE_WORD_COUNT {
            return Err(PasskeyError::InvalidRecoveryCode(format!(
                "Expected {} words, got {}",
                RECOVERY_CODE_WORD_COUNT, word_count
            )));
        }

        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &normalized)
            .map_err(|e| PasskeyError::InvalidRecoveryCode(format!("Invalid mnemonic: {}", e)))?;

        debug!("Parsed valid recovery code");
        Ok(Self { mnemonic })
    }

    /// Get the recovery code as a phrase string
    pub fn phrase(&self) -> String {
        self.mnemonic.to_string()
    }

    /// Derive 32-byte key material from the recovery code
    ///
    /// Deterministic derivation suitable for encrypting/decrypting identity
    /// backups (the `identity_backups` escrow bundle) and for the derived
    /// verification hash / identifier in `derive.rs`. The flow is:
    ///
    /// 1. BIP39 PBKDF2-HMAC-SHA512 with empty passphrase → 64-byte seed.
    /// 2. HKDF-SHA256 expand the seed with
    ///    `info = b"gitcellar-passkey-recovery-v1"` → 32 bytes.
    ///
    /// The HKDF `info` tag domain-separates this key from every other use of
    /// the same seed (notably the master keypair, `gitcellar-master-v1` in
    /// `gitcellar-crypto::master`) — see [`RecoveryKeyDerivation`] for the
    /// rationale and the pre-launch cutover note (2026-07-20; the previous
    /// derivation was the raw seed's first 32 bytes, untagged).
    pub fn derive_key_material(&self) -> [u8; 32] {
        // The 64-byte BIP39 seed is an intermediate secret — wipe it on exit.
        let seed: Zeroizing<[u8; 64]> = Zeroizing::new(self.mnemonic.to_seed(""));

        let mut key_material = [0u8; 32];
        Hkdf::<Sha256>::new(None, seed.as_ref())
            .expand(RecoveryKeyDerivation::DERIVATION_INFO, &mut key_material)
            .expect("HKDF-SHA256 expand to 32 bytes cannot fail");

        debug!("Derived key material from recovery code (HKDF, domain-separated)");
        key_material
    }

    /// Verify that this recovery code is valid
    ///
    /// Always returns true for a successfully parsed RecoveryCode.
    pub fn is_valid(&self) -> bool {
        true
    }

    /// Format the recovery code for display (groups of 4 words per line)
    ///
    /// Makes the recovery code easier to write down and verify.
    ///
    /// # Example output
    /// ```text
    /// abandon ability able about
    /// above absent absorb abstract
    /// absurd abuse access accident
    /// account accuse achieve acid
    /// acoustic acquire across act
    /// action actor actress actual
    /// ```
    pub fn format_for_display(&self) -> String {
        let phrase = self.phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let mut lines = Vec::new();

        for chunk in words.chunks(4) {
            lines.push(chunk.join(" "));
        }

        lines.join("\n")
    }

    /// Format recovery code with line numbers for display
    ///
    /// # Example output
    /// ```text
    ///  1- 4: abandon ability able about
    ///  5- 8: above absent absorb abstract
    ///  9-12: absurd abuse access accident
    /// 13-16: account accuse achieve acid
    /// 17-20: acoustic acquire across act
    /// 21-24: action actor actress actual
    /// ```
    pub fn format_with_numbers(&self) -> String {
        let phrase = self.phrase();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        let mut lines = Vec::new();

        for (i, chunk) in words.chunks(4).enumerate() {
            let start = i * 4 + 1;
            let end = start + chunk.len() - 1;
            lines.push(format!("{:2}-{:2}: {}", start, end, chunk.join(" ")));
        }

        lines.join("\n")
    }
}

/// Generate a new recovery code
///
/// Creates a cryptographically secure 24-word BIP39 mnemonic.
/// This should be called during initial account setup.
///
/// # Returns
/// A new RecoveryCode with 256 bits of entropy
pub fn generate_recovery_code() -> Result<RecoveryCode> {
    // Generate 256-bit entropy for 24 words
    let mut entropy = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut entropy);

    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| PasskeyError::KeyGeneration(format!("Failed to generate mnemonic: {}", e)))?;

    info!("Generated new recovery code ({} words)", RECOVERY_CODE_WORD_COUNT);

    Ok(RecoveryCode { mnemonic })
}

/// Check if a phrase looks like a valid recovery code
///
/// Quick validation without full parsing.
pub fn is_valid_phrase(phrase: &str) -> bool {
    RecoveryCode::from_phrase(phrase).is_ok()
}

/// Validate individual words and return any invalid ones
///
/// Useful for providing feedback to users typing their recovery code.
///
/// # Returns
/// A vector of (1-based position, word) tuples for each invalid word
pub fn find_invalid_words(phrase: &str) -> Vec<(usize, String)> {
    let word_list = Language::English.word_list();
    let mut invalid_words = Vec::new();

    for (i, word) in phrase.split_whitespace().enumerate() {
        let normalized = word.to_lowercase();
        if !word_list.iter().any(|w| *w == normalized) {
            invalid_words.push((i + 1, word.to_string()));
        }
    }

    invalid_words
}

/// Normalize a recovery phrase (lowercase, single spaces)
fn normalize_phrase(phrase: &str) -> String {
    phrase
        .to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_recovery_code() {
        let code = generate_recovery_code().unwrap();
        let phrase = code.phrase();

        // Should have 24 words
        assert_eq!(phrase.split_whitespace().count(), 24);

        // Should be valid
        assert!(code.is_valid());
    }

    #[test]
    fn test_parse_valid_phrase() {
        // Known valid BIP39 mnemonic (24 words)
        let valid = "abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon art";

        let code = RecoveryCode::from_phrase(valid).unwrap();
        assert!(code.is_valid());
    }

    #[test]
    fn test_parse_invalid_word() {
        let invalid = "abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon abandon abandon xyz123";

        let result = RecoveryCode::from_phrase(invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_wrong_word_count() {
        let too_short = "abandon abandon abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon";

        let result = RecoveryCode::from_phrase(too_short);
        assert!(matches!(result, Err(PasskeyError::InvalidRecoveryCode(_))));
    }

    #[test]
    fn test_derive_key_material_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon art";

        let code1 = RecoveryCode::from_phrase(phrase).unwrap();
        let code2 = RecoveryCode::from_phrase(phrase).unwrap();

        let key1 = code1.derive_key_material();
        let key2 = code2.derive_key_material();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_derive_key_material_known_answer() {
        // Known-answer test pinning the HKDF-SHA256 domain-separated
        // derivation (info = "gitcellar-passkey-recovery-v1", cutover
        // 2026-07-20). If this test breaks, every existing escrow bundle
        // and recovery identifier becomes underivable — post-launch that
        // is a migration, not a refactor.
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon art";

        let code = RecoveryCode::from_phrase(phrase).unwrap();
        let key = code.derive_key_material();

        assert_eq!(
            hex::encode(key),
            "226eaf013aa3d5a947c85fa0db92b348eb068f8d2da3723a38f0cb7b58c0528a"
        );

        // Guard against silent regression to the pre-2026-07-20 derivation
        // (raw first 32 bytes of the BIP39 seed, no domain tag).
        assert_ne!(
            hex::encode(key),
            "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf70",
            "derive_key_material regressed to the untagged raw-seed derivation"
        );
    }

    #[test]
    fn test_derivation_info_pinned() {
        // If anyone changes DERIVATION_INFO, every existing escrow bundle
        // becomes unrecoverable. This pins the value; breaking it forces the
        // author to confront the migration question. (Same pattern as
        // `derivation_info_pinned` in gitcellar-crypto's master.rs.)
        assert_eq!(
            RecoveryKeyDerivation::DERIVATION_INFO,
            b"gitcellar-passkey-recovery-v1"
        );
        assert_eq!(RecoveryKeyDerivation::VERSION, 1);
    }

    #[test]
    fn test_format_for_display() {
        let code = generate_recovery_code().unwrap();
        let formatted = code.format_for_display();
        let lines: Vec<_> = formatted.lines().collect();

        assert_eq!(lines.len(), 6); // 24 words / 4 per line = 6 lines
    }

    #[test]
    fn test_format_with_numbers() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon art";

        let code = RecoveryCode::from_phrase(phrase).unwrap();
        let formatted = code.format_with_numbers();

        assert!(formatted.contains(" 1- 4:"));
        assert!(formatted.contains("21-24:"));
    }

    #[test]
    fn test_find_invalid_words() {
        let phrase = "abandon invalid123 ability xyz";
        let invalid = find_invalid_words(phrase);

        assert_eq!(invalid.len(), 2);
        assert_eq!(invalid[0], (2, "invalid123".to_string()));
        assert_eq!(invalid[1], (4, "xyz".to_string()));
    }

    #[test]
    fn test_is_valid_phrase() {
        let valid = "abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon art";

        assert!(is_valid_phrase(valid));
        assert!(!is_valid_phrase("not valid"));
    }

    #[test]
    fn test_normalize_phrase() {
        let messy = "  ABANDON   Ability   ABLE  ";
        let normalized = normalize_phrase(messy);
        assert_eq!(normalized, "abandon ability able");
    }
}
