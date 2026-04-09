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
//! - Derives deterministic 32-byte key material for encryption
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
use rand::RngCore;
use tracing::{debug, info};

/// Number of words in a recovery code
pub const RECOVERY_CODE_WORD_COUNT: usize = 24;

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
    /// Uses BIP39 seed derivation to produce deterministic key material
    /// suitable for encrypting/decrypting identity backups.
    pub fn derive_key_material(&self) -> [u8; 32] {
        // Use BIP39's built-in seed derivation with empty password
        // This gives us 64 bytes derived from the mnemonic
        let seed = self.mnemonic.to_seed("");

        // Use first 32 bytes as key material
        let mut key_material = [0u8; 32];
        key_material.copy_from_slice(&seed[..32]);

        debug!("Derived key material from recovery code");
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
