//! Key derivation utilities for recovery codes
//!
//! Provides additional derivation functions for recovery-related operations.

use crate::recovery::RecoveryCode;
use sha2::{Sha256, Digest};

impl RecoveryCode {
    /// Derive a verification hash from the recovery code
    ///
    /// This hash can be stored (e.g., in the credential store) to verify
    /// that a user has the correct recovery code without storing the code itself.
    pub fn derive_verification_hash(&self) -> String {
        let key_material = self.derive_key_material();

        let mut hasher = Sha256::new();
        hasher.update(&key_material);
        hasher.update(b"verification");

        hex::encode(hasher.finalize())
    }

    /// Derive a unique identifier from the recovery code
    ///
    /// This can be used to identify which recovery code was used
    /// without revealing the code itself.
    pub fn derive_identifier(&self) -> String {
        let key_material = self.derive_key_material();

        let mut hasher = Sha256::new();
        hasher.update(&key_material);
        hasher.update(b"identifier");

        let hash = hasher.finalize();
        // Take first 16 hex chars (8 bytes) for a short identifier
        hex::encode(&hash[..8])
    }

    /// Verify that a stored hash matches this recovery code
    pub fn verify_against_hash(&self, stored_hash: &str) -> bool {
        self.derive_verification_hash() == stored_hash
    }
}

/// Hash a recovery code phrase for safe storage
///
/// This produces a verification hash that can be stored in the credential store
/// to verify the user has the correct recovery phrase later.
pub fn hash_recovery_phrase(phrase: &str) -> Option<String> {
    RecoveryCode::from_phrase(phrase)
        .ok()
        .map(|code| code.derive_verification_hash())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::generate_recovery_code;

    #[test]
    fn test_derive_verification_hash() {
        let code = generate_recovery_code().unwrap();
        let hash = code.derive_verification_hash();

        // Hash should be 64 hex chars (256 bits)
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_verification_hash_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon abandon abandon art";

        let code1 = RecoveryCode::from_phrase(phrase).unwrap();
        let code2 = RecoveryCode::from_phrase(phrase).unwrap();

        assert_eq!(code1.derive_verification_hash(), code2.derive_verification_hash());
    }

    #[test]
    fn test_derive_identifier() {
        let code = generate_recovery_code().unwrap();
        let id = code.derive_identifier();

        // Identifier should be 16 hex chars
        assert_eq!(id.len(), 16);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_verify_against_hash() {
        let code = generate_recovery_code().unwrap();
        let hash = code.derive_verification_hash();

        // Same code should verify
        assert!(code.verify_against_hash(&hash));

        // Different code should not verify
        let other_code = generate_recovery_code().unwrap();
        assert!(!other_code.verify_against_hash(&hash));
    }

    #[test]
    fn test_hash_recovery_phrase() {
        let valid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon abandon \
                            abandon abandon abandon abandon abandon abandon abandon art";

        let hash = hash_recovery_phrase(valid_phrase);
        assert!(hash.is_some());
        assert_eq!(hash.unwrap().len(), 64);

        // Invalid phrase should return None
        let invalid_hash = hash_recovery_phrase("not a valid phrase");
        assert!(invalid_hash.is_none());
    }
}
