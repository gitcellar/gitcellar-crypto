//! Identity export and import utilities
//!
//! Provides ASCII-armored import/export of OpenPGP keys.

use crate::error::{PasskeyError, Result};
use crate::identity::Identity;
use sequoia_openpgp as openpgp;
use openpgp::armor;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;

impl Identity {
    /// Export the public key as ASCII-armored PGP format
    ///
    /// Returns a string that can be shared publicly or used for verification.
    pub fn export_public_key(&self) -> Result<String> {
        let mut output = Vec::new();

        {
            let mut writer = armor::Writer::new(&mut output, armor::Kind::PublicKey)
                .map_err(|e| PasskeyError::KeySave(format!("Failed to create armor writer: {}", e)))?;

            self.cert.serialize(&mut writer)
                .map_err(|e| PasskeyError::KeySave(format!("Failed to serialize: {}", e)))?;

            writer.finalize()
                .map_err(|e| PasskeyError::KeySave(format!("Failed to finalize: {}", e)))?;
        }

        String::from_utf8(output)
            .map_err(|e| PasskeyError::KeySave(format!("Invalid UTF-8: {}", e)))
    }

    /// Export the secret key as ASCII-armored PGP format
    ///
    /// WARNING: This exports secret key material. Handle with extreme care!
    /// This is typically used for backup or transfer purposes.
    pub fn export_secret_key(&self) -> Result<String> {
        let mut output = Vec::new();

        {
            let mut writer = armor::Writer::new(&mut output, armor::Kind::SecretKey)
                .map_err(|e| PasskeyError::KeySave(format!("Failed to create armor writer: {}", e)))?;

            self.cert.as_tsk().serialize(&mut writer)
                .map_err(|e| PasskeyError::KeySave(format!("Failed to serialize: {}", e)))?;

            writer.finalize()
                .map_err(|e| PasskeyError::KeySave(format!("Failed to finalize: {}", e)))?;
        }

        String::from_utf8(output)
            .map_err(|e| PasskeyError::KeySave(format!("Invalid UTF-8: {}", e)))
    }

    /// Import identity from ASCII-armored secret key
    ///
    /// # Arguments
    /// * `armored` - ASCII-armored PGP secret key block
    pub fn from_armored_secret_key(armored: &str) -> Result<Self> {
        let cert = openpgp::Cert::from_bytes(armored.as_bytes())
            .map_err(|e| PasskeyError::KeyLoad(format!("Failed to parse armored key: {}", e)))?;

        // Extract user ID
        let user_id = cert.userids()
            .next()
            .and_then(|uid| String::from_utf8(uid.userid().value().to_vec()).ok())
            .unwrap_or_else(|| "unknown".to_string());

        Ok(Self { cert, user_id })
    }

    /// Import identity from ASCII-armored public key
    ///
    /// Note: This identity will not have secret key material and cannot
    /// be used for signing or decryption - only for verification.
    ///
    /// # Arguments
    /// * `armored` - ASCII-armored PGP public key block
    pub fn from_armored_public_key(armored: &str) -> Result<Self> {
        let cert = openpgp::Cert::from_bytes(armored.as_bytes())
            .map_err(|e| PasskeyError::KeyLoad(format!("Failed to parse armored key: {}", e)))?;

        // Extract user ID
        let user_id = cert.userids()
            .next()
            .and_then(|uid| String::from_utf8(uid.userid().value().to_vec()).ok())
            .unwrap_or_else(|| "unknown".to_string());

        Ok(Self { cert, user_id })
    }
}

/// Parse a public key from ASCII-armored format
///
/// Returns the OpenPGP certificate for use in verification.
pub fn parse_public_key(armored: &str) -> Result<openpgp::Cert> {
    openpgp::Cert::from_bytes(armored.as_bytes())
        .map_err(|e| PasskeyError::InvalidPublicKey(format!("Failed to parse public key: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_export_public_key() {
        let identity = Identity::generate("test@example.com").unwrap();
        let public = identity.export_public_key().unwrap();

        assert!(public.contains("BEGIN PGP PUBLIC KEY BLOCK"));
        assert!(public.contains("END PGP PUBLIC KEY BLOCK"));
        // Should NOT contain private key material
        assert!(!public.contains("PRIVATE"));
    }

    #[test]
    fn test_export_secret_key() {
        let identity = Identity::generate("test@example.com").unwrap();
        let secret = identity.export_secret_key().unwrap();

        assert!(secret.contains("BEGIN PGP PRIVATE KEY BLOCK"));
        assert!(secret.contains("END PGP PRIVATE KEY BLOCK"));
    }

    #[test]
    fn test_roundtrip_secret_key() {
        let original = Identity::generate("test@example.com").unwrap();
        let armored = original.export_secret_key().unwrap();

        let imported = Identity::from_armored_secret_key(&armored).unwrap();
        assert_eq!(imported.fingerprint(), original.fingerprint());
        assert_eq!(imported.user_id(), original.user_id());

        // Imported key should have signing capability
        assert!(imported.has_signing_key());
    }

    #[test]
    fn test_import_public_key() {
        let original = Identity::generate("test@example.com").unwrap();
        let public_armored = original.export_public_key().unwrap();

        let imported = Identity::from_armored_public_key(&public_armored).unwrap();
        assert_eq!(imported.fingerprint(), original.fingerprint());

        // Public-only import should NOT have signing key
        assert!(!imported.has_signing_key());
    }

    #[test]
    fn test_parse_public_key() {
        let identity = Identity::generate("test@example.com").unwrap();
        let armored = identity.export_public_key().unwrap();

        let cert = parse_public_key(&armored).unwrap();
        assert_eq!(cert.fingerprint().to_hex(), identity.fingerprint());
    }

    #[test]
    fn test_parse_invalid_key() {
        let result = parse_public_key("not a valid key");
        assert!(matches!(result, Err(PasskeyError::InvalidPublicKey(_))));
    }
}
