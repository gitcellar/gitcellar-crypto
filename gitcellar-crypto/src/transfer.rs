//! Identity transfer (.gckey files)
//!
//! Handles exporting and importing identities for transfer between machines.
//!
//! # Design Philosophy
//!
//! "A locked key is an oxymoron." - The gckey file IS the key. It is not
//! password-protected. Users are expected to store the file securely, just
//! like they would protect a house key or SSH private key.
//!
//! See `docs/architecture/identity/GCKEY_AND_PASSKEY_ARCHITECTURE.md` for the full
//! design rationale.

use crate::error::{CryptoError, Result};
use crate::Identity;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use tracing::info;

/// .gckey file format constants
const GCKEY_HEADER_BEGIN: &str = "-----BEGIN GITCELLAR KEY FILE-----";
const GCKEY_HEADER_END: &str = "-----END GITCELLAR KEY FILE-----";
const GCKEY_VERSION: &str = "3.0";

/// Identity bundle for machine transfer
///
/// Contains the user's identity (Ed25519 keypair) in a portable format.
/// The file is NOT encrypted - the file itself IS the secret.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityBundle {
    /// Bundle format version
    pub version: String,
    /// Creation timestamp
    pub created_at: String,
    /// User ID from identity
    pub user_id: String,
    /// Key fingerprint
    pub fingerprint: String,
    /// Secret key (base64-encoded armored PGP key)
    pub secret_key: String,
    /// Public key (base64-encoded armored PGP key)
    pub public_key: String,
}

/// Wrapper for the gckey file format
#[derive(Debug, Serialize, Deserialize)]
struct GckeyFile {
    /// Format version
    version: String,
    /// Always false in v3.0+ (file is not encrypted)
    encrypted: bool,
    /// The identity bundle as JSON
    data: IdentityBundle,
}

impl IdentityBundle {
    /// Create a bundle from an identity
    fn from_identity(identity: &Identity) -> Result<Self> {
        let secret_key = identity.export_secret_key()?;
        let public_key = identity.export_public_key()?;

        Ok(Self {
            version: GCKEY_VERSION.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            user_id: identity.user_id().to_string(),
            fingerprint: identity.fingerprint(),
            secret_key: BASE64.encode(secret_key.as_bytes()),
            public_key: BASE64.encode(public_key.as_bytes()),
        })
    }

    /// Export identity to .gckey format
    ///
    /// Creates a portable backup of the identity. The file is NOT encrypted -
    /// the file itself IS the key. Store it securely (password manager,
    /// encrypted USB drive, physical safe).
    ///
    /// # Example
    ///
    /// ```ignore
    /// let identity = Identity::load()?;
    /// let gckey = IdentityBundle::export(&identity)?;
    /// std::fs::write("my-identity.gckey", gckey)?;
    /// ```
    pub fn export(identity: &Identity) -> Result<String> {
        info!("Exporting identity to .gckey file (v{})", GCKEY_VERSION);

        let bundle = Self::from_identity(identity)?;

        let gckey_file = GckeyFile {
            version: GCKEY_VERSION.to_string(),
            encrypted: false,
            data: bundle,
        };

        let content = serde_json::to_string_pretty(&gckey_file)?;
        Ok(wrap_gckey_format(&content))
    }

    /// Import identity from .gckey format
    ///
    /// Restores an identity from a .gckey file. The file must be in the
    /// standard gckey format (v2.0 or v3.0).
    ///
    /// # Arguments
    ///
    /// * `gckey_content` - The contents of the .gckey file
    ///
    /// # Example
    ///
    /// ```ignore
    /// let gckey = std::fs::read_to_string("my-identity.gckey")?;
    /// let identity = IdentityBundle::import(&gckey)?;
    /// identity.save()?;
    /// ```
    pub fn import(gckey_content: &str) -> Result<Identity> {
        info!("Importing identity from .gckey file");

        let inner_content = unwrap_gckey_format(gckey_content)?;

        // Parse the gckey file - support both v2.0 and v3.0 formats
        let bundle = parse_gckey_content(&inner_content)?;

        // Decode and import the secret key
        let secret_key_bytes = BASE64.decode(&bundle.secret_key)
            .map_err(|e| CryptoError::BundleFormat(format!("Invalid secret key encoding: {}", e)))?;
        let secret_key_str = String::from_utf8(secret_key_bytes)
            .map_err(|e| CryptoError::BundleFormat(format!("Invalid secret key UTF-8: {}", e)))?;

        Ok(Identity::from_armored_secret_key(&secret_key_str)?)
    }

    // Removed: export_unencrypted() - use export() instead (all exports are unprotected)
    // Removed: export_encrypted() - gckey files are no longer password-protected
    // Removed: is_encrypted() - v3.0+ files are never encrypted
}

/// Parse gckey content, supporting both v2.0 (legacy) and v3.0 formats
fn parse_gckey_content(content: &str) -> Result<IdentityBundle> {
    // First, try to parse as a raw JSON object to check the version/structure
    let json_value: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| CryptoError::BundleFormat(format!("Invalid JSON: {}", e)))?;

    // Check if this is an encrypted v2.0 file (we no longer support importing these)
    if let Some(encrypted) = json_value.get("encrypted").and_then(|v| v.as_bool()) {
        if encrypted {
            return Err(CryptoError::BundleFormat(
                "Password-protected gckey files are no longer supported. \
                 Please re-export your identity using the latest version.".to_string()
            ));
        }
    }

    // Try v3.0 format first (data is an object)
    if let Some(data) = json_value.get("data") {
        if data.is_object() {
            let gckey_file: GckeyFile = serde_json::from_str(content)
                .map_err(|e| CryptoError::BundleFormat(format!("Invalid v3.0 format: {}", e)))?;
            return Ok(gckey_file.data);
        }
    }

    // Try v2.0 format (data is a JSON string containing the bundle)
    if let Some(data) = json_value.get("data").and_then(|v| v.as_str()) {
        let bundle: IdentityBundle = serde_json::from_str(data)
            .map_err(|e| CryptoError::BundleFormat(format!("Invalid v2.0 bundle: {}", e)))?;
        return Ok(bundle);
    }

    Err(CryptoError::BundleFormat(
        "Unrecognized gckey format. Expected v2.0 or v3.0 format.".to_string()
    ))
}

/// Wrap content in .gckey file format
fn wrap_gckey_format(content: &str) -> String {
    format!(
        "{}\n{}\n{}",
        GCKEY_HEADER_BEGIN,
        content,
        GCKEY_HEADER_END
    )
}

/// Unwrap .gckey file format and extract content
fn unwrap_gckey_format(gckey_content: &str) -> Result<String> {
    let trimmed = gckey_content.trim();

    if !trimmed.starts_with(GCKEY_HEADER_BEGIN) {
        return Err(CryptoError::BundleFormat(format!(
            "Invalid file format. Expected header: {}",
            GCKEY_HEADER_BEGIN
        )));
    }

    let end_pos = trimmed.find(GCKEY_HEADER_END)
        .ok_or_else(|| CryptoError::BundleFormat(format!(
            "Missing end marker: {}",
            GCKEY_HEADER_END
        )))?;

    let content = trimmed[GCKEY_HEADER_BEGIN.len()..end_pos].trim();
    Ok(content.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_identity() -> Identity {
        Identity::generate("test@example.com").unwrap()
    }

    #[test]
    fn test_export_import_roundtrip() {
        let identity = create_test_identity();
        let original_fp = identity.fingerprint();

        // Export
        let gckey = IdentityBundle::export(&identity).unwrap();
        assert!(gckey.contains(GCKEY_HEADER_BEGIN));
        assert!(gckey.contains(GCKEY_HEADER_END));
        assert!(gckey.contains("\"version\": \"3.0\""));
        assert!(gckey.contains("\"encrypted\": false"));

        // Import
        let imported = IdentityBundle::import(&gckey).unwrap();
        assert_eq!(imported.fingerprint(), original_fp);
    }

    #[test]
    fn test_v2_unencrypted_format_compatibility() {
        // Create a v2.0 style unencrypted file (data is a JSON string)
        let identity = create_test_identity();
        let bundle = IdentityBundle::from_identity(&identity).unwrap();
        let bundle_json = serde_json::to_string_pretty(&bundle).unwrap();

        let v2_content = format!(
            r#"{{
  "version": "2.0",
  "encrypted": false,
  "salt": null,
  "nonce": null,
  "data": {}
}}"#,
            serde_json::to_string(&bundle_json).unwrap()
        );

        let wrapped = wrap_gckey_format(&v2_content);
        let imported = IdentityBundle::import(&wrapped).unwrap();
        assert_eq!(imported.fingerprint(), identity.fingerprint());
    }

    #[test]
    fn test_reject_encrypted_v2_files() {
        // A v2.0 encrypted file should be rejected
        let v2_encrypted = r#"{
  "version": "2.0",
  "encrypted": true,
  "salt": "abc123",
  "nonce": "def456",
  "data": "encrypted_garbage"
}"#;

        let wrapped = wrap_gckey_format(v2_encrypted);
        let result = IdentityBundle::import(&wrapped);

        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("no longer supported"));
    }

    #[test]
    fn test_gckey_format_wrapping() {
        let content = r#"{"test": "data"}"#;
        let wrapped = wrap_gckey_format(content);

        assert!(wrapped.starts_with(GCKEY_HEADER_BEGIN));
        assert!(wrapped.ends_with(GCKEY_HEADER_END));

        let unwrapped = unwrap_gckey_format(&wrapped).unwrap();
        assert_eq!(unwrapped, content);
    }

    #[test]
    fn test_invalid_gckey_format() {
        let result = unwrap_gckey_format("invalid content");
        assert!(matches!(result, Err(CryptoError::BundleFormat(_))));
    }

    #[test]
    fn test_bundle_contains_expected_fields() {
        let identity = create_test_identity();
        let gckey = IdentityBundle::export(&identity).unwrap();

        // Verify the exported file contains expected structure
        assert!(gckey.contains("\"user_id\""));
        assert!(gckey.contains("\"fingerprint\""));
        assert!(gckey.contains("\"secret_key\""));
        assert!(gckey.contains("\"public_key\""));
        assert!(gckey.contains("\"created_at\""));
    }
}
