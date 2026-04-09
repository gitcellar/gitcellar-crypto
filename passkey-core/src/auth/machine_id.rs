//! Machine ID derivation and validation
//!
//! Machine IDs are derived from the public key fingerprint, providing
//! a cryptographically bound identifier for each device.
//!
//! # Format
//!
//! Machine ID format: `{prefix}-{fingerprint[..16]}`
//! - `prefix` is configured per-application (e.g., "gcm" for GitCellar)
//! - The 16 hex chars are from the public key fingerprint
//!
//! This makes the machine_id verifiable against the public key.

use crate::error::Result;
use crate::identity::Identity;
use crate::paths::PasskeyConfig;
use sequoia_openpgp::Cert;

/// Derive machine ID from an Identity
///
/// # Arguments
/// * `config` - PasskeyConfig with the machine_id_prefix
/// * `identity` - The identity to derive the machine ID from
///
/// # Returns
/// Machine ID in format `{prefix}-{fingerprint[..16]}`
pub fn derive_machine_id_from_identity(config: &PasskeyConfig, identity: &Identity) -> String {
    derive_machine_id_from_fingerprint(&config.machine_id_prefix, &identity.fingerprint())
}

/// Derive machine ID from an OpenPGP certificate
///
/// # Arguments
/// * `config` - PasskeyConfig with the machine_id_prefix
/// * `cert` - The OpenPGP certificate
pub fn derive_machine_id_from_cert(config: &PasskeyConfig, cert: &Cert) -> String {
    let fingerprint = cert.fingerprint().to_hex();
    derive_machine_id_from_fingerprint(&config.machine_id_prefix, &fingerprint)
}

/// Derive machine ID from a public key (ASCII-armored)
///
/// # Arguments
/// * `config` - PasskeyConfig with the machine_id_prefix
/// * `public_key` - ASCII-armored PGP public key
pub fn derive_machine_id(config: &PasskeyConfig, public_key: &str) -> Result<String> {
    use crate::identity::parse_public_key;

    let cert = parse_public_key(public_key)?;
    Ok(derive_machine_id_from_cert(config, &cert))
}

/// Derive machine ID from a fingerprint string
///
/// # Arguments
/// * `prefix` - The machine ID prefix (e.g., "gcm")
/// * `fingerprint` - The hex fingerprint (at least 16 chars)
fn derive_machine_id_from_fingerprint(prefix: &str, fingerprint: &str) -> String {
    let short_fp = if fingerprint.len() >= 16 {
        &fingerprint[..16]
    } else {
        fingerprint
    };
    format!("{}-{}", prefix, short_fp.to_lowercase())
}

/// Verify that a claimed machine_id matches a public key's fingerprint
///
/// # Arguments
/// * `config` - PasskeyConfig with the machine_id_prefix
/// * `public_key` - ASCII-armored PGP public key
/// * `claimed_machine_id` - The machine ID to verify
///
/// # Returns
/// `Ok(true)` if the machine ID matches, `Ok(false)` otherwise
pub fn verify_machine_id(
    config: &PasskeyConfig,
    public_key: &str,
    claimed_machine_id: &str,
) -> Result<bool> {
    let expected = derive_machine_id(config, public_key)?;
    Ok(expected == claimed_machine_id)
}

/// Validate machine ID format
///
/// Valid format: `{prefix}-{16 hex chars}`
///
/// # Arguments
/// * `config` - PasskeyConfig with the machine_id_prefix
/// * `machine_id` - The machine ID to validate
pub fn is_valid_machine_id(config: &PasskeyConfig, machine_id: &str) -> bool {
    let parts: Vec<&str> = machine_id.split('-').collect();

    if parts.len() != 2 {
        return false;
    }

    if parts[0] != config.machine_id_prefix {
        return false;
    }

    if parts[1].len() != 16 || !parts[1].chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    true
}

/// Validate machine ID format with any prefix
///
/// Validates the format without checking the specific prefix.
pub fn is_valid_machine_id_format(machine_id: &str) -> bool {
    let parts: Vec<&str> = machine_id.split('-').collect();

    if parts.len() != 2 {
        return false;
    }

    // Prefix should be 2-6 alphanumeric chars
    if parts[0].len() < 2 || parts[0].len() > 6 || !parts[0].chars().all(|c| c.is_alphanumeric()) {
        return false;
    }

    // Fingerprint part should be 16 hex chars
    if parts[1].len() != 16 || !parts[1].chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    true
}

/// Extract the prefix from a machine ID
pub fn extract_prefix(machine_id: &str) -> Option<&str> {
    machine_id.split('-').next()
}

/// Extract the fingerprint portion from a machine ID
pub fn extract_fingerprint(machine_id: &str) -> Option<&str> {
    let parts: Vec<&str> = machine_id.split('-').collect();
    if parts.len() == 2 {
        Some(parts[1])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> PasskeyConfig {
        PasskeyConfig::new("test").with_machine_id_prefix("tst")
    }

    #[test]
    fn test_derive_machine_id_from_identity() {
        let config = test_config();
        let identity = Identity::generate("test@example.com").unwrap();

        let machine_id = derive_machine_id_from_identity(&config, &identity);

        assert!(machine_id.starts_with("tst-"));
        assert_eq!(machine_id.len(), 20); // "tst-" + 16 hex
    }

    #[test]
    fn test_is_valid_machine_id() {
        let config = test_config();

        // Valid
        assert!(is_valid_machine_id(&config, "tst-a1b2c3d4e5f60a8b"));
        assert!(is_valid_machine_id(&config, "tst-0000000000000000"));
        assert!(is_valid_machine_id(&config, "tst-ffffffffffffffff"));

        // Wrong prefix
        assert!(!is_valid_machine_id(&config, "xxx-a1b2c3d4e5f60a8b"));

        // Wrong length
        assert!(!is_valid_machine_id(&config, "tst-short"));
        assert!(!is_valid_machine_id(&config, "tst-"));
        assert!(!is_valid_machine_id(&config, "tst"));

        // Invalid chars
        assert!(!is_valid_machine_id(&config, "tst-notahex!1234567"));
    }

    #[test]
    fn test_is_valid_machine_id_format() {
        // Valid formats
        assert!(is_valid_machine_id_format("gcm-a1b2c3d4e5f60a8b"));
        assert!(is_valid_machine_id_format("tst-a1b2c3d4e5f60a8b"));
        assert!(is_valid_machine_id_format("ab-0000000000000000"));

        // Invalid formats
        assert!(!is_valid_machine_id_format("a-1234567890123456")); // Prefix too short
        assert!(!is_valid_machine_id_format("toolong-1234567890123456")); // Prefix too long
        assert!(!is_valid_machine_id_format("gcm-short")); // Fingerprint too short
    }

    #[test]
    fn test_verify_machine_id() {
        let config = test_config();
        let identity = Identity::generate("test@example.com").unwrap();
        let public_key = identity.export_public_key().unwrap();
        let machine_id = derive_machine_id_from_identity(&config, &identity);

        // Should verify
        assert!(verify_machine_id(&config, &public_key, &machine_id).unwrap());

        // Different ID should not verify
        assert!(!verify_machine_id(&config, &public_key, "tst-0000000000000000").unwrap());
    }

    #[test]
    fn test_extract_prefix() {
        assert_eq!(extract_prefix("gcm-a1b2c3d4e5f60a8b"), Some("gcm"));
        assert_eq!(extract_prefix("tst-0000000000000000"), Some("tst"));
        assert_eq!(extract_prefix("invalid"), Some("invalid")); // No dash
    }

    #[test]
    fn test_extract_fingerprint() {
        assert_eq!(extract_fingerprint("gcm-a1b2c3d4e5f60a8b"), Some("a1b2c3d4e5f60a8b"));
        assert_eq!(extract_fingerprint("invalid"), None);
    }
}
