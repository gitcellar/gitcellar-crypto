//! Machine ID derivation and validation
//!
//! Machine IDs are derived from the public key fingerprint, providing
//! a cryptographically bound identifier for each device.
//!
//! # Format
//!
//! Machine ID format: `{prefix}-{full-fingerprint-hex}`
//! - `prefix` is configured per-application (e.g., "gcm" for GitCellar)
//! - the hex is the device key's **whole** fingerprint, lowercased
//!
//! This makes the machine_id verifiable against the public key.
//!
//! # L-3 — why the whole fingerprint (2026-07-15 pre-launch hardening)
//!
//! This previously emitted `{prefix}-{fingerprint[..16]}` — 16 hex chars, i.e.
//! **64 bits** of device identity. Two things follow from truncating an
//! identifier to 64 bits:
//!
//! - **Grindable second identity.** A machine_id is the name the system revokes,
//!   registers (`UNIQUE(machine_id)`), and denylists by. At 64 bits an attacker
//!   can grind a key whose id collides with a target's (~2^64 — costly but no
//!   longer a comfortable margin), and the *identifier* then no longer names one
//!   key. It never granted impersonation on its own (challenge signatures verify
//!   against the **stored** pubkey, not the claimed id), but it let an attacker
//!   squat a victim's registration slot and blur which device a revocation names.
//! - **Birthday floor.** Accidental collision at ~2^32 devices. Irrelevant at
//!   current scale, and exactly the kind of ceiling nobody wants to discover
//!   later — which is why this is a pre-launch fix.
//!
//! The fix is the boring one: stop truncating. The full fingerprint is already
//! the key's collision-resistant name, so the identifier now inherits whatever
//! the fingerprint offers instead of throwing 3/4 of it away.
//!
//! **Accepted widths** are 40 hex (OpenPGP v4) and 64 hex (v6, and the
//! SHA-256-over-raw-Ed25519-pubkey ids the Multi-Device-Recovery path derives —
//! see `derive_machine_id_from_ed25519_pubkey` in the cloud's `db::passkey`).
//! Both families deliberately share this one shape so machine_id consumers stay
//! agnostic to the underlying signature stack.
//!
//! **BREAKING:** every device identity changes. Every crate that derives or
//! validates a machine_id MUST move together, or the desktop and cloud sides
//! will disagree and all auth fails.

use crate::error::Result;
use crate::identity::Identity;
use crate::paths::PasskeyConfig;
use sequoia_openpgp::Cert;

/// Hex widths a well-formed machine_id fingerprint may have: 40 = OpenPGP v4
/// fingerprint, 64 = OpenPGP v6 fingerprint or a SHA-256-derived device id.
/// (L-3: 16 — the retired 64-bit truncation — is deliberately NOT accepted.)
pub const MACHINE_ID_HEX_WIDTHS: [usize; 2] = [40, 64];

/// Is `s` a full-width, all-hex device-identity string?
fn is_valid_fingerprint_hex(s: &str) -> bool {
    MACHINE_ID_HEX_WIDTHS.contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Derive machine ID from an Identity
///
/// # Arguments
/// * `config` - PasskeyConfig with the machine_id_prefix
/// * `identity` - The identity to derive the machine ID from
///
/// # Returns
/// Machine ID in format `{prefix}-{full fingerprint}` (L-3 — never truncated)
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
/// L-3: uses the fingerprint WHOLE — no truncation. See the module docs.
///
/// # Arguments
/// * `prefix` - The machine ID prefix (e.g., "gcm")
/// * `fingerprint` - The hex fingerprint (`Fingerprint::to_hex()`, unspaced)
fn derive_machine_id_from_fingerprint(prefix: &str, fingerprint: &str) -> String {
    format!("{}-{}", prefix, fingerprint.to_lowercase())
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
/// Valid format: `{prefix}-{40 or 64 hex chars}` (L-3 — a 16-hex id is the
/// retired 64-bit truncation and is rejected).
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

    is_valid_fingerprint_hex(parts[1])
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

    // Fingerprint part must be a full-width hex device identity (L-3).
    is_valid_fingerprint_hex(parts[1])
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

    /// A full-width (40-hex, v4) sample id for the tests below.
    const FULL_40: &str = "a1b2c3d4e5f60a8b112233445566778899aabbcc";
    /// A full-width (64-hex) sample id — the v6 / SHA-256 width.
    const FULL_64: &str =
        "a1b2c3d4e5f60a8b112233445566778899aabbccddeeff001122334455667788";

    #[test]
    fn test_derive_machine_id_from_identity() {
        let config = test_config();
        let identity = Identity::generate("test@example.com").unwrap();

        let machine_id = derive_machine_id_from_identity(&config, &identity);

        assert!(machine_id.starts_with("tst-"));
        // L-3: the WHOLE fingerprint, not a 16-hex truncation.
        assert!(is_valid_machine_id(&config, &machine_id), "got {machine_id}");
    }

    /// L-3 — the derived id contains the entire fingerprint, so nothing about
    /// the key's name is discarded.
    #[test]
    fn derive_keeps_the_whole_fingerprint() {
        let config = test_config();
        let identity = Identity::generate("test@example.com").unwrap();
        let fingerprint = identity.fingerprint().to_lowercase();

        let machine_id = derive_machine_id_from_identity(&config, &identity);

        assert_eq!(machine_id, format!("tst-{fingerprint}"));
        assert_eq!(extract_fingerprint(&machine_id), Some(fingerprint.as_str()));
    }

    /// L-3 NEGATIVE — the truncation-collision case. Two DIFFERENT fingerprints
    /// that share their first 16 hex chars collided into one identity under the
    /// retired derivation; under the full-width derivation they are distinct,
    /// and the retired 16-hex form is no longer accepted at all.
    #[test]
    fn truncated_fingerprints_no_longer_collide() {
        let config = test_config();
        let shared_prefix = "a1b2c3d4e5f60a8b"; // the old 64-bit identity
        let fp_a = format!("{shared_prefix}1111111111111111111111aa");
        let fp_b = format!("{shared_prefix}2222222222222222222222bb");
        assert_eq!(fp_a.len(), 40);
        assert_eq!(fp_b.len(), 40);

        let id_a = derive_machine_id_from_fingerprint("tst", &fp_a);
        let id_b = derive_machine_id_from_fingerprint("tst", &fp_b);

        // Under the retired rule both were `tst-a1b2c3d4e5f60a8b`.
        assert_ne!(id_a, id_b, "distinct keys must have distinct device identities");
        assert!(id_a.starts_with("tst-a1b2c3d4e5f60a8b"));
        assert!(id_b.starts_with("tst-a1b2c3d4e5f60a8b"));

        // ...and that retired 64-bit id is now rejected outright, so a stale
        // client cannot present one and be treated as a valid device.
        assert!(!is_valid_machine_id(&config, "tst-a1b2c3d4e5f60a8b"));
        assert!(!is_valid_machine_id_format("gcm-a1b2c3d4e5f60a8b"));
    }

    #[test]
    fn test_is_valid_machine_id() {
        let config = test_config();

        // Valid — both accepted widths
        assert!(is_valid_machine_id(&config, &format!("tst-{FULL_40}")));
        assert!(is_valid_machine_id(&config, &format!("tst-{FULL_64}")));
        assert!(is_valid_machine_id(&config, &format!("tst-{}", "0".repeat(40))));
        assert!(is_valid_machine_id(&config, &format!("tst-{}", "f".repeat(64))));

        // Wrong prefix
        assert!(!is_valid_machine_id(&config, &format!("xxx-{FULL_40}")));

        // L-3: retired 64-bit width and other wrong lengths
        assert!(!is_valid_machine_id(&config, "tst-a1b2c3d4e5f60a8b")); // 16
        assert!(!is_valid_machine_id(&config, &format!("tst-{}", "a".repeat(39))));
        assert!(!is_valid_machine_id(&config, &format!("tst-{}", "a".repeat(41))));
        assert!(!is_valid_machine_id(&config, &format!("tst-{}", "a".repeat(63))));
        assert!(!is_valid_machine_id(&config, &format!("tst-{}", "a".repeat(65))));
        assert!(!is_valid_machine_id(&config, "tst-short"));
        assert!(!is_valid_machine_id(&config, "tst-"));
        assert!(!is_valid_machine_id(&config, "tst"));

        // Invalid chars (right length, not hex)
        assert!(!is_valid_machine_id(&config, &format!("tst-{}!", "a".repeat(39))));
    }

    #[test]
    fn test_is_valid_machine_id_format() {
        // Valid formats
        assert!(is_valid_machine_id_format(&format!("gcm-{FULL_40}")));
        assert!(is_valid_machine_id_format(&format!("tst-{FULL_64}")));
        assert!(is_valid_machine_id_format(&format!("ab-{}", "0".repeat(40))));

        // Invalid formats
        assert!(!is_valid_machine_id_format(&format!("a-{FULL_40}"))); // Prefix too short
        assert!(!is_valid_machine_id_format(&format!("toolong-{FULL_40}"))); // Prefix too long
        assert!(!is_valid_machine_id_format("gcm-short")); // Fingerprint too short
        assert!(!is_valid_machine_id_format("gcm-a1b2c3d4e5f60a8b")); // L-3: retired 16-hex
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
        assert!(!verify_machine_id(&config, &public_key, &format!("tst-{FULL_40}")).unwrap());

        // L-3: presenting only the old 16-hex PREFIX of this very key's id must
        // not verify — a truncated claim is not this device.
        let truncated = format!("tst-{}", &extract_fingerprint(&machine_id).unwrap()[..16]);
        assert!(!verify_machine_id(&config, &public_key, &truncated).unwrap());
    }

    #[test]
    fn test_extract_prefix() {
        assert_eq!(extract_prefix(&format!("gcm-{FULL_40}")), Some("gcm"));
        assert_eq!(extract_prefix("invalid"), Some("invalid")); // No dash
    }

    #[test]
    fn test_extract_fingerprint() {
        assert_eq!(extract_fingerprint(&format!("gcm-{FULL_40}")), Some(FULL_40));
        assert_eq!(extract_fingerprint("invalid"), None);
    }
}
