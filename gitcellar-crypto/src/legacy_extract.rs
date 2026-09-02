//! One-shot extraction of raw Ed25519 keypair bytes from a legacy
//! Sequoia OpenPGP `secret.pgp` certificate.
//!
//! Pre-feature GitCellar identities are stored as Sequoia OpenPGP
//! certs whose primary key is Ed25519 (curve `Ed25519`, algorithm
//! `EdDSA`). For DEC-MDR-04 Option D — single-key dual-role migration —
//! we need the raw 32-byte Ed25519 seed back so the same keypair can
//! play both master and device roles in the new hierarchy without
//! requiring the user to re-enter the recovery phrase.
//!
//! This module is the **only** place in the codebase that bridges the
//! Sequoia-OpenPGP and raw-Ed25519 representations. Keeping it isolated
//! protects the rest of the crypto stack from accidental cross-stack
//! coupling.
//!
//! # Why "scalar" is the seed
//!
//! Sequoia stores the Ed25519 secret key in
//! `mpi::SecretKeyMaterial::EdDSA { scalar }`. The "scalar" name is
//! historical OpenPGP nomenclature; in practice Sequoia's Ed25519
//! backend roundtrips the secret as
//! `ed25519_dalek::SigningKey::to_bytes()` (i.e., the 32-byte secret
//! seed, not the SHA-512-clamped scalar). Feeding that back through
//! `SigningKey::from_bytes` produces bit-identical signatures and the
//! same public key — verified by the cross-check in
//! [`extract_ed25519_keypair`].

use ed25519_dalek::{SigningKey, VerifyingKey};
use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;
use openpgp::crypto::mpi;
use openpgp::parse::Parse;
use openpgp::types::Curve;
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors that can occur during extraction.
#[derive(Debug, Error)]
pub enum LegacyExtractError {
    #[error("legacy Sequoia certificate could not be parsed: {0}")]
    BadCert(String),

    #[error("legacy primary key is not Ed25519: {0}")]
    NotEd25519(String),

    #[error("legacy primary key has no secret material — refusing to migrate a public-only cert")]
    NoSecretMaterial,

    #[error(
        "legacy Sequoia secret is password-encrypted; cannot migrate without phrase \
         (rotate via recover-from-phrase ceremony post-launch)"
    )]
    EncryptedSecret,

    #[error("derived public key does not match cert primary public key — refusing to migrate")]
    PubkeyMismatch,
}

/// Extracted raw Ed25519 keypair (canonical for the multi-device-recovery layer).
pub struct LegacyEd25519Keypair {
    /// 32-byte Ed25519 secret seed (suitable as `SigningKey::from_bytes`
    /// input). Stored in zeroizing memory so callers can drop it
    /// without leaking the bytes.
    pub secret_seed: Zeroizing<[u8; 32]>,

    /// 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
}

/// Parse `secret_pgp_bytes` (the contents of a legacy `secret.pgp`
/// file) and return the raw 32-byte Ed25519 seed + matching public key.
///
/// Performs a cross-check by deriving the public key from the
/// extracted seed via dalek and comparing against the cert's primary
/// public key. A mismatch indicates either a corrupt cert or an
/// algorithm-version drift in Sequoia's Ed25519 representation; either
/// way the caller MUST refuse to migrate.
pub fn extract_ed25519_keypair(
    secret_pgp_bytes: &[u8],
) -> Result<LegacyEd25519Keypair, LegacyExtractError> {
    let cert = Cert::from_bytes(secret_pgp_bytes)
        .map_err(|e| LegacyExtractError::BadCert(e.to_string()))?;

    let public_bytes = ed25519_public_from_cert(&cert)?;
    let primary = cert.primary_key().key();

    // Secret part: scalar is the 32-byte Ed25519 seed. Pad to handle
    // the unlikely case of a leading-zero stripped MPI.
    let secret_seed: Zeroizing<[u8; 32]> = match primary.optional_secret() {
        Some(openpgp::packet::key::SecretKeyMaterial::Unencrypted(unenc)) => unenc
            .map(|s| match s {
                mpi::SecretKeyMaterial::EdDSA { scalar } => {
                    let padded = scalar.value_padded(32);
                    if padded.len() != 32 {
                        return Err(LegacyExtractError::BadCert(format!(
                            "Ed25519 scalar has unexpected length {}",
                            padded.len()
                        )));
                    }
                    let mut arr = Zeroizing::new([0u8; 32]);
                    arr.copy_from_slice(&padded);
                    Ok(arr)
                }
                other => Err(LegacyExtractError::NotEd25519(format!("{:?}", other))),
            }),
        Some(openpgp::packet::key::SecretKeyMaterial::Encrypted(_)) => {
            return Err(LegacyExtractError::EncryptedSecret)
        }
        None => return Err(LegacyExtractError::NoSecretMaterial),
    }?;

    // Cross-check: dalek-derived pubkey MUST match cert pubkey.
    {
        let signing = SigningKey::from_bytes(&secret_seed);
        let derived = signing.verifying_key().to_bytes();
        if derived != public_bytes {
            return Err(LegacyExtractError::PubkeyMismatch);
        }
        // Sanity: also validate the public_bytes parse cleanly as an
        // Ed25519 point (defends against future cert tampering).
        VerifyingKey::from_bytes(&public_bytes)
            .map_err(|e| LegacyExtractError::BadCert(e.to_string()))?;
        drop(signing);
    }

    Ok(LegacyEd25519Keypair {
        secret_seed,
        public_key: public_bytes,
    })
}

/// Extract the raw 32-byte Ed25519 public key from a PGP certificate's
/// primary key (public material only — works on public-only certs).
///
/// This is the verifier-side counterpart of [`extract_ed25519_keypair`]:
/// under DEC-MDR-04 Option D the legacy PGP primary key IS the master/device
/// key, so a server holding only the registered armored public key can bind
/// a migration `DeviceCertificate`'s `device_pubkey` to the key that owns the
/// registration (Cloud API `/api/desktop/register` migration cloud-sync leg,
/// Multi-Device Recovery specification §11).
pub fn extract_ed25519_public_key(
    public_pgp_bytes: &[u8],
) -> Result<[u8; 32], LegacyExtractError> {
    let cert = Cert::from_bytes(public_pgp_bytes)
        .map_err(|e| LegacyExtractError::BadCert(e.to_string()))?;
    ed25519_public_from_cert(&cert)
}

/// Normalize stored public-certificate bytes (binary OR ASCII-armored OpenPGP)
/// to ASCII armor.
///
/// Onboarded identities store `public.pgp` in BINARY OpenPGP form, while the
/// Cloud API's register wire format is armored text. Reading the file with
/// `read_to_string` fails UTF-8 validation on the binary form — which is how
/// the migration cloud-sync silently skipped for every onboarded user (found
/// 2026-07-16 in end-to-end testing). Round-tripping through
/// Sequoia accepts either form and always emits armor.
pub fn armored_public_key(public_pgp_bytes: &[u8]) -> Result<String, LegacyExtractError> {
    use openpgp::serialize::Serialize as _;

    let cert = Cert::from_bytes(public_pgp_bytes)
        .map_err(|e| LegacyExtractError::BadCert(e.to_string()))?;
    let mut buf = Vec::new();
    cert.armored()
        .serialize(&mut buf)
        .map_err(|e| LegacyExtractError::BadCert(e.to_string()))?;
    String::from_utf8(buf).map_err(|e| LegacyExtractError::BadCert(e.to_string()))
}

/// Shared public-part extraction: q = 0x40 || raw_pubkey_32. Pad to 33 bytes
/// in case leading zeros were stripped (the 0x40 prefix prevents this in
/// practice, but `value_padded` is the safe API).
fn ed25519_public_from_cert(cert: &Cert) -> Result<[u8; 32], LegacyExtractError> {
    let primary = cert.primary_key().key();
    let public_bytes: [u8; 32] = match primary.mpis() {
        mpi::PublicKey::EdDSA { curve, q } => {
            if !matches!(curve, Curve::Ed25519) {
                return Err(LegacyExtractError::NotEd25519(format!("{:?}", curve)));
            }
            let padded = q
                .value_padded(33)
                .map_err(|e| LegacyExtractError::BadCert(e.to_string()))?;
            if padded.len() != 33 || padded[0] != 0x40 {
                return Err(LegacyExtractError::BadCert(format!(
                    "unexpected Ed25519 public-point encoding (len={}, prefix=0x{:02x})",
                    padded.len(),
                    padded.first().copied().unwrap_or(0),
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&padded[1..33]);
            arr
        }
        other => return Err(LegacyExtractError::NotEd25519(format!("{:?}", other))),
    };

    // Sanity: the bytes must parse as a valid Ed25519 point (defends
    // against tampered/corrupt certs).
    VerifyingKey::from_bytes(&public_bytes)
        .map_err(|e| LegacyExtractError::BadCert(e.to_string()))?;

    Ok(public_bytes)
}

#[cfg(test)]
mod tests {
    //! Unit tests around extraction. The end-to-end migration tests
    //! that exercise extraction against a committed pre-feature
    //! fixture live in the Desktop app's `multi_device_migration_test`.

    use super::*;
    use crate::Identity;

    #[test]
    fn extract_roundtrips_for_freshly_generated_identity() {
        // Generate a Sequoia identity (same path passkey-core takes
        // during onboarding), serialize the secret part, extract via
        // our helper, and verify the seed produces the same public
        // point dalek-side.
        use openpgp::serialize::Serialize;
        let identity = Identity::generate("alice@example.com").unwrap();
        let mut buf = Vec::new();
        identity.cert().as_tsk().serialize(&mut buf).unwrap();

        let kp = extract_ed25519_keypair(&buf).expect("extraction");
        let signing = SigningKey::from_bytes(&kp.secret_seed);
        assert_eq!(signing.verifying_key().to_bytes(), kp.public_key);
    }

    #[test]
    fn extract_rejects_garbage_bytes() {
        let result = extract_ed25519_keypair(&[0x00, 0x01, 0x02, 0x03]);
        assert!(matches!(result, Err(LegacyExtractError::BadCert(_))));
    }

    #[test]
    fn extract_public_key_works_on_public_only_cert_and_matches_keypair() {
        use openpgp::serialize::Serialize;
        let identity = Identity::generate("carol@example.com").unwrap();

        let mut secret_buf = Vec::new();
        identity.cert().as_tsk().serialize(&mut secret_buf).unwrap();
        let kp = extract_ed25519_keypair(&secret_buf).expect("keypair extraction");

        // Public-only serialization (what the Cloud API holds).
        let mut public_buf = Vec::new();
        identity.cert().serialize(&mut public_buf).unwrap();
        let public = extract_ed25519_public_key(&public_buf).expect("public extraction");

        assert_eq!(public, kp.public_key);
    }

    #[test]
    fn armored_public_key_accepts_binary_and_armored_forms() {
        use openpgp::serialize::Serialize;
        let identity = Identity::generate("dave@example.com").unwrap();

        // Binary serialization (the on-disk public.pgp form for onboarded users).
        let mut binary_buf = Vec::new();
        identity.cert().serialize(&mut binary_buf).unwrap();
        assert!(
            std::str::from_utf8(&binary_buf).is_err() || !binary_buf.starts_with(b"-----"),
            "fixture should exercise the binary form"
        );

        let armored = armored_public_key(&binary_buf).expect("binary → armor");
        assert!(armored.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));

        // Idempotent on already-armored input, and same key both ways.
        let rearmored = armored_public_key(armored.as_bytes()).expect("armor → armor");
        let a = Cert::from_bytes(armored.as_bytes()).unwrap().fingerprint();
        let b = Cert::from_bytes(rearmored.as_bytes()).unwrap().fingerprint();
        assert_eq!(a, b);
        assert_eq!(a, identity.cert().fingerprint());
    }

    #[test]
    fn extract_rejects_public_only_cert() {
        // Public-only cert (no secret material) — the primary's
        // `optional_secret()` returns None.
        use openpgp::serialize::Serialize;
        let identity = Identity::generate("bob@example.com").unwrap();
        let mut buf = Vec::new();
        identity.cert().serialize(&mut buf).unwrap();

        let result = extract_ed25519_keypair(&buf);
        assert!(matches!(result, Err(LegacyExtractError::NoSecretMaterial)));
    }
}
