//! Signature verification for passkey authentication
//!
//! Provides Ed25519 detached signature verification using Sequoia OpenPGP.

use crate::error::{PasskeyError, Result};
use crate::identity::parse_public_key;
use sequoia_openpgp as openpgp;
use openpgp::parse::Parse;
use openpgp::parse::stream::{DetachedVerifierBuilder, MessageStructure, VerificationHelper};
use openpgp::policy::StandardPolicy;
use openpgp::Cert;
use tracing::debug;

/// Verify a detached signature against data using the provided public key
///
/// # Arguments
/// * `public_key_pem` - ASCII-armored PGP public key
/// * `data` - The data that was signed
/// * `signature` - The detached signature bytes
///
/// # Returns
/// * `Ok(true)` - Signature is valid
/// * `Ok(false)` - Signature is invalid
/// * `Err(_)` - Could not parse key or signature
pub fn verify_detached_signature(
    public_key_pem: &str,
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    debug!("Verifying signature ({} bytes) against {} bytes of data", signature.len(), data.len());

    let cert = parse_public_key(public_key_pem)?;
    verify_detached_signature_with_cert(&cert, data, signature)
}

/// Verify a detached signature using an already-parsed certificate
///
/// This is more efficient when you already have the Cert object.
pub fn verify_detached_signature_with_cert(
    cert: &Cert,
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    let policy = StandardPolicy::new();

    // Create verification helper
    struct Helper {
        cert: Cert,
    }

    impl VerificationHelper for Helper {
        fn get_certs(
            &mut self,
            _ids: &[openpgp::KeyHandle],
        ) -> openpgp::Result<Vec<Cert>> {
            Ok(vec![self.cert.clone()])
        }

        fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
            use openpgp::parse::stream::MessageLayer;

            // CRITICAL (DISC-BC-09): Sequoia accepts the message iff `check`
            // returns Ok, and `verify_bytes` reflects exactly that. So we MUST
            // return Err when NO signature cryptographically verifies over the
            // data — otherwise verification succeeds even for tampered data or a
            // signature that signs *different* bytes (the auth-bypass class).
            // Returning Ok only when a signature actually verified is the whole
            // security property. (A prior version set a `self.valid` flag here
            // and returned Ok(()) unconditionally; that flag was never read, so
            // every structurally-valid signature was accepted regardless of the
            // data — fixed to match `gitcellar_crypto::broadcast::verify_detached`.)
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

    let helper = Helper {
        cert: cert.clone(),
    };

    // Build verifier and verify data
    let mut verifier = DetachedVerifierBuilder::from_bytes(signature)
        .map_err(|_| PasskeyError::InvalidSignature)?
        .with_policy(&policy, None, helper)
        .map_err(|e| {
            debug!("Failed to create verifier: {}", e);
            PasskeyError::InvalidSignature
        })?;

    match verifier.verify_bytes(data) {
        Ok(()) => {
            debug!("Signature verification successful");
            Ok(true)
        }
        Err(e) => {
            debug!("Signature verification failed: {}", e);
            Ok(false)
        }
    }
}

/// Parse a signature from base64-encoded string
pub fn parse_signature_base64(encoded: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| PasskeyError::InvalidSignature)
}

/// Parse a signature from hex-encoded string
pub fn parse_signature_hex(encoded: &str) -> Result<Vec<u8>> {
    hex::decode(encoded)
        .map_err(|_| PasskeyError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    // Note: Full signature verification tests require signing capability,
    // which would need to be added to Identity or tested via integration tests.

    #[test]
    fn test_parse_signature_base64() {
        let data = vec![1, 2, 3, 4, 5];
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);

        let decoded = parse_signature_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_parse_signature_base64_invalid() {
        let result = parse_signature_base64("not valid base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_signature_hex() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let encoded = "deadbeef";

        let decoded = parse_signature_hex(encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_parse_signature_hex_invalid() {
        let result = parse_signature_hex("not valid hex!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_with_wrong_data() {
        // This tests the error path - verification should fail with wrong data
        let identity = Identity::generate("test@example.com").unwrap();
        let public_key = identity.export_public_key().unwrap();

        // Create a fake signature (this won't be valid)
        let fake_signature = vec![0u8; 64];
        let data = b"some data";

        // This should return Ok(false) or Err, not Ok(true)
        let result = verify_detached_signature(&public_key, data, &fake_signature);
        // The signature is invalid, so this should either error or return false
        match result {
            Ok(valid) => assert!(!valid),
            Err(_) => {} // Also acceptable
        }
    }

    /// DISC-BC-09 regression guard. A genuine detached signature must verify
    /// ONLY over the exact bytes it signed: tampered data — or a signature that
    /// signs *different* bytes — must be rejected, and a signature must not
    /// verify under a different identity's public key. The pre-fix verifier
    /// accepted any structurally-valid signature over arbitrary data (an
    /// authentication-bypass class on the challenge-response path).
    #[test]
    fn real_signature_verifies_only_over_exact_bytes() {
        use sequoia_openpgp as openpgp;
        use openpgp::policy::StandardPolicy;
        use openpgp::serialize::stream::{Message, Signer};
        use std::io::Write;

        // Produce a genuine detached signature using the identity's signing key.
        // passkey-core has no public signing API, so we sign with Sequoia directly
        // via the secret-bearing cert exposed by `Identity::cert()` (mirrors the
        // proven `gitcellar_crypto::EncryptionEngine::sign_data` idiom).
        fn sign_detached(identity: &Identity, data: &[u8]) -> Vec<u8> {
            let policy = StandardPolicy::new();
            let keypair = identity
                .cert()
                .keys()
                .with_policy(&policy, None)
                .supported()
                .for_signing()
                .secret()
                .next()
                .expect("identity has a signing key")
                .key()
                .clone()
                .into_keypair()
                .expect("convert signing key into keypair");

            let mut sig = Vec::new();
            {
                let message = Message::new(&mut sig);
                let mut signer = Signer::new(message, keypair)
                    .detached()
                    .build()
                    .expect("build detached signer");
                signer.write_all(data).expect("write data to signer");
                signer.finalize().expect("finalize signature");
            }
            sig
        }

        let identity = Identity::generate("tamper-test@example.com").unwrap();
        let public_key = identity.export_public_key().unwrap();

        let data = b"challenge-nonce-abc123";
        let signature = sign_detached(&identity, data);

        // Valid: the signature verifies over the exact bytes it signed.
        assert!(
            verify_detached_signature(&public_key, data, &signature).unwrap(),
            "a genuine signature must verify over the exact signed bytes"
        );

        // Tampered data: a single-byte change must NOT verify. This is the exact
        // case the pre-fix verifier wrongly accepted (returned Ok(true)).
        let tampered = b"challenge-nonce-abc124";
        assert_ne!(&data[..], &tampered[..]);
        assert!(
            !verify_detached_signature(&public_key, tampered, &signature).unwrap(),
            "a signature over different data must be rejected (DISC-BC-09 guard)"
        );

        // Cross-key: a different identity's public key must not accept this
        // signature (rejected via Ok(false) — or an Err; never Ok(true)).
        let other = Identity::generate("other@example.com").unwrap();
        let other_public = other.export_public_key().unwrap();
        let cross = verify_detached_signature(&other_public, data, &signature);
        assert!(
            !matches!(cross, Ok(true)),
            "a signature must not verify under a different identity's public key"
        );
    }
}
