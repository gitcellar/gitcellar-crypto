//! Revocation certificates (Contract C-2) for Multi-Device Recovery.
//!
//! A [`RevocationCertificate`] proves that a particular device's keypair
//! is no longer authorized for the user's account. The signing-authority
//! rules mirror device certificates (DEC-MDR-06): a revocation is valid
//! if signed by either (a) the user's published master pubkey
//! (re-derived from the phrase), or (b) any non-revoked device pubkey
//! belonging to that user.
//!
//! Wire format is canonical CBOR + 64-byte Ed25519 signature, identical
//! shape to [`crate::device_cert::DeviceCertificate`].
//!
//! See the Multi-Device Recovery specification § 4 and § 6 (Revocation Flow) and `tests/revocation_cert.rs` for the property
//! tests pinning the cross-signing accept/reject behavior.

use ciborium::{de, ser};
use ed25519_dalek::{Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::device_cert::SignerRole;
use crate::master::{verify_with_verifying_key, MasterKeyDerivation, MasterKeyError, MaterializedMaster};

/// Reason field in a revocation certificate (Contract C-2).
///
/// Serializes as the canonical-CBOR strings `"user_initiated"`,
/// `"compromise"`, `"device_lost"`, `"rotation"` — these strings are part
/// of the on-the-wire contract; renaming a variant breaks every
/// outstanding revocation cert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    UserInitiated,
    Compromise,
    DeviceLost,
    Rotation,
}

/// Errors raised while building or verifying a [`RevocationCertificate`].
#[derive(Debug, Error)]
pub enum RevocationCertError {
    #[error("CBOR serialization failed: {0}")]
    Serialization(String),

    #[error("CBOR deserialization failed: {0}")]
    Deserialization(String),

    #[error("master pubkey on cert does not match expected master pubkey")]
    MasterMismatch,

    #[error("signer is not in the eligible set for this user")]
    UnknownSigner,

    #[error("signer_pubkey field disagrees with declared signer_role")]
    SignerRoleMismatch,

    #[error("signature verification failed")]
    SignatureFailed,

    #[error("master signing failed: {0}")]
    MasterKey(#[from] MasterKeyError),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid certificate version: expected {expected}, got {got}")]
    UnsupportedVersion { expected: u32, got: u32 },
}

/// Plain-data payload signed by a revocation certificate.
///
/// Wire format (canonical CBOR, struct field order is fixed):
///
/// ```text
/// {
///   cert_version          : u32 (currently 1)
///   target_device_pubkey  : 32 bytes — the device being revoked
///   master_pubkey         : 32 bytes
///   revoked_at            : i64 epoch seconds
///   reason                : "user_initiated" | "compromise"
///                         | "device_lost"   | "rotation"
///   signer_role           : "master" | "device"
///   signer_pubkey         : 32 bytes
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationCertificatePayload {
    pub cert_version: u32,
    #[serde(with = "serde_byte_array_32")]
    pub target_device_pubkey: [u8; 32],
    #[serde(with = "serde_byte_array_32")]
    pub master_pubkey: [u8; 32],
    pub revoked_at: i64,
    pub reason: RevocationReason,
    pub signer_role: SignerRole,
    #[serde(with = "serde_byte_array_32")]
    pub signer_pubkey: [u8; 32],
}

/// Signed revocation certificate — payload + 64-byte Ed25519 signature.
///
/// Storage path: `desktop_instances.revocation_certificate BYTEA` in
/// the Cloud API schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationCertificate {
    pub payload: RevocationCertificatePayload,
    #[serde(with = "serde_byte_array_64")]
    pub signature: [u8; 64],
}

impl RevocationCertificate {
    /// Build + sign a revocation cert with the master private key.
    ///
    /// Used for the "user re-enters phrase to revoke a lost device"
    /// path. Cross-signing-from-a-surviving-device is the more common
    /// flow ([`Self::sign_with_device`]).
    pub fn sign_with_master(
        master: &MaterializedMaster,
        target_device_pubkey: [u8; 32],
        revoked_at: i64,
        reason: RevocationReason,
    ) -> Result<Self, RevocationCertError> {
        let master_pubkey = master.public_key();
        let payload = RevocationCertificatePayload {
            cert_version: MasterKeyDerivation::VERSION,
            target_device_pubkey,
            master_pubkey,
            revoked_at,
            reason,
            signer_role: SignerRole::Master,
            signer_pubkey: master_pubkey,
        };
        let signed_bytes = encode_payload(&payload)?;
        let signature = master.sign(&signed_bytes);
        Ok(Self { payload, signature })
    }

    /// Build + sign a revocation cert with a surviving device's private
    /// key (cross-signing per DEC-MDR-06).
    ///
    /// Per the spec, a device may revoke itself; whether the API surface
    /// exposes that is a Cloud-API decision (not the crypto layer's).
    pub fn sign_with_device(
        signer_secret: &ed25519_dalek::SigningKey,
        master_pubkey: [u8; 32],
        target_device_pubkey: [u8; 32],
        revoked_at: i64,
        reason: RevocationReason,
    ) -> Result<Self, RevocationCertError> {
        let signer_pubkey = signer_secret.verifying_key().to_bytes();
        let payload = RevocationCertificatePayload {
            cert_version: MasterKeyDerivation::VERSION,
            target_device_pubkey,
            master_pubkey,
            revoked_at,
            reason,
            signer_role: SignerRole::Device,
            signer_pubkey,
        };
        let signed_bytes = encode_payload(&payload)?;
        let signature = signer_secret.sign(&signed_bytes).to_bytes();
        Ok(Self { payload, signature })
    }

    /// Encode the entire signed cert to canonical CBOR for storage or wire.
    pub fn to_cbor(&self) -> Result<Vec<u8>, RevocationCertError> {
        let mut buf = Vec::new();
        ser::into_writer(self, &mut buf)
            .map_err(|e| RevocationCertError::Serialization(e.to_string()))?;
        Ok(buf)
    }

    /// Decode a cert from CBOR bytes; does not verify the signature.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, RevocationCertError> {
        de::from_reader(bytes).map_err(|e| RevocationCertError::Deserialization(e.to_string()))
    }

    /// Encode just the signed payload (used by tests for tamper-detection).
    pub fn signed_payload_bytes(&self) -> Result<Vec<u8>, RevocationCertError> {
        encode_payload(&self.payload)
    }

    /// Verify the cert against the user's published master pubkey and
    /// (for cross-signed certs) the set of currently non-revoked device
    /// pubkeys.
    ///
    /// Verification rules mirror [`crate::device_cert::DeviceCertificate::verify`]
    /// — a revocation by a now-revoked device is rejected because that
    /// device's pubkey is no longer in `eligible_device_pubkeys`. This
    /// is what makes "revoke after compromise" stick: even if the
    /// compromised device emits a revocation cert against a legitimate
    /// device, that revocation will not validate once the compromised
    /// device's own revocation has propagated.
    pub fn verify(
        &self,
        master_pubkey: &[u8; 32],
        eligible_device_pubkeys: &[[u8; 32]],
    ) -> Result<(), RevocationCertError> {
        if self.payload.cert_version != MasterKeyDerivation::VERSION {
            return Err(RevocationCertError::UnsupportedVersion {
                expected: MasterKeyDerivation::VERSION,
                got: self.payload.cert_version,
            });
        }
        if &self.payload.master_pubkey != master_pubkey {
            return Err(RevocationCertError::MasterMismatch);
        }

        match self.payload.signer_role {
            SignerRole::Master => {
                if self.payload.signer_pubkey != *master_pubkey {
                    return Err(RevocationCertError::SignerRoleMismatch);
                }
            }
            SignerRole::Device => {
                if !eligible_device_pubkeys
                    .iter()
                    .any(|pk| pk == &self.payload.signer_pubkey)
                {
                    return Err(RevocationCertError::UnknownSigner);
                }
                if self.payload.signer_pubkey == *master_pubkey {
                    return Err(RevocationCertError::SignerRoleMismatch);
                }
            }
        }

        let verifying_key = VerifyingKey::from_bytes(&self.payload.signer_pubkey)
            .map_err(|e| RevocationCertError::InvalidPublicKey(e.to_string()))?;
        let signed_bytes = encode_payload(&self.payload)?;
        verify_with_verifying_key(&verifying_key, &signed_bytes, &self.signature)
            .map_err(|_| RevocationCertError::SignatureFailed)
    }
}

fn encode_payload(payload: &RevocationCertificatePayload) -> Result<Vec<u8>, RevocationCertError> {
    let mut buf = Vec::new();
    ser::into_writer(payload, &mut buf)
        .map_err(|e| RevocationCertError::Serialization(e.to_string()))?;
    Ok(buf)
}

mod serde_byte_array_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let v = serde_bytes::ByteBuf::deserialize(deserializer)?;
        let arr: [u8; 32] = v
            .into_vec()
            .try_into()
            .map_err(|v: Vec<u8>| serde::de::Error::invalid_length(v.len(), &"32 bytes"))?;
        Ok(arr)
    }
}

mod serde_byte_array_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let v = serde_bytes::ByteBuf::deserialize(deserializer)?;
        let arr: [u8; 64] = v
            .into_vec()
            .try_into()
            .map_err(|v: Vec<u8>| serde::de::Error::invalid_length(v.len(), &"64 bytes"))?;
        Ok(arr)
    }
}
