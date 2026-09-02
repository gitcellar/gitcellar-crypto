//! Device certificates (Contract C-1) for Multi-Device Recovery.
//!
//! A [`DeviceCertificate`] binds a device's Ed25519 public key to a user's
//! published master public key, an enrollment timestamp, a user-supplied
//! label, a platform string, and the public key of whichever party signed
//! the cert (master or another non-revoked device — see DEC-MDR-06/07).
//! The on-the-wire form is **canonical CBOR** of the
//! [`DeviceCertificatePayload`] followed by a 64-byte Ed25519 signature.
//! Canonical encoding means: every signer/verifier pair on the network
//! agrees byte-for-byte on what the signature covers, regardless of map
//! iteration order or numeric encoding choices.
//!
//! See the Multi-Device Recovery specification § 4 (Data Model — Certificate
//! Formats) and `tests/device_cert.rs` for the property tests that pin the
//! cross-signing accept/reject behavior.

use ciborium::{de, ser};
use ed25519_dalek::{Signer, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::master::{verify_with_verifying_key, MasterKeyDerivation, MasterKeyError, MaterializedMaster};

/// Maximum length of the user-supplied `label` field, in bytes (UTF-8).
/// Enforced at construction; certs with longer labels are rejected.
pub const MAX_LABEL_BYTES: usize = 64;

/// Discriminator naming who signed a device certificate.
///
/// Serialized as the canonical-CBOR strings `"master"` and `"device"` —
/// see the Multi-Device Recovery specification § 4. The string representation is
/// part of the on-the-wire contract; renaming the variants is a breaking
/// change for every issued certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignerRole {
    Master,
    Device,
}

/// Errors raised while building or verifying a [`DeviceCertificate`].
#[derive(Debug, Error)]
pub enum CertError {
    #[error("label exceeds maximum {MAX_LABEL_BYTES} bytes (got {0})")]
    LabelTooLong(usize),

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

/// Plain-data payload signed by a device certificate.
///
/// Wire format (canonical CBOR, struct field order is fixed by this
/// declaration — see `tests/device_cert.rs::canonical_encoding_is_stable`
/// for the determinism guard):
///
/// ```text
/// {
///   cert_version       : u32 (currently 1)
///   device_pubkey      : 32 bytes
///   master_pubkey      : 32 bytes
///   label              : UTF-8 string, ≤ 64 bytes
///   platform           : "windows" | "macos" | "linux" (free-form string)
///   enrolled_at        : i64 epoch seconds
///   signer_role        : "master" | "device"
///   signer_pubkey      : 32 bytes
/// }
/// ```
///
/// Note: `enrolled_at` is `i64` epoch seconds rather than the RFC 3339
/// string mentioned prosaically in the canonical-spec § 4 — RFC 3339 has
/// multiple equivalent representations of the same moment which break
/// canonical-CBOR determinism. The specification prose is reconciled to
/// this on-the-wire choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificatePayload {
    pub cert_version: u32,
    #[serde(with = "serde_byte_array_32")]
    pub device_pubkey: [u8; 32],
    #[serde(with = "serde_byte_array_32")]
    pub master_pubkey: [u8; 32],
    pub label: String,
    pub platform: String,
    pub enrolled_at: i64,
    pub signer_role: SignerRole,
    #[serde(with = "serde_byte_array_32")]
    pub signer_pubkey: [u8; 32],
}

/// Signed device certificate — payload + 64-byte Ed25519 signature.
///
/// Round-trip through CBOR via [`Self::to_cbor`] / [`Self::from_cbor`]:
/// the storage path is `desktop_instances.device_certificate BYTEA` in
/// the Cloud API schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificate {
    pub payload: DeviceCertificatePayload,
    #[serde(with = "serde_byte_array_64")]
    pub signature: [u8; 64],
}

impl DeviceCertificate {
    /// Build + sign a device cert with the master private key.
    ///
    /// Use this for the very first device-enrollment ceremony in a user's
    /// account, or whenever the user re-enters the phrase to sign a fresh
    /// device cert (recover-from-phrase). The cert's `master_pubkey` and
    /// `signer_pubkey` will both equal the master pubkey, with
    /// `signer_role = Master`.
    pub fn sign_with_master(
        master: &MaterializedMaster,
        device_pubkey: [u8; 32],
        label: String,
        platform: String,
        enrolled_at: i64,
    ) -> Result<Self, CertError> {
        validate_label(&label)?;
        let master_pubkey = master.public_key();
        let payload = DeviceCertificatePayload {
            cert_version: MasterKeyDerivation::VERSION,
            device_pubkey,
            master_pubkey,
            label,
            platform,
            enrolled_at,
            signer_role: SignerRole::Master,
            signer_pubkey: master_pubkey,
        };
        let signed_bytes = encode_payload(&payload)?;
        let signature = master.sign(&signed_bytes);
        Ok(Self { payload, signature })
    }

    /// Build + sign a device cert with an existing device's private key
    /// (the cross-signing path per DEC-MDR-07).
    ///
    /// `signer_pubkey` MUST match the public key of `signer_signing_key`;
    /// no check is made here — passing a mismatch produces a cert that
    /// will fail verification.
    pub fn sign_with_device(
        signer_secret: &ed25519_dalek::SigningKey,
        master_pubkey: [u8; 32],
        device_pubkey: [u8; 32],
        label: String,
        platform: String,
        enrolled_at: i64,
    ) -> Result<Self, CertError> {
        validate_label(&label)?;
        let signer_pubkey = signer_secret.verifying_key().to_bytes();
        let payload = DeviceCertificatePayload {
            cert_version: MasterKeyDerivation::VERSION,
            device_pubkey,
            master_pubkey,
            label,
            platform,
            enrolled_at,
            signer_role: SignerRole::Device,
            signer_pubkey,
        };
        let signed_bytes = encode_payload(&payload)?;
        let signature = signer_secret.sign(&signed_bytes).to_bytes();
        Ok(Self { payload, signature })
    }

    /// Encode the entire signed cert to canonical CBOR for storage or wire.
    pub fn to_cbor(&self) -> Result<Vec<u8>, CertError> {
        let mut buf = Vec::new();
        ser::into_writer(self, &mut buf).map_err(|e| CertError::Serialization(e.to_string()))?;
        Ok(buf)
    }

    /// Decode a cert from CBOR bytes (e.g. the `device_certificate` BYTEA
    /// column). Does **not** verify the signature — call
    /// [`Self::verify`] for that.
    pub fn from_cbor(bytes: &[u8]) -> Result<Self, CertError> {
        de::from_reader(bytes).map_err(|e| CertError::Deserialization(e.to_string()))
    }

    /// Encode just the signed payload (the CBOR bytes that the signature
    /// is computed over). Used by both the signing path and the verify
    /// path; exposed for tests that want to mutate one byte at a time.
    pub fn signed_payload_bytes(&self) -> Result<Vec<u8>, CertError> {
        encode_payload(&self.payload)
    }

    /// Verify the cert against the user's published master pubkey and
    /// (for cross-signed certs) the set of currently non-revoked device
    /// pubkeys.
    ///
    /// Verification rules (per MDR-035 + DEC-MDR-06/07):
    ///
    /// 1. The cert's `master_pubkey` field MUST match `master_pubkey`.
    ///    Catches one-cert-pretending-to-be-from-another-user.
    /// 2. The cert's `signer_pubkey` MUST match its `signer_role`:
    ///    - `Master` → signer_pubkey MUST equal `master_pubkey`.
    ///    - `Device` → signer_pubkey MUST appear in
    ///      `eligible_device_pubkeys`. A revoked device is *not* in this
    ///      list, so its outstanding signatures stop validating
    ///      immediately upon revocation.
    /// 3. `cert_version` MUST equal [`MasterKeyDerivation::VERSION`].
    /// 4. The Ed25519 signature MUST validate against the canonical CBOR
    ///    of the payload using the signer's pubkey (`verify_strict`,
    ///    rejecting malleable encodings).
    pub fn verify(
        &self,
        master_pubkey: &[u8; 32],
        eligible_device_pubkeys: &[[u8; 32]],
    ) -> Result<(), CertError> {
        if self.payload.cert_version != MasterKeyDerivation::VERSION {
            return Err(CertError::UnsupportedVersion {
                expected: MasterKeyDerivation::VERSION,
                got: self.payload.cert_version,
            });
        }
        if &self.payload.master_pubkey != master_pubkey {
            return Err(CertError::MasterMismatch);
        }
        validate_label(&self.payload.label)?;

        match self.payload.signer_role {
            SignerRole::Master => {
                if self.payload.signer_pubkey != *master_pubkey {
                    return Err(CertError::SignerRoleMismatch);
                }
            }
            SignerRole::Device => {
                if !eligible_device_pubkeys
                    .iter()
                    .any(|pk| pk == &self.payload.signer_pubkey)
                {
                    return Err(CertError::UnknownSigner);
                }
                if self.payload.signer_pubkey == *master_pubkey {
                    // signer_role=Device with master_pubkey as signer is
                    // a contradiction — reject explicitly rather than
                    // accepting it via the eligible-set check.
                    return Err(CertError::SignerRoleMismatch);
                }
            }
        }

        let verifying_key = VerifyingKey::from_bytes(&self.payload.signer_pubkey)
            .map_err(|e| CertError::InvalidPublicKey(e.to_string()))?;
        let signed_bytes = encode_payload(&self.payload)?;
        verify_with_verifying_key(&verifying_key, &signed_bytes, &self.signature)
            .map_err(|_| CertError::SignatureFailed)
    }
}

fn validate_label(label: &str) -> Result<(), CertError> {
    let n = label.as_bytes().len();
    if n > MAX_LABEL_BYTES {
        return Err(CertError::LabelTooLong(n));
    }
    Ok(())
}

fn encode_payload(payload: &DeviceCertificatePayload) -> Result<Vec<u8>, CertError> {
    let mut buf = Vec::new();
    ser::into_writer(payload, &mut buf).map_err(|e| CertError::Serialization(e.to_string()))?;
    Ok(buf)
}

/// `serde` adapter that serializes `[u8; 32]` as a CBOR byte string
/// (major type 2) rather than as a CBOR array of 32 small integers
/// (major type 4). Byte strings are 33–34 bytes on the wire vs. ~64 for
/// the array form, and they round-trip cleanly through `Vec<u8>`-typed
/// `BYTEA` storage.
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

/// 64-byte sibling of [`serde_byte_array_32`] for the trailing signature.
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
