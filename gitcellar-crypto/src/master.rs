//! Master key derivation and materialization for Multi-Device Recovery (ADR-019).
//!
//! The master keypair is the root of the device-certificate chain of trust.
//! It is **deterministically derived** from the user's 24-word BIP39 recovery
//! phrase via a domain-separated HKDF-SHA256 expansion (per MDR-001) and is
//! **never persisted** on any device (per DEC-MDR-08). The master private key
//! is materialized in memory only at:
//!
//! 1. First-onboarding ceremony (signs the user's first device certificate), or
//! 2. Recover-from-phrase ceremony (signs a new device cert after the user
//!    re-enters the phrase on a fresh device).
//!
//! In both cases the private key is wrapped in [`MaterializedMaster`], a
//! `ZeroizeOnDrop` carrier whose backing buffer is overwritten with zeros
//! when the value drops. The master public key is published per-user in the
//! Cloud API; the master private key never leaves the device that derived it.
//!
//! See the Multi-Device Recovery specification § 2 (Trust Model).

use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Errors that can occur during master-key derivation or signing.
#[derive(Debug, Error)]
pub enum MasterKeyError {
    #[error("invalid recovery phrase: {0}")]
    InvalidPhrase(String),

    #[error("HKDF expansion failed: {0}")]
    Hkdf(String),

    #[error("invalid master public key: {0}")]
    InvalidPublicKey(String),

    #[error("signature verification failed")]
    SignatureFailed,
}

/// Algorithm identity for the master-key derivation scheme.
///
/// This is a zero-sized anchor that exposes the canonical derivation
/// constants. Bumping [`Self::VERSION`] requires a corresponding bump
/// to [`Self::DERIVATION_INFO`] so older and newer derivations cannot
/// collide; legacy keys remain derivable from the phrase as long as the
/// older `(VERSION, DERIVATION_INFO)` pair is preserved in code.
pub struct MasterKeyDerivation;

impl MasterKeyDerivation {
    /// HKDF `info` parameter for domain separation. Bumping this rotates
    /// every existing master keypair — only do this in a planned migration.
    pub const DERIVATION_INFO: &'static [u8] = b"gitcellar-master-v1";

    /// Schema version of the derivation. Stored in device certificates
    /// (`cert_version` field) so a v2 client can recognize a v1 cert.
    pub const VERSION: u32 = 1;
}

/// Materialized master private key, held in zeroizing memory.
///
/// **Do not** persist instances of this type. Construct via
/// [`Self::from_phrase`] only at the moments listed in the module docs;
/// drop as soon as the necessary signature(s) are produced. The backing
/// buffer is zeroed via `zeroize::Zeroizing` on drop, and the inner
/// `SigningKey` used during signing is itself `ZeroizeOnDrop` (provided
/// by `ed25519-dalek` 2.x).
///
/// `MaterializedMaster` deliberately does **not** implement `Debug`,
/// `Display`, `Clone`, or `Copy`. The compile-time assertion below will
/// fail to compile if any of those traits are added by accident.
pub struct MaterializedMaster {
    /// Long-lived storage for the 32-byte Ed25519 secret. Wrapped in
    /// `Zeroizing` so the buffer is overwritten on drop. We intentionally
    /// store the raw bytes (rather than a `SigningKey`) so the canonical
    /// copy is wiped even if `ed25519-dalek`'s internal layout changes.
    secret_bytes: Zeroizing<[u8; 32]>,

    /// 32-byte Ed25519 public key. Not secret — caching for cheap access
    /// and to avoid re-deriving it from `secret_bytes` on every call.
    public_key: [u8; 32],
}

// Compile-time guard: any future PR that derives `Debug`/`Display`/`Clone`/
// `Copy` on `MaterializedMaster` will fail to build. Asserted at compile time.
static_assertions::assert_not_impl_any!(
    MaterializedMaster: std::fmt::Debug,
    std::fmt::Display,
    Clone,
    Copy
);

impl MaterializedMaster {
    /// Derive the master keypair from a 24-word BIP39 recovery phrase.
    ///
    /// The derivation is fully deterministic: same phrase → same master
    /// keypair, on every device, every time. The derivation flow is:
    ///
    /// 1. Parse + validate the phrase as a 24-word BIP39 mnemonic.
    /// 2. Run BIP39 PBKDF2-HMAC-SHA512 with empty passphrase → 64-byte seed.
    /// 3. HKDF-SHA256 expand the seed with `info = b"gitcellar-master-v1"`
    ///    to produce 32 bytes of master secret material.
    /// 4. Treat those 32 bytes as an Ed25519 secret-key seed.
    ///
    /// All transient buffers (the BIP39 seed) are zeroized before this
    /// function returns.
    ///
    /// # Errors
    ///
    /// Returns [`MasterKeyError::InvalidPhrase`] if the phrase is not a
    /// valid BIP39 mnemonic (wrong word count, invalid checksum, unknown
    /// word, etc.).
    pub fn from_phrase(phrase: &str) -> Result<Self, MasterKeyError> {
        let normalized = normalize_phrase(phrase);
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &normalized)
            .map_err(|e| MasterKeyError::InvalidPhrase(e.to_string()))?;

        // Wrap the 64-byte BIP39 seed in `Zeroizing` so we wipe it on
        // function exit — it's an intermediate, not part of the long-lived
        // master secret.
        let seed: Zeroizing<[u8; 64]> = Zeroizing::new(mnemonic.to_seed(""));

        let mut secret_bytes = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(None, seed.as_ref())
            .expand(MasterKeyDerivation::DERIVATION_INFO, secret_bytes.as_mut())
            .map_err(|e| MasterKeyError::Hkdf(e.to_string()))?;

        // Derive the public key once. The transient SigningKey is itself
        // ZeroizeOnDrop in ed25519-dalek 2.x, so any internal scratch space
        // it allocates is wiped when we drop the local at end-of-scope.
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let public_key = signing_key.verifying_key().to_bytes();
        drop(signing_key);

        Ok(Self {
            secret_bytes,
            public_key,
        })
    }

    /// Construct a [`MaterializedMaster`] from raw 32 bytes of Ed25519
    /// secret-key material, bypassing phrase derivation.
    ///
    /// This is the migration path for DEC-MDR-04 Option D (single-key
    /// dual-role): existing onboarded users hold an Ed25519 keypair that
    /// today serves as their identity. After multi-device-recovery ships,
    /// that same keypair plays both master and device roles. The migration
    /// extracts the raw 32-byte secret from the legacy Sequoia OpenPGP
    /// cert and feeds it here — no phrase entry required.
    ///
    /// **Do not use this constructor for any other purpose.** New master
    /// keys MUST come from [`Self::from_phrase`] so the phrase remains the
    /// canonical bootstrap. This entrypoint exists exclusively for the
    /// one-time first-launch migration of pre-feature accounts.
    ///
    /// The supplied buffer is **wiped in place before this function returns** —
    /// the seed is copied into the `Zeroizing<[u8; 32]>` carrier (wiped on drop)
    /// and the caller's buffer is zeroized. Callers therefore need no cleanup of
    /// their own, and must not keep a separate copy.
    ///
    /// F-6 (hardening review, Aug 2026): this used to take the array **by value** and
    /// do `Zeroizing::new(secret_bytes)`. `[u8; 32]` is `Copy`, so that moved a
    /// *copy* into the carrier and zeroized only the copy — the parameter and the
    /// caller's original were both left live. Three copies of the Ed25519 master
    /// seed existed and two were never wiped, so the seed lingered in freed
    /// stack/heap recoverable from a crash dump, core file, hibernation image, or
    /// a swapped page. Taking `&mut` is what makes the wipe reach the real value
    /// (and makes it observable, hence testable).
    pub fn from_secret_bytes(secret_bytes: &mut [u8; 32]) -> Result<Self, MasterKeyError> {
        let mut zeroizing = Zeroizing::new([0u8; 32]);
        zeroizing.copy_from_slice(secret_bytes);
        // Wipe the caller's buffer itself — see the note above.
        secret_bytes.zeroize();

        let signing_key = SigningKey::from_bytes(&zeroizing);
        let public_key = signing_key.verifying_key().to_bytes();
        drop(signing_key);

        Ok(Self {
            secret_bytes: zeroizing,
            public_key,
        })
    }

    /// Sign `msg` with the master private key, returning a 64-byte
    /// Ed25519 signature.
    ///
    /// Reconstructs an ephemeral [`SigningKey`] from the stored secret
    /// bytes for the duration of the call. The transient `SigningKey`
    /// is dropped (and zeroized via dalek's own `ZeroizeOnDrop` derive)
    /// before this function returns.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let signing_key = SigningKey::from_bytes(&self.secret_bytes);
        let sig = signing_key.sign(msg);
        sig.to_bytes()
    }

    /// 32-byte Ed25519 public key for this master.
    ///
    /// Safe to publish, store, and compare. This is what the Cloud API
    /// records per-user as `master_pubkey`.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

/// Verify a 64-byte Ed25519 signature `sig` over `msg` against the
/// supplied 32-byte master public key.
///
/// Uses `verify_strict` to reject malleable signatures (matches the
/// posture used elsewhere in the GitCellar crypto stack).
pub fn verify_with_pubkey(
    pubkey: &[u8; 32],
    msg: &[u8],
    sig: &[u8; 64],
) -> Result<(), MasterKeyError> {
    let verifying_key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| MasterKeyError::InvalidPublicKey(e.to_string()))?;
    let signature = Signature::from_bytes(sig);
    verifying_key
        .verify_strict(msg, &signature)
        .map_err(|_| MasterKeyError::SignatureFailed)
}

/// Verify using `&VerifyingKey` directly — convenience for callers that
/// already parsed the pubkey (e.g. the cert-verify path that re-uses the
/// verifying key for multiple checks).
pub(crate) fn verify_with_verifying_key(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    sig: &[u8; 64],
) -> Result<(), MasterKeyError> {
    let signature = Signature::from_bytes(sig);
    verifying_key
        .verify_strict(msg, &signature)
        .map_err(|_| MasterKeyError::SignatureFailed)
}

/// Plain Ed25519 verification using the stdlib `Verifier` trait.
/// Currently unused at module scope but documented for completeness.
#[allow(dead_code)]
pub(crate) fn verify_loose(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    sig: &[u8; 64],
) -> Result<(), MasterKeyError> {
    let signature = Signature::from_bytes(sig);
    verifying_key
        .verify(msg, &signature)
        .map_err(|_| MasterKeyError::SignatureFailed)
}

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

    const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn derivation_is_deterministic() {
        let m1 = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
        let m2 = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
        assert_eq!(m1.public_key(), m2.public_key());
    }

    #[test]
    fn different_phrases_yield_different_keys() {
        // Another known-valid 24-word mnemonic with a different last word.
        let other = "legal winner thank year wave sausage worth useful legal winner thank \
                     year wave sausage worth useful legal winner thank year wave sausage \
                     worth title";
        let m1 = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
        let m2 = MaterializedMaster::from_phrase(other).unwrap();
        assert_ne!(m1.public_key(), m2.public_key());
    }

    #[test]
    fn rejects_invalid_phrase() {
        let result = MaterializedMaster::from_phrase("not a valid phrase at all");
        assert!(matches!(result, Err(MasterKeyError::InvalidPhrase(_))));
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
        let msg = b"some message to sign";
        let sig = master.sign(msg);
        verify_with_pubkey(&master.public_key(), msg, &sig).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
        let sig = master.sign(b"original message");
        let result = verify_with_pubkey(&master.public_key(), b"different message", &sig);
        assert!(matches!(result, Err(MasterKeyError::SignatureFailed)));
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
        let other = "legal winner thank year wave sausage worth useful legal winner thank \
                     year wave sausage worth useful legal winner thank year wave sausage \
                     worth title";
        let other_master = MaterializedMaster::from_phrase(other).unwrap();
        let msg = b"hello";
        let sig = master.sign(msg);
        let result = verify_with_pubkey(&other_master.public_key(), msg, &sig);
        assert!(matches!(result, Err(MasterKeyError::SignatureFailed)));
    }

    #[test]
    fn normalize_phrase_lowercases_and_collapses() {
        assert_eq!(normalize_phrase("  ABANDON   Ability  ABLE "), "abandon ability able");
    }

    #[test]
    fn from_secret_bytes_roundtrips_with_from_phrase() {
        // The migration path (`from_secret_bytes`) and the canonical
        // bootstrap (`from_phrase`) MUST agree on the public key for the
        // same underlying 32-byte secret. This pins the contract that
        // DEC-MDR-04 Option D depends on: a migrated user's master pubkey
        // is determined solely by the existing keypair's secret bytes,
        // not by which constructor produced the `MaterializedMaster`.
        let from_phrase = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
        let mut secret_copy: [u8; 32] = *from_phrase.secret_bytes;
        let from_bytes = MaterializedMaster::from_secret_bytes(&mut secret_copy).unwrap();
        assert_eq!(from_phrase.public_key(), from_bytes.public_key());

        let msg = b"single-key dual-role migration sanity";
        let sig_a = from_phrase.sign(msg);
        let sig_b = from_bytes.sign(msg);
        // Ed25519 signatures of the same message under the same key are
        // deterministic — both constructors should produce the same sig.
        assert_eq!(sig_a, sig_b);
    }

    #[test]
    fn from_secret_bytes_signs_verifies_loop() {
        // The migration's downstream step is to call `cert::sign_with_master`
        // which calls `master.sign(...)`. Pin that the `from_secret_bytes`
        // path produces signatures verifiable against `master.public_key()`.
        let mut secret = [0xABu8; 32];
        let master = MaterializedMaster::from_secret_bytes(&mut secret).unwrap();
        let msg = b"hello migration";
        let sig = master.sign(msg);
        verify_with_pubkey(&master.public_key(), msg, &sig).unwrap();
    }

    #[test]
    fn from_secret_bytes_wipes_the_callers_buffer() {
        // F-6 (hardening review, Aug 2026). The constructor used to take the seed by
        // value and zeroize a `Copy` of it (`[u8; 32]` is `Copy`), so the real
        // seed survived in the caller's buffer — the module's stated premise
        // ("the backing buffer is overwritten with zeros") was only partly
        // delivered. The wipe now reaches the caller's buffer, which is what
        // makes it checkable at all.
        let mut secret = [0x5Au8; 32];
        let master = MaterializedMaster::from_secret_bytes(&mut secret).unwrap();

        assert_eq!(
            secret, [0u8; 32],
            "F-6: the caller's seed buffer must be zeroized in place, not copied and abandoned"
        );

        // The master must still be usable — a wipe that also broke the key would
        // pass the assertion above for the wrong reason.
        let msg = b"seed wiped, key still live";
        verify_with_pubkey(&master.public_key(), msg, &master.sign(msg)).unwrap();
    }

    #[test]
    fn derivation_info_pinned() {
        // If anyone ever changes DERIVATION_INFO, every existing user's
        // master keypair becomes unrecoverable. This test pins the value;
        // breaking it in a future PR forces the author to confront the
        // migration question.
        assert_eq!(MasterKeyDerivation::DERIVATION_INFO, b"gitcellar-master-v1");
        assert_eq!(MasterKeyDerivation::VERSION, 1);
    }
}
