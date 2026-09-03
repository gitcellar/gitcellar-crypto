//! Device-key storage abstraction (Multi-Device Recovery, DEC-MDR-14).
//!
//! Per the Multi-Device Recovery specification § 3 (DEC-MDR-14),
//! the v1 device-key store is exposed behind a [`KeystoreBackend`] trait
//! so that v2 can introduce hardware-backed implementations (YubiKey,
//! macOS Secure Enclave, TPM, etc.) without changing API or schema.
//! v1 ships with a single [`FileSystemKeystore`] implementation that
//! lives at `$APPDATA/gitcellar/users/<u>/identity/`.
//!
//! ## Storage layout
//!
//! ```text
//! identity/
//!   device.key.bin   — 32 raw bytes, Ed25519 private seed (mode 0600)
//!   device.pub.bin   — 32 raw bytes, Ed25519 public key
//!   device-cert.bin  — canonical CBOR DeviceCertificate
//!   master.pub.bin   — 32 raw bytes, master public key
//! ```
//!
//! The `.pgp` extensions used by the legacy single-key flow (see
//! `gitcellar-crypto::cloud_backup` and `gitcellar-identity`) coexist;
//! the multi-device-recovery layer uses `.bin` files to make the format
//! distinction obvious — these are raw Ed25519 keys, not Sequoia-wrapped
//! OpenPGP packets.

use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::device_cert::DeviceCertificate;

/// Filename for the device's private key (32 raw bytes).
pub const DEVICE_PRIVATE_FILENAME: &str = "device.key.bin";

/// Seal the 32-byte device seed for at-rest storage via the OS-keyring/DPAPI
/// -backed Local Protection Key (F5 / AC-F5.1 / DEC-LD-03).
///
/// Returns sealed bytes on success. If the OS keyring is unavailable (rare;
/// headless/CI without Secret-Service) the raw seed is returned with a warning,
/// preserving availability — the read path's [`open_device_seed_at_rest`]
/// transparently accepts both forms. Shared so the desktop migration path and
/// other writers seal identically.
pub fn seal_device_seed_at_rest(seed: &[u8; 32]) -> Vec<u8> {
    #[cfg(feature = "keyring")]
    {
        match gitcellar_identity::keywrap::wrap_at_rest(seed) {
            Ok(sealed) => sealed,
            Err(e) => {
                tracing::warn!(
                    "At-rest wrap unavailable for device seed ({}); writing unsealed. \
                     Key material protected by filesystem permissions only.",
                    e
                );
                seed.to_vec()
            }
        }
    }
    #[cfg(not(feature = "keyring"))]
    {
        tracing::warn!(
            "Built without the keyring feature; writing device seed unsealed. \
             Key material protected by filesystem permissions only."
        );
        seed.to_vec()
    }
}

/// Open an at-rest device-seed payload, transparently passing through a legacy
/// (pre-F5) plaintext 32-byte seed (F5 / DEC-LD-03). Shared so every reader of
/// `device.key.bin` opens the seal identically.
pub fn open_device_seed_at_rest(raw: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    if gitcellar_identity::keywrap::is_wrapped(raw) {
        #[cfg(feature = "keyring")]
        {
            gitcellar_identity::keywrap::unwrap_at_rest(raw)
                .map_err(|e| KeystoreError::InvalidKey(format!("device seed at-rest open failed: {e}")))
        }
        #[cfg(not(feature = "keyring"))]
        {
            Err(KeystoreError::InvalidKey(
                "device seed is sealed, but this build has no OS-keyring support".to_string(),
            ))
        }
    } else {
        Ok(raw.to_vec())
    }
}

/// Build an Ed25519 [`SigningKey`] from a 32-byte seed, **wiping `seed` in the
/// same breath**.
///
/// F-6 (hardening review, Aug 2026): the read path used to land the opened seed in a
/// bare `[u8; 32]`, hand a `Copy` of it to `Zeroizing::new(...)`, and then build
/// the key from the still-live original — so the "wiped" value was a copy and the
/// real seed survived unzeroized in freed stack memory (recoverable from a crash
/// dump, core file, hibernation image, or a swapped page). Routing every read
/// through this helper makes the wipe reach the real buffer, and makes it
/// observable — hence testable, which the in-place version was not.
///
/// The returned `SigningKey` is `ZeroizeOnDrop` (dalek 2.x), so the seed's only
/// remaining home is wiped when the key drops.
fn signing_key_from_seed(seed: &mut [u8]) -> Result<SigningKey, KeystoreError> {
    let arr: &mut [u8; 32] = seed
        .try_into()
        .map_err(|_| KeystoreError::InvalidKey("device private key is not 32 bytes".into()))?;
    let key = SigningKey::from_bytes(arr);
    arr.zeroize();
    Ok(key)
}

/// Filename for the device's public key (32 raw bytes).
pub const DEVICE_PUBLIC_FILENAME: &str = "device.pub.bin";

/// Filename for the signed device certificate (canonical CBOR).
pub const DEVICE_CERT_FILENAME: &str = "device-cert.bin";

/// Filename for the master public key (32 raw bytes).
pub const MASTER_PUBLIC_FILENAME: &str = "master.pub.bin";

/// Errors that can occur while interacting with a keystore backend.
#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("keystore backend not available")]
    Unavailable,

    #[error("device key not initialized — call generate_device_keypair first")]
    NotInitialized,

    #[error("device certificate not present in keystore")]
    NoCertificate,

    #[error("master public key not present in keystore")]
    NoMasterPubkey,

    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid key bytes: {0}")]
    InvalidKey(String),

    #[error("certificate (de)serialization failed: {0}")]
    Cert(String),
}

/// Abstraction over a per-user device-key storage backend.
///
/// Implementors hold (or generate) the device's Ed25519 keypair, expose
/// signing through the local-only private key, and persist the
/// associated [`DeviceCertificate`] + master public key. v1 has a single
/// implementation ([`FileSystemKeystore`]); v2 plans hardware-backed
/// implementations (DEC-MDR-14).
///
/// Methods are synchronous and not `async` — file-system / hardware
/// access is the bottleneck, not network I/O. Callers that need
/// asynchronous behavior (e.g. tokio's `spawn_blocking`) wrap as needed.
pub trait KeystoreBackend {
    /// Whether this backend is usable in the current environment
    /// (hardware present, OS API available, etc.). v1 file-system
    /// keystore returns `true` whenever its directory is writable.
    fn available(&self) -> bool;

    /// Generate a fresh Ed25519 keypair on this device, persist the
    /// private key + public key, and return the new public key bytes.
    /// If a keypair already exists, this returns it unchanged (the
    /// operation is idempotent — useful for first-launch flows).
    fn generate_device_keypair(&mut self) -> Result<[u8; 32], KeystoreError>;

    /// Sign `message` with the device's Ed25519 private key. Returns a
    /// 64-byte detached signature. Errors if the keypair has not been
    /// generated yet.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], KeystoreError>;

    /// Export the device's 32-byte Ed25519 public key.
    fn export_pubkey(&self) -> Result<[u8; 32], KeystoreError>;

    /// Read the persisted device certificate (canonical CBOR).
    /// Returns [`KeystoreError::NoCertificate`] if no cert is stored.
    fn export_cert(&self) -> Result<DeviceCertificate, KeystoreError>;

    /// Persist the supplied device certificate. Overwrites any existing
    /// cert — caller is responsible for ensuring monotonicity / version
    /// progression where that matters.
    fn import_cert(&mut self, cert: &DeviceCertificate) -> Result<(), KeystoreError>;

    /// Read the master public key associated with this device.
    /// Returns [`KeystoreError::NoMasterPubkey`] if not yet stored.
    fn export_master_pubkey(&self) -> Result<[u8; 32], KeystoreError>;

    /// Persist the master public key.
    fn import_master_pubkey(&mut self, master_pubkey: &[u8; 32]) -> Result<(), KeystoreError>;
}

/// Filesystem-backed [`KeystoreBackend`] implementation.
///
/// v1 of multi-device-recovery uses this exclusively. v2 will add
/// hardware backends behind a feature flag without changing the trait.
pub struct FileSystemKeystore {
    /// Identity directory for the user
    /// (`$APPDATA/gitcellar/users/<u>/identity/`). Created on demand.
    identity_dir: PathBuf,

    /// Cached device public key (loaded from disk lazily by callers
    /// that hit `export_pubkey` repeatedly). Optional so we can defer
    /// disk I/O until needed; `None` means "not yet loaded or generated".
    cached_pubkey: Option<[u8; 32]>,
}

impl FileSystemKeystore {
    /// Create a new keystore backend rooted at `identity_dir`.
    /// Does **not** create the directory; call
    /// [`Self::ensure_dir`] before reading or writing.
    pub fn new(identity_dir: impl Into<PathBuf>) -> Self {
        Self {
            identity_dir: identity_dir.into(),
            cached_pubkey: None,
        }
    }

    /// Ensure the identity directory exists. Idempotent.
    pub fn ensure_dir(&self) -> Result<(), KeystoreError> {
        fs::create_dir_all(&self.identity_dir)?;
        Ok(())
    }

    fn private_path(&self) -> PathBuf {
        self.identity_dir.join(DEVICE_PRIVATE_FILENAME)
    }

    fn public_path(&self) -> PathBuf {
        self.identity_dir.join(DEVICE_PUBLIC_FILENAME)
    }

    fn cert_path(&self) -> PathBuf {
        self.identity_dir.join(DEVICE_CERT_FILENAME)
    }

    fn master_pub_path(&self) -> PathBuf {
        self.identity_dir.join(MASTER_PUBLIC_FILENAME)
    }

    fn read_signing_key(&self) -> Result<SigningKey, KeystoreError> {
        let path = self.private_path();
        if !path.exists() {
            return Err(KeystoreError::NotInitialized);
        }
        // A legacy (pre-F5) file IS the plaintext seed, so the raw read buffer
        // holds key material too — carry it in `Zeroizing` rather than leaving a
        // freed `Vec` behind.
        let raw: Zeroizing<Vec<u8>> = Zeroizing::new(fs::read(&path)?);
        // F5 (AC-F5.1, DEC-LD-03): open the at-rest seal. A legacy (pre-F5)
        // plaintext 32-byte seed lacks the wrap magic and passes through
        // unchanged, so existing device keys keep working and are re-sealed on
        // the next write.
        let mut seed: Zeroizing<Vec<u8>> = Zeroizing::new(open_device_seed_at_rest(&raw)?);
        signing_key_from_seed(&mut seed)
    }

    fn write_atomic(&self, target: &Path, contents: &[u8]) -> Result<(), KeystoreError> {
        let mut tmp = target.to_path_buf();
        let tmp_name = format!(
            "{}.tmp",
            target
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("file")
        );
        tmp.set_file_name(tmp_name);
        fs::write(&tmp, contents)?;
        fs::rename(&tmp, target)?;
        // POSIX file permission tightening (0600) is best-effort; on
        // Windows the equivalent is the user-only ACL inherited from
        // `$APPDATA`. Skip on non-unix targets.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(target)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(target, perms)?;
        }
        Ok(())
    }
}

impl KeystoreBackend for FileSystemKeystore {
    fn available(&self) -> bool {
        // The directory does not have to exist yet — v1 considers the
        // backend available if the parent path is creatable. We don't
        // probe filesystem permissions here; callers that need a hard
        // up-front check can call `ensure_dir` and react to the result.
        true
    }

    fn generate_device_keypair(&mut self) -> Result<[u8; 32], KeystoreError> {
        self.ensure_dir()?;
        if self.private_path().exists() && self.public_path().exists() {
            return self.export_pubkey();
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        let pubkey = signing_key.verifying_key().to_bytes();
        let mut secret_bytes = signing_key.to_bytes();

        // F5 (AC-F5.1/F5.4, DEC-LD-03): seal the 32-byte private seed with the
        // OS-keyring/DPAPI-backed Local Protection Key before it touches disk.
        // The on-disk `device.key.bin` is no longer 32 raw plaintext bytes; an
        // infostealer reading it off disk gets AES-256-GCM ciphertext, closing
        // the Windows inherited-ACL gap. Falls back to a plaintext write +
        // warning only where no OS keyring exists (preserves availability).
        // `seal_device_seed_at_rest` falls back to returning the RAW seed when no
        // OS keyring exists, so the buffer we hand to `write_atomic` may itself be
        // key material — carry it in `Zeroizing`.
        let secret_to_write: Zeroizing<Vec<u8>> =
            Zeroizing::new(seal_device_seed_at_rest(&secret_bytes));
        self.write_atomic(&self.private_path(), &secret_to_write)?;
        self.write_atomic(&self.public_path(), &pubkey)?;
        // Drop the in-memory copies; SigningKey is ZeroizeOnDrop, and the local
        // `secret_bytes` is a stack copy.
        //
        // F-6 (hardening review, Aug 2026): this used to be
        // `Zeroizing::new(secret_bytes)`, which — `[u8; 32]` being `Copy` —
        // zeroized a COPY and left the freshly generated device seed live in
        // `secret_bytes`. Zeroize the real value instead.
        drop(signing_key);
        secret_bytes.zeroize();

        self.cached_pubkey = Some(pubkey);
        Ok(pubkey)
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], KeystoreError> {
        let signing_key = self.read_signing_key()?;
        Ok(signing_key.sign(message).to_bytes())
    }

    fn export_pubkey(&self) -> Result<[u8; 32], KeystoreError> {
        if let Some(p) = self.cached_pubkey {
            return Ok(p);
        }
        let path = self.public_path();
        if !path.exists() {
            return Err(KeystoreError::NotInitialized);
        }
        let bytes = fs::read(&path)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KeystoreError::InvalidKey("device public key is not 32 bytes".into()))?;
        // Belt-and-suspenders: confirm the bytes parse as a valid
        // Ed25519 point. A corrupt file should not silently propagate.
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| KeystoreError::InvalidKey(e.to_string()))?;
        Ok(arr)
    }

    fn export_cert(&self) -> Result<DeviceCertificate, KeystoreError> {
        let path = self.cert_path();
        if !path.exists() {
            return Err(KeystoreError::NoCertificate);
        }
        let bytes = fs::read(&path)?;
        DeviceCertificate::from_cbor(&bytes).map_err(|e| KeystoreError::Cert(e.to_string()))
    }

    fn import_cert(&mut self, cert: &DeviceCertificate) -> Result<(), KeystoreError> {
        self.ensure_dir()?;
        let bytes = cert.to_cbor().map_err(|e| KeystoreError::Cert(e.to_string()))?;
        self.write_atomic(&self.cert_path(), &bytes)
    }

    fn export_master_pubkey(&self) -> Result<[u8; 32], KeystoreError> {
        let path = self.master_pub_path();
        if !path.exists() {
            return Err(KeystoreError::NoMasterPubkey);
        }
        let bytes = fs::read(&path)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| KeystoreError::InvalidKey("master public key is not 32 bytes".into()))?;
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| KeystoreError::InvalidKey(e.to_string()))?;
        Ok(arr)
    }

    fn import_master_pubkey(&mut self, master_pubkey: &[u8; 32]) -> Result<(), KeystoreError> {
        self.ensure_dir()?;
        // Reject obviously-bad bytes early.
        VerifyingKey::from_bytes(master_pubkey)
            .map_err(|e| KeystoreError::InvalidKey(e.to_string()))?;
        self.write_atomic(&self.master_pub_path(), master_pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// F-6 (hardening review, Aug 2026) — the seed buffer the signing key is built
    /// from must be wiped in place. The pre-fix read path zeroized a `Copy` of
    /// the seed and then built the key from the still-live original, so the real
    /// device seed survived unzeroized. This is the observable half of that fix.
    #[test]
    fn signing_key_from_seed_wipes_the_seed_buffer() {
        let original = [0x11u8; 32];
        let mut seed = original.to_vec();

        let key = signing_key_from_seed(&mut seed).expect("32-byte seed is accepted");

        // Built from the seed BEFORE the wipe — otherwise the assertion below
        // would pass for the wrong reason (a wiped seed making a wrong key).
        assert_eq!(key.to_bytes(), original);
        assert_eq!(
            seed,
            vec![0u8; 32],
            "F-6: the seed buffer must be zeroized in place, not copied and abandoned"
        );
    }

    #[test]
    fn signing_key_from_seed_rejects_wrong_length() {
        let mut short = vec![0u8; 31];
        assert!(signing_key_from_seed(&mut short).is_err());
        let mut long = vec![0u8; 33];
        assert!(signing_key_from_seed(&mut long).is_err());
    }
}
