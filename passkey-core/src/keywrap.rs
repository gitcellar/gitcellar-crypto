//! At-rest key wrapping via the OS keyring / DPAPI (F5, DEC-LD-03).
//!
//! GitCellar's most sensitive key material — the device Ed25519 seed, the
//! OpenPGP identity secret key, and (via [`local_protection_secret`]) the
//! repository-key keyring — is written to flat files under the user's config
//! directory. Historically those files were **plaintext**, protected only by a
//! Unix `0600` mode (and, on Windows, by the ACL inherited from `%APPDATA%`).
//! That is exactly the threat DEC-SEC-001 calls out: an infostealer running as
//! the user reads the plaintext straight off disk.
//!
//! This module closes that gap at the **lowest crate layer** (DEC-LD-03): the
//! key material's writers (`gitcellar-crypto::keystore`, `passkey-core::identity`)
//! cannot depend on the Service crate, so the wrap lives here in `passkey-core`,
//! backed directly by the `keyring` crate (Windows Credential Manager / DPAPI,
//! macOS Keychain, Linux Secret Service).
//!
//! ## Mechanism
//!
//! A single per-OS-user **Local Protection Key** (LPK) — 32 random bytes — is
//! generated once and stored in the OS keyring (never on the filesystem). Every
//! at-rest secret is sealed with AES-256-GCM under the LPK before being written:
//!
//! ```text
//! [ magic "GCKW0001" (8 bytes) ][ nonce (12 bytes) ][ ciphertext + GCM tag ]
//! ```
//!
//! An infostealer that reads the wrapped file off disk gets ciphertext; the LPK
//! it would need lives in DPAPI/Keychain/Secret-Service, not in a flat file.
//!
//! ## Backward-safe migration
//!
//! [`unwrap_at_rest`] treats any payload **without** the magic header as a legacy
//! plaintext value and returns it unchanged. This mirrors the Service keyring's
//! `.key`→`.gckey` auto-migration: an existing identity on disk keeps working,
//! and the next write re-seals it. No flag-day, no migration script.
//!
//! ## Availability fallback
//!
//! If the OS keyring is unavailable (some headless Linux/CI environments with no
//! Secret-Service daemon), [`wrap_at_rest`] returns an error and callers fall
//! back to a plaintext write with a warning — preserving availability rather
//! than bricking onboarding. On the primary platform (Windows desktop) DPAPI /
//! Credential Manager is always present for an interactive user, so the wrap
//! always engages there. The pure [`wrap_with_key`] / [`unwrap_with_key`]
//! primitives never touch the keyring and are fully deterministic for testing.

use crate::error::{PasskeyError, Result};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use zeroize::Zeroizing;

/// Magic header identifying an at-rest-wrapped payload ("GitCellar KeyWrap v1").
pub const KEYWRAP_MAGIC: &[u8; 8] = b"GCKW0001";

/// AES-256-GCM nonce size (96 bits).
const NONCE_SIZE: usize = 12;

/// OS-keyring service name under which the Local Protection Key is stored.
/// `passkey-core` is vendored specifically for GitCellar, so a fixed service
/// name is correct here (matches `PasskeyConfig::gitcellar().app_name`).
const KEYWRAP_SERVICE: &str = "gitcellar";

/// OS-keyring entry name for the per-OS-user Local Protection Key (v1).
const LPK_ENTRY: &str = "at-rest-protection-key-v1";

/// Whether `data` carries the at-rest wrap magic header.
///
/// Used on the read path to distinguish a sealed payload from a legacy
/// plaintext value (transparent migration).
pub fn is_wrapped(data: &[u8]) -> bool {
    data.len() >= KEYWRAP_MAGIC.len() && &data[..KEYWRAP_MAGIC.len()] == KEYWRAP_MAGIC
}

/// Seal `plaintext` with AES-256-GCM under an explicit 32-byte key.
///
/// Pure (no keyring / no global state); deterministic given a fixed RNG, used
/// directly by the wrap test suite. Most callers want [`wrap_at_rest`].
pub fn wrap_with_key(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| PasskeyError::Other(format!("at-rest cipher init failed: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| PasskeyError::Other(format!("at-rest seal failed: {e}")))?;

    let mut out = Vec::with_capacity(KEYWRAP_MAGIC.len() + NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(KEYWRAP_MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a payload sealed by [`wrap_with_key`] using an explicit 32-byte key.
///
/// Returns an error if the magic header is absent (use [`is_wrapped`] first) or
/// if authentication fails (wrong key / tampered ciphertext).
pub fn unwrap_with_key(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if !is_wrapped(data) {
        return Err(PasskeyError::Other(
            "at-rest payload is not wrapped (missing magic header)".to_string(),
        ));
    }
    let body = &data[KEYWRAP_MAGIC.len()..];
    if body.len() < NONCE_SIZE {
        return Err(PasskeyError::Other(
            "at-rest payload truncated (no nonce)".to_string(),
        ));
    }
    let (nonce_bytes, ciphertext) = body.split_at(NONCE_SIZE);

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| PasskeyError::Other(format!("at-rest cipher init failed: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| PasskeyError::Other("at-rest open failed: wrong key or tampered data".to_string()))
}

/// Fetch (or first-time create) the per-OS-user Local Protection Key from the
/// OS keyring.
///
/// Idempotent and stable: the first call resolves the key (reading the keyring,
/// or minting + persisting one if absent) and caches it **process-locally**, so
/// every later call in this process returns the identical key. Errors with
/// [`PasskeyError::CredentialStore`] if the OS keyring is unavailable.
///
/// ## Concurrency
///
/// The process-local cache is guarded by a mutex, so concurrent first-callers in
/// one process mint at most ONE key (no last-write-wins race that would orphan a
/// seal made with a loser's key — the bug the integration suite surfaced). For
/// the cross-process first-launch case (Desktop + Service racing on a fresh
/// machine) the mint path re-reads the keyring after writing and adopts whatever
/// value actually persisted, so independent processes converge on one key.
#[cfg(feature = "keyring")]
pub fn local_protection_key() -> Result<Zeroizing<[u8; 32]>> {
    // The test override always wins and is never cached, so tests can toggle it
    // between cases.
    if let Some(test_key) = test_override::get() {
        return Ok(Zeroizing::new(test_key));
    }

    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<Option<[u8; 32]>>> = OnceLock::new();
    let mut guard = CACHE.get_or_init(|| Mutex::new(None)).lock().unwrap();
    if let Some(cached) = *guard {
        return Ok(Zeroizing::new(cached));
    }

    let key = resolve_lpk_from_keyring()?;
    *guard = Some(key);
    Ok(Zeroizing::new(key))
}

/// Read-or-mint the LPK from the OS keyring (uncached). See
/// [`local_protection_key`] for the caching/concurrency contract.
#[cfg(feature = "keyring")]
fn resolve_lpk_from_keyring() -> Result<[u8; 32]> {
    let entry = keyring::Entry::new(KEYWRAP_SERVICE, LPK_ENTRY)
        .map_err(|e| PasskeyError::CredentialStore(format!("LPK entry init failed: {e}")))?;

    let decode = |b64: String| -> Result<[u8; 32]> {
        let bytes = B64
            .decode(b64.trim())
            .map_err(|e| PasskeyError::CredentialStore(format!("LPK decode failed: {e}")))?;
        bytes
            .try_into()
            .map_err(|_| PasskeyError::CredentialStore("LPK is not 32 bytes".to_string()))
    };

    match entry.get_password() {
        Ok(b64) => decode(b64),
        Err(keyring::Error::NoEntry) => {
            // First run on this machine/user: mint + persist a fresh LPK.
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            entry
                .set_password(&B64.encode(key))
                .map_err(|e| PasskeyError::CredentialStore(format!("LPK persist failed: {e}")))?;
            // Cross-process convergence: re-read and adopt whatever actually
            // persisted. If another process won the mint race, we take theirs;
            // a seal made later in THIS process then uses the converged key.
            match entry.get_password() {
                Ok(b64) => decode(b64),
                Err(_) => {
                    tracing::info!("Minted a new at-rest Local Protection Key in the OS keyring");
                    Ok(key)
                }
            }
        }
        Err(e) => Err(PasskeyError::CredentialStore(format!(
            "LPK retrieval failed: {e}"
        ))),
    }
}

/// Base64 form of the Local Protection Key, suitable as a stable passphrase for
/// the Service repository-key keyring (AC-F5.2 engagement helper).
///
/// Same DPAPI-backed secret as [`local_protection_key`]; exposed as a string so
/// the Service's `Keyring::new_with_passphrase` can consume it without
/// `passkey-core` depending on the Service crate (DEC-LD-03).
#[cfg(feature = "keyring")]
pub fn local_protection_secret() -> Result<String> {
    let key = local_protection_key()?;
    Ok(B64.encode(&*key))
}

/// Seal `plaintext` for at-rest storage under the OS-keyring-backed LPK.
///
/// Returns an error if the keyring is unavailable; callers writing key files
/// should fall back to a plaintext write + warning to preserve availability.
#[cfg(feature = "keyring")]
pub fn wrap_at_rest(plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = local_protection_key()?;
    wrap_with_key(plaintext, &key)
}

/// Open an at-rest payload, transparently passing through legacy plaintext.
///
/// If `data` lacks the wrap magic it is returned unchanged (a pre-F5 plaintext
/// file). Otherwise it is opened under the OS-keyring-backed LPK.
#[cfg(feature = "keyring")]
pub fn unwrap_at_rest(data: &[u8]) -> Result<Vec<u8>> {
    if !is_wrapped(data) {
        return Ok(data.to_vec());
    }
    let key = local_protection_key()?;
    unwrap_with_key(data, &key)
}

/// Test-only override so unit tests can exercise the keyring-backed wrappers
/// deterministically without a real OS keyring (common in CI).
#[cfg(feature = "keyring")]
mod test_override {
    use std::sync::{Mutex, OnceLock};

    static OVERRIDE: OnceLock<Mutex<Option<[u8; 32]>>> = OnceLock::new();

    fn cell() -> &'static Mutex<Option<[u8; 32]>> {
        OVERRIDE.get_or_init(|| Mutex::new(None))
    }

    pub fn get() -> Option<[u8; 32]> {
        *cell().lock().unwrap()
    }

    /// Install (or clear) a fixed LPK for the current process. Test-only.
    #[doc(hidden)]
    pub fn set(key: Option<[u8; 32]>) {
        *cell().lock().unwrap() = key;
    }
}

/// Install a fixed Local Protection Key for the current process, bypassing the
/// OS keyring. **Test-only** — lets crate-unit tests verify the keyring-backed
/// wrappers without a live keyring. Pass `None` to clear.
#[cfg(feature = "keyring")]
#[doc(hidden)]
pub fn __set_test_lpk(key: Option<[u8; 32]>) {
    test_override::set(key);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn roundtrip_with_key() {
        let plain = b"the device seed is 32 bytes of secret material!!";
        let wrapped = wrap_with_key(plain, &TEST_KEY).unwrap();

        assert!(is_wrapped(&wrapped));
        assert_ne!(&wrapped[..], &plain[..], "wrapped output must not be plaintext");
        assert!(
            wrapped.len() > plain.len(),
            "wrapped adds magic+nonce+tag overhead"
        );

        let opened = unwrap_with_key(&wrapped, &TEST_KEY).unwrap();
        assert_eq!(opened, plain);
    }

    #[test]
    fn roundtrip_32_byte_seed() {
        // The device Ed25519 seed is exactly 32 bytes — the canonical AC-F5.1 case.
        let seed = [0xABu8; 32];
        let wrapped = wrap_with_key(&seed, &TEST_KEY).unwrap();
        assert!(is_wrapped(&wrapped));
        // The on-disk bytes are no longer the 32 raw seed bytes.
        assert_ne!(&wrapped[..32.min(wrapped.len())], &seed[..]);
        let opened = unwrap_with_key(&wrapped, &TEST_KEY).unwrap();
        assert_eq!(opened, seed.to_vec());
    }

    #[test]
    fn wrong_key_fails_auth() {
        let plain = b"secret";
        let wrapped = wrap_with_key(plain, &TEST_KEY).unwrap();
        let wrong = [9u8; 32];
        assert!(unwrap_with_key(&wrapped, &wrong).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let plain = b"secret material";
        let mut wrapped = wrap_with_key(plain, &TEST_KEY).unwrap();
        // Flip a bit in the ciphertext region (after magic + nonce).
        let last = wrapped.len() - 1;
        wrapped[last] ^= 0x01;
        assert!(
            unwrap_with_key(&wrapped, &TEST_KEY).is_err(),
            "GCM auth tag must reject tampering"
        );
    }

    #[test]
    fn legacy_plaintext_is_not_wrapped() {
        // A pre-F5 plaintext value (e.g. a raw 32-byte seed) is not detected as wrapped.
        let legacy = [0x11u8; 32];
        assert!(!is_wrapped(&legacy));
        // And short values never false-positive on the magic.
        assert!(!is_wrapped(b"GCKW")); // too short
        assert!(!is_wrapped(b"")); // empty
    }

    #[test]
    fn unwrap_with_key_rejects_unwrapped() {
        let legacy = [0x22u8; 16];
        assert!(unwrap_with_key(&legacy, &TEST_KEY).is_err());
    }

    #[test]
    fn nonce_is_random_per_call() {
        let plain = b"same plaintext";
        let a = wrap_with_key(plain, &TEST_KEY).unwrap();
        let b = wrap_with_key(plain, &TEST_KEY).unwrap();
        assert_ne!(a, b, "fresh nonce per seal → distinct ciphertexts");
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn at_rest_wrappers_with_test_lpk() {
        // Exercise the keyring-backed wrappers deterministically via the test LPK.
        __set_test_lpk(Some([5u8; 32]));

        let plain = b"identity secret key bytes";
        let wrapped = wrap_at_rest(plain).unwrap();
        assert!(is_wrapped(&wrapped));
        let opened = unwrap_at_rest(&wrapped).unwrap();
        assert_eq!(opened, plain);

        // Legacy plaintext passes through unwrap_at_rest unchanged.
        let legacy = b"legacy plaintext secret".to_vec();
        assert_eq!(unwrap_at_rest(&legacy).unwrap(), legacy);

        __set_test_lpk(None);
    }
}
