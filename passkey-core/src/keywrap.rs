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
//! ## No plaintext fallback
//!
//! If the OS keyring is unavailable (some headless Linux/CI environments with no
//! Secret-Service daemon), [`wrap_at_rest`] returns an error, and since
//! 2026-09-25 the identity writer refuses rather than writing the key
//! unsealed. A test that needs a sealed write without a keyring
//! installs a per-thread test key with [`__set_test_lpk`]. The pure
//! [`wrap_with_key`] / [`unwrap_with_key`] primitives never touch the keyring
//! and are fully deterministic for testing.
//!
//! ## A missing LPK is an error, never a silent re-mint
//!
//! The LPK used to be minted whenever the keyring had no entry. That is right
//! exactly once — the first run for this OS user — and wrong every other time:
//! after a credential-store wipe or profile reset, a fresh key silently
//! replaced the lost one, every file sealed under the old key became
//! unreadable, and nothing said so. Now ([`resolve_lpk`]):
//!
//! - **opening** sealed data never mints: the sealed data proves an LPK
//!   existed, so its absence is reported ([`LPK_MISSING_MARKER`] in the error);
//! - **sealing** mints only when this install has never minted one, which a
//!   marker file ([`lpk_minted_marker_path`], in the identity root, removed with
//!   it on uninstall) records; otherwise it is the same error;
//! - a deliberate re-mint — restoring an identity from the recovery phrase —
//!   goes through [`remint_local_protection_key`], which says loudly what it
//!   costs.

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
///
/// **Public because the destructive-uninstall credential sweep has to know it.**
/// It used to be private, so the sweep carried a copied literal with a "keep in
/// sync" note, and that copy drifted twice.
pub const KEYWRAP_SERVICE: &str = "gitcellar";

/// OS-keyring entry name for the per-OS-user Local Protection Key (v1).
/// Public for the same reason as [`KEYWRAP_SERVICE`] — it is swept by name on
/// the destructive-uninstall path, and a second copy of the name is a defect.
pub const LPK_ENTRY: &str = "at-rest-protection-key-v1";

/// Token carried in every "the LPK is missing" error, so a caller can tell that
/// case from a keyring that is merely unavailable without a new error variant.
pub const LPK_MISSING_MARKER: &str = "LPK_MISSING";

/// File name of the "an LPK has been minted for this install" marker.
pub const LPK_MINTED_MARKER_FILE: &str = "lpk-v1.minted";

/// Where the minted marker lives: the GitCellar identity root, next to the
/// sealed files it vouches for, so the destructive uninstall that sweeps the
/// LPK also removes the marker with the identity root.
pub fn lpk_minted_marker_path() -> std::path::PathBuf {
    crate::paths::PasskeyConfig::gitcellar()
        .config_dir()
        .join(LPK_MINTED_MARKER_FILE)
}

/// What a caller of [`resolve_lpk`] is allowed to do when the keyring has no LPK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LpkMode {
    /// Opening sealed data: never mint.
    Open,
    /// Sealing: mint only if this install has never minted one.
    Seal,
    /// Deliberate re-mint after a known loss (identity restore from phrase).
    Remint,
}

/// The OS-keyring slot holding the LPK, abstracted so the mint policy is
/// testable without a real credential store.
pub trait LpkStore {
    /// `Ok(None)` when there is no entry; `Err` when the store itself failed.
    fn get(&self) -> std::result::Result<Option<String>, String>;
    fn set(&self, b64: &str) -> std::result::Result<(), String>;
}

/// Resolve the LPK from `store` under `mode`, using `marker` as the record that
/// one was minted for this install. See the module docs for the policy.
pub fn resolve_lpk(
    store: &dyn LpkStore,
    marker: &std::path::Path,
    mode: LpkMode,
) -> Result<[u8; 32]> {
    let decode = |b64: String| -> Result<[u8; 32]> {
        let bytes = B64
            .decode(b64.trim())
            .map_err(|e| PasskeyError::CredentialStore(format!("LPK decode failed: {e}")))?;
        bytes
            .try_into()
            .map_err(|_| PasskeyError::CredentialStore("LPK is not 32 bytes".to_string()))
    };

    match store
        .get()
        .map_err(|e| PasskeyError::CredentialStore(format!("LPK retrieval failed: {e}")))?
    {
        Some(b64) => {
            let key = decode(b64)?;
            // Backfill: an install whose LPK predates the marker gets one now,
            // so a later loss of that LPK is caught rather than re-minted over.
            if !marker.exists() {
                write_minted_marker(marker);
            }
            Ok(key)
        }
        None => {
            match mode {
                LpkMode::Open => {
                    return Err(PasskeyError::CredentialStore(format!(
                        "{LPK_MISSING_MARKER}: the Local Protection Key is missing from the OS \
                         credential store, so data sealed under it cannot be opened. It was not \
                         re-created: a new key cannot open what the lost one sealed."
                    )))
                }
                LpkMode::Seal if marker.exists() => {
                    return Err(PasskeyError::CredentialStore(format!(
                        "{LPK_MISSING_MARKER}: the Local Protection Key minted for this install \
                         ({}) is missing from the OS credential store. Refusing to mint a \
                         replacement silently — everything sealed under the lost key would become \
                         unreadable without notice. Restore the identity from its recovery phrase.",
                        marker.display()
                    )))
                }
                LpkMode::Seal | LpkMode::Remint => {}
            }
            if mode == LpkMode::Remint {
                tracing::warn!(
                    "Re-minting the at-rest Local Protection Key after a known loss: anything \
                     sealed under the previous key on this machine stays unreadable"
                );
            }
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            store
                .set(&B64.encode(key))
                .map_err(|e| PasskeyError::CredentialStore(format!("LPK persist failed: {e}")))?;
            // Cross-process convergence: re-read and adopt whatever actually
            // persisted. If another process won the mint race, we take theirs.
            let key = match store.get() {
                Ok(Some(b64)) => decode(b64)?,
                _ => key,
            };
            write_minted_marker(marker);
            tracing::info!("Minted a new at-rest Local Protection Key in the OS keyring");
            Ok(key)
        }
    }
}

/// Record that an LPK was minted. Best-effort: a marker that cannot be written
/// only weakens the re-mint guard for this install, while failing the mint
/// after the key is already in the keyring would strand it.
fn write_minted_marker(marker: &std::path::Path) {
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(marker, b"an at-rest Local Protection Key was minted for this install\n") {
        tracing::warn!("Could not record the LPK minted marker at {:?}: {}", marker, e);
    }
}

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
/// OS keyring, for SEALING ([`LpkMode::Seal`]).
///
/// Idempotent and stable: the first call resolves the key (reading the keyring,
/// or minting + persisting one if this install never minted one) and caches it
/// **process-locally**, so every later call in this process returns the
/// identical key. Errors with [`PasskeyError::CredentialStore`] if the OS
/// keyring is unavailable, or if the LPK this install minted has gone missing.
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
    cached_lpk(LpkMode::Seal)
}

/// Process-local LPK cache shared by every mode.
#[cfg(feature = "keyring")]
fn lpk_cache() -> &'static std::sync::Mutex<Option<[u8; 32]>> {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<Option<[u8; 32]>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(None))
}

#[cfg(feature = "keyring")]
fn cached_lpk(mode: LpkMode) -> Result<Zeroizing<[u8; 32]>> {
    // The test override always wins and is never cached, so tests can toggle it
    // between cases.
    if let Some(test_key) = test_override::get() {
        return Ok(Zeroizing::new(test_key));
    }

    let mut guard = lpk_cache().lock().unwrap();
    if let Some(cached) = *guard {
        return Ok(Zeroizing::new(cached));
    }

    let key = resolve_lpk(&KeyringLpkStore::new()?, &lpk_minted_marker_path(), mode)?;
    *guard = Some(key);
    Ok(Zeroizing::new(key))
}

/// Deliberately replace a lost LPK — the recovery-phrase restore path.
///
/// A no-op when the LPK is present. When it is missing, mints a new one even
/// though this install minted one before, and says so: whatever was sealed under
/// the lost key on this machine stays unreadable. Never call this to get past an
/// [`LPK_MISSING_MARKER`] error on any other path.
#[cfg(feature = "keyring")]
pub fn remint_local_protection_key() -> Result<()> {
    if test_override::get().is_some() {
        return Ok(());
    }
    let mut guard = lpk_cache().lock().unwrap();
    let key = resolve_lpk(
        &KeyringLpkStore::new()?,
        &lpk_minted_marker_path(),
        LpkMode::Remint,
    )?;
    *guard = Some(key);
    Ok(())
}

/// The real OS-keyring slot ([`KEYWRAP_SERVICE`] / [`LPK_ENTRY`]).
#[cfg(feature = "keyring")]
struct KeyringLpkStore(keyring::Entry);

#[cfg(feature = "keyring")]
impl KeyringLpkStore {
    fn new() -> Result<Self> {
        keyring::Entry::new(KEYWRAP_SERVICE, LPK_ENTRY)
            .map(Self)
            .map_err(|e| PasskeyError::CredentialStore(format!("LPK entry init failed: {e}")))
    }
}

#[cfg(feature = "keyring")]
impl LpkStore for KeyringLpkStore {
    fn get(&self) -> std::result::Result<Option<String>, String> {
        match self.0.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn set(&self, b64: &str) -> std::result::Result<(), String> {
        self.0.set_password(b64).map_err(|e| e.to_string())
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
/// Returns an error if the keyring is unavailable or the LPK this install
/// minted is missing. Callers writing key files must refuse the write rather
/// than fall back to plaintext.
#[cfg(feature = "keyring")]
pub fn wrap_at_rest(plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = local_protection_key()?;
    wrap_with_key(plaintext, &key)
}

/// Open an at-rest payload, transparently passing through legacy plaintext.
///
/// If `data` lacks the wrap magic it is returned unchanged (a pre-F5 plaintext
/// file). Otherwise it is opened under the OS-keyring-backed LPK, which is
/// never minted on this path: sealed data proves an LPK existed, so a missing
/// one is an [`LPK_MISSING_MARKER`] error.
#[cfg(feature = "keyring")]
pub fn unwrap_at_rest(data: &[u8]) -> Result<Vec<u8>> {
    if !is_wrapped(data) {
        return Ok(data.to_vec());
    }
    let key = cached_lpk(LpkMode::Open)?;
    unwrap_with_key(data, &key)
}

/// Test-only override so unit tests can exercise the keyring-backed wrappers
/// deterministically without a real OS keyring (common in CI).
///
/// ## Why this is THREAD-LOCAL and not a process-wide static
///
/// It used to be a `static Mutex<Option<[u8; 32]>>`, i.e. shared by every test in the
/// binary — and `cargo test` runs tests in PARALLEL THREADS in one process. So
/// `at_rest_wrappers_with_test_lpk` clearing the override at the end of its body
/// (`__set_test_lpk(None)`, which is the correct thing for a test to do with global state)
/// could land in the middle of an identity test that had installed its own key and was
/// midway through `Identity::save_to`.
///
/// That was not a flake with a cosmetic outcome. With the override gone, `wrap_at_rest`
/// falls through to the real OS keyring; in a Linux CI container there is no Secret-Service,
/// so it fails. At the time `save_to` then fell back to writing the secret key **unsealed**
/// with a warning (that fallback has since been removed: a failed seal now fails the save).
/// The victim test read `secret.pgp` back, found no wrap magic, and failed — correctly. It
/// was reporting a real unsealed write caused by a neighbouring test, which is why it failed
/// ~7 runs in 12 in CI and never once locally, where Windows DPAPI always answers and the
/// fallback never fired.
///
/// A security test that is wrong half the time is one people learn to scroll past, so the
/// cure has to remove the race rather than mute it. Thread-local does that by construction:
/// every test owns its own value, no test can clear another's, and tests still run in
/// parallel (serialising them would also have worked and would have been slower and easier
/// to forget to apply to the next test).
///
/// A test-only escape hatch: it is public so integration tests can reach it, but only test
/// code calls `__set_test_lpk`, so in GitCellar's shipped binaries the value is `None` on
/// every thread and the keyring path is the only path. (Being `pub`, it is callable by any
/// code linking this crate; moving it behind a test-only feature is the tighter form.) `local_protection_key()` reads it on the SAME thread that
/// is doing the wrap, which is the thread the test installed it on.
#[cfg(feature = "keyring")]
mod test_override {
    use std::cell::Cell;

    thread_local! {
        static OVERRIDE: Cell<Option<[u8; 32]>> = const { Cell::new(None) };
    }

    pub fn get() -> Option<[u8; 32]> {
        OVERRIDE.with(|c| c.get())
    }

    /// Install (or clear) a fixed LPK for the CURRENT THREAD. Test-only.
    #[doc(hidden)]
    pub fn set(key: Option<[u8; 32]>) {
        OVERRIDE.with(|c| c.set(key));
    }
}

/// Install a fixed Local Protection Key for the CURRENT THREAD, bypassing the
/// OS keyring. **Test-only** — lets crate-unit tests verify the keyring-backed
/// wrappers without a live keyring. Pass `None` to clear.
///
/// Thread-scoped on purpose: see `test_override` for the parallel-test race that a
/// process-wide override caused, and why it surfaced as an unsealed key on disk.
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

    /// The test LPK override must not be visible from another thread.
    ///
    /// This is the regression guard for a real defect, not a style preference. When the
    /// override was a process-wide `static Mutex<..>`, `at_rest_wrappers_with_test_lpk`
    /// above clearing it could race a concurrent identity test mid-`save_to`; that test's
    /// wrap then fell through to the OS keyring, which a Linux CI container does not have,
    /// and `save_to`'s availability fallback wrote the OpenPGP secret key to disk UNSEALED.
    /// The failure looked like flake (~7 runs in 12, never locally, because Windows DPAPI
    /// always answers) while actually reporting an unsealed private key.
    ///
    /// If someone makes this shared again, this test fails instead of the flake coming back.
    #[cfg(feature = "keyring")]
    #[test]
    fn test_lpk_override_is_thread_local() {
        __set_test_lpk(Some([9u8; 32]));
        assert_eq!(
            super::test_override::get(),
            Some([9u8; 32]),
            "the installing thread must see its own override"
        );

        let seen_elsewhere = std::thread::spawn(|| super::test_override::get())
            .join()
            .expect("probe thread panicked");
        assert_eq!(
            seen_elsewhere, None,
            "another thread saw this thread's test LPK — the override is shared again, so one test can clear another's key mid-wrap and the secret key lands on disk unsealed"
        );

        // And the converse: a clear on another thread must not disturb ours.
        std::thread::spawn(|| __set_test_lpk(None)).join().expect("probe thread panicked");
        assert_eq!(
            super::test_override::get(),
            Some([9u8; 32]),
            "another thread clearing the override wiped ours — this is the exact race"
        );

        __set_test_lpk(None);
    }
}
