//! At-rest key protection fails closed.
//!
//! Two fail-open paths are pinned shut here:
//!
//! 1. **A failed seal wrote the key in plaintext.** `Identity::save_to` fell
//!    back to writing the OpenPGP secret key unsealed, with a warning, whenever
//!    the OS keyring could not seal it. Now nothing is written.
//! 2. **A missing Local Protection Key was silently re-minted.** After a
//!    credential-store wipe, the next seal minted a fresh LPK, and everything
//!    sealed under the lost one became unreadable without a word. Now opening
//!    never mints, sealing mints only on an install that never minted one, and
//!    a re-mint is an explicit call.
//!
//! The LPK policy is driven through `resolve_lpk` with an in-memory store and a
//! temp marker, so no real credential store is touched.

use std::cell::RefCell;
use std::path::PathBuf;

use passkey_core::keywrap::{resolve_lpk, LpkMode, LpkStore, LPK_MISSING_MARKER};
use passkey_core::{Identity, PasskeyError};
use tempfile::TempDir;

/// An in-memory keyring slot. `fail` simulates a store that is unavailable.
#[derive(Default)]
struct FakeStore {
    value: RefCell<Option<String>>,
    fail: bool,
    sets: RefCell<u32>,
}

impl LpkStore for FakeStore {
    fn get(&self) -> Result<Option<String>, String> {
        if self.fail {
            return Err("no Secret Service".into());
        }
        Ok(self.value.borrow().clone())
    }
    fn set(&self, b64: &str) -> Result<(), String> {
        if self.fail {
            return Err("no Secret Service".into());
        }
        *self.sets.borrow_mut() += 1;
        *self.value.borrow_mut() = Some(b64.to_string());
        Ok(())
    }
}

fn marker_in(dir: &TempDir) -> PathBuf {
    dir.path().join("lpk-v1.minted")
}

fn is_missing_error(r: &Result<[u8; 32], PasskeyError>) -> bool {
    matches!(r, Err(PasskeyError::CredentialStore(m)) if m.contains(LPK_MISSING_MARKER))
}

// ---------------------------------------------------------------------------
// The mint policy
// ---------------------------------------------------------------------------

#[test]
fn first_seal_on_a_fresh_install_mints_and_records_it() {
    let dir = TempDir::new().unwrap();
    let store = FakeStore::default();

    let key = resolve_lpk(&store, &marker_in(&dir), LpkMode::Seal).expect("first run mints");

    assert_eq!(*store.sets.borrow(), 1, "exactly one key persisted");
    assert!(marker_in(&dir).exists(), "the mint is recorded");
    // And the next resolution returns the same key, minting nothing.
    let again = resolve_lpk(&store, &marker_in(&dir), LpkMode::Seal).unwrap();
    assert_eq!(key, again);
    assert_eq!(*store.sets.borrow(), 1);
}

#[test]
fn a_lost_lpk_is_an_error_on_seal_not_a_silent_remint() {
    let dir = TempDir::new().unwrap();
    let store = FakeStore::default();
    resolve_lpk(&store, &marker_in(&dir), LpkMode::Seal).unwrap();

    // The credential store is wiped (profile reset, credential cleanup).
    *store.value.borrow_mut() = None;

    let r = resolve_lpk(&store, &marker_in(&dir), LpkMode::Seal);
    assert!(is_missing_error(&r), "expected an LPK_MISSING error, got {r:?}");
    assert_eq!(*store.sets.borrow(), 1, "no replacement key was minted");
    assert!(store.value.borrow().is_none());
}

#[test]
fn opening_sealed_data_never_mints_even_on_a_fresh_install() {
    // Sealed data proves an LPK existed; a fresh one could not open it.
    let dir = TempDir::new().unwrap();
    let store = FakeStore::default();

    let r = resolve_lpk(&store, &marker_in(&dir), LpkMode::Open);

    assert!(is_missing_error(&r), "expected an LPK_MISSING error, got {r:?}");
    assert_eq!(*store.sets.borrow(), 0);
    assert!(!marker_in(&dir).exists());
}

#[test]
fn an_explicit_remint_replaces_a_lost_lpk() {
    let dir = TempDir::new().unwrap();
    let store = FakeStore::default();
    let old = resolve_lpk(&store, &marker_in(&dir), LpkMode::Seal).unwrap();
    *store.value.borrow_mut() = None;

    let new = resolve_lpk(&store, &marker_in(&dir), LpkMode::Remint).expect("remint mints");

    assert_ne!(old, new, "a new key, not the lost one");
    assert_eq!(*store.sets.borrow(), 2);
    // And sealing works again afterwards.
    assert_eq!(resolve_lpk(&store, &marker_in(&dir), LpkMode::Seal).unwrap(), new);
}

#[test]
fn a_present_lpk_without_a_marker_backfills_one() {
    // Installs that minted their LPK before the marker existed get the
    // re-mint guard on their next resolution.
    let dir = TempDir::new().unwrap();
    let store = FakeStore::default();
    *store.value.borrow_mut() = Some(base64_of([7u8; 32]));

    let key = resolve_lpk(&store, &marker_in(&dir), LpkMode::Open).unwrap();

    assert_eq!(key, [7u8; 32]);
    assert!(marker_in(&dir).exists(), "marker backfilled");
    *store.value.borrow_mut() = None;
    assert!(is_missing_error(&resolve_lpk(&store, &marker_in(&dir), LpkMode::Seal)));
}

#[test]
fn an_unavailable_store_is_an_error_in_every_mode() {
    let dir = TempDir::new().unwrap();
    let store = FakeStore { fail: true, ..Default::default() };
    for mode in [LpkMode::Open, LpkMode::Seal, LpkMode::Remint] {
        let r = resolve_lpk(&store, &marker_in(&dir), mode);
        assert!(
            matches!(r, Err(PasskeyError::CredentialStore(_))),
            "{mode:?}: {r:?}"
        );
    }
}

fn base64_of(key: [u8; 32]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(key)
}

// ---------------------------------------------------------------------------
// The identity writer
// ---------------------------------------------------------------------------

#[test]
fn a_failed_seal_writes_nothing_at_all() {
    let dir = TempDir::new().unwrap();
    let target = dir.path().join("users").join("alice").join("identity");
    let identity = Identity::generate("alice@example.com").unwrap();

    let r = identity.save_to_with_sealer(&target, |_| {
        Err(PasskeyError::KeySave("keyring unavailable".into()))
    });

    assert!(r.is_err(), "the save must fail when the seal fails");
    assert!(
        !target.exists(),
        "nothing — not the secret key, not the public key, not the directory — may be written"
    );
}

#[test]
fn the_sealer_output_is_exactly_what_lands_on_disk() {
    let dir = TempDir::new().unwrap();
    let identity = Identity::generate("bob@example.com").unwrap();

    identity
        .save_to_with_sealer(dir.path(), |_| Ok(b"SEALED".to_vec()))
        .unwrap();

    assert_eq!(std::fs::read(dir.path().join("secret.pgp")).unwrap(), b"SEALED");
}

#[cfg(feature = "keyring")]
#[test]
fn save_to_seals_under_the_lpk() {
    passkey_core::keywrap::__set_test_lpk(Some([0x42u8; 32]));
    let dir = TempDir::new().unwrap();
    let identity = Identity::generate("carol@example.com").unwrap();

    identity.save_to(dir.path()).unwrap();

    let raw = std::fs::read(dir.path().join("secret.pgp")).unwrap();
    assert!(passkey_core::keywrap::is_wrapped(&raw));
    let loaded = Identity::load_from(dir.path()).unwrap();
    assert_eq!(loaded.fingerprint(), identity.fingerprint());
    passkey_core::keywrap::__set_test_lpk(None);
}
