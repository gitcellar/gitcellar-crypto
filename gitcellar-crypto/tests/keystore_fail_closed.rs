//! The device keystore fails closed: when the at-rest seal is unavailable, no
//! device seed reaches disk, sealed or not.
//!
//! Before this, `generate_device_keypair` wrote the raw 32-byte seed with a
//! warning whenever the OS keyring could not answer. These tests drive the seal
//! failure through `FileSystemKeystore::with_sealer`, because on Windows the real
//! keyring (DPAPI) always answers and the failure could not otherwise be reached.

use gitcellar_crypto::keystore::{
    FileSystemKeystore, KeystoreBackend, KeystoreError, DEVICE_PRIVATE_FILENAME,
    DEVICE_PUBLIC_FILENAME,
};
use tempfile::TempDir;

fn seal_unavailable(_seed: &[u8; 32]) -> Result<Vec<u8>, KeystoreError> {
    Err(KeystoreError::Unavailable)
}

#[test]
fn generate_refuses_when_the_seal_is_unavailable() {
    let dir = TempDir::new().unwrap();
    let identity_dir = dir.path().join("identity");
    let mut store = FileSystemKeystore::with_sealer(&identity_dir, seal_unavailable);

    let result = store.generate_device_keypair();
    assert!(
        matches!(result, Err(KeystoreError::Unavailable)),
        "an unavailable seal must fail the call, got {result:?}"
    );

    // Nothing was written: no private seed, no public half that would make a
    // later call think a keypair exists, no leftover temp file.
    let leftovers: Vec<_> = std::fs::read_dir(&identity_dir)
        .map(|entries| entries.filter_map(|e| e.ok()).map(|e| e.file_name()).collect())
        .unwrap_or_default();
    assert!(
        leftovers.is_empty(),
        "fail-closed keystore left files behind: {leftovers:?}"
    );
    assert!(!identity_dir.join(DEVICE_PRIVATE_FILENAME).exists());
    assert!(!identity_dir.join(DEVICE_PUBLIC_FILENAME).exists());

    // And the store still reports "no key", rather than something half-made.
    assert!(matches!(store.export_pubkey(), Err(KeystoreError::NotInitialized)));
    assert!(matches!(store.sign(b"x"), Err(KeystoreError::NotInitialized)));
}

#[test]
fn a_failed_generate_does_not_poison_a_later_one() {
    let dir = TempDir::new().unwrap();
    let identity_dir = dir.path().join("identity");

    let mut refusing = FileSystemKeystore::with_sealer(&identity_dir, seal_unavailable);
    assert!(refusing.generate_device_keypair().is_err());

    // A sealer that works (a stand-in for the keyring coming back) produces a
    // keypair whose on-disk seed is exactly what it sealed -- never the raw seed.
    fn seal_marked(seed: &[u8; 32]) -> Result<Vec<u8>, KeystoreError> {
        let mut out = b"SEALED:".to_vec();
        out.extend(seed.iter().map(|b| b ^ 0xff));
        Ok(out)
    }
    let mut working = FileSystemKeystore::with_sealer(&identity_dir, seal_marked);
    working.generate_device_keypair().unwrap();
    let on_disk = std::fs::read(identity_dir.join(DEVICE_PRIVATE_FILENAME)).unwrap();
    assert!(on_disk.starts_with(b"SEALED:"));
    assert_ne!(on_disk.len(), 32, "the raw 32-byte seed must never be written");
}

/// The default sealer is the fail-closed one. Without the keyring feature there
/// is no seal at all, so it must refuse rather than hand back the seed.
#[cfg(not(feature = "keyring"))]
#[test]
fn default_sealer_refuses_without_keyring_feature() {
    let seed = [7u8; 32];
    assert!(matches!(
        gitcellar_crypto::keystore::try_seal_device_seed_at_rest(&seed),
        Err(KeystoreError::Unavailable)
    ));
}

/// With the keyring feature, the default sealer's output is a keywrap payload,
/// never the seed itself.
#[cfg(feature = "keyring")]
#[test]
fn default_sealer_output_is_wrapped() {
    gitcellar_identity::keywrap::__set_test_lpk(Some([0x33u8; 32]));
    let seed = [7u8; 32];
    let sealed = gitcellar_crypto::keystore::try_seal_device_seed_at_rest(&seed).unwrap();
    assert!(gitcellar_identity::keywrap::is_wrapped(&sealed));
    assert!(!sealed.windows(32).any(|w| w == seed), "sealed payload contains the raw seed");
}
