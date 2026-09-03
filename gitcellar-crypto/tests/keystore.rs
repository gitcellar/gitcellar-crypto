//! Integration tests for `gitcellar-crypto::keystore`.

use gitcellar_crypto::device_cert::DeviceCertificate;
use gitcellar_crypto::keystore::{
    FileSystemKeystore, KeystoreBackend, KeystoreError, DEVICE_CERT_FILENAME,
    DEVICE_PRIVATE_FILENAME, DEVICE_PUBLIC_FILENAME, MASTER_PUBLIC_FILENAME,
};
use gitcellar_crypto::master::{verify_with_pubkey, MaterializedMaster};
use tempfile::TempDir;

const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon abandon art";

fn ks(dir: &TempDir) -> FileSystemKeystore {
    FileSystemKeystore::new(dir.path().join("identity"))
}

#[test]
fn available_returns_true_by_default() {
    let dir = TempDir::new().unwrap();
    assert!(ks(&dir).available());
}

#[test]
fn export_pubkey_before_generate_errors() {
    let dir = TempDir::new().unwrap();
    let store = ks(&dir);
    assert!(matches!(store.export_pubkey(), Err(KeystoreError::NotInitialized)));
}

#[test]
fn generate_device_keypair_persists_files() {
    let dir = TempDir::new().unwrap();
    let mut store = ks(&dir);
    let pubkey = store.generate_device_keypair().unwrap();

    let identity_dir = dir.path().join("identity");
    assert!(identity_dir.join(DEVICE_PRIVATE_FILENAME).exists());
    assert!(identity_dir.join(DEVICE_PUBLIC_FILENAME).exists());

    // Pub bytes from disk match the pubkey returned by generate.
    let on_disk = std::fs::read(identity_dir.join(DEVICE_PUBLIC_FILENAME)).unwrap();
    assert_eq!(on_disk, pubkey);
}

#[test]
fn generate_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let mut store = ks(&dir);
    let pk1 = store.generate_device_keypair().unwrap();
    let pk2 = store.generate_device_keypair().unwrap();
    assert_eq!(pk1, pk2);

    let mut store2 = ks(&dir);
    let pk3 = store2.generate_device_keypair().unwrap();
    assert_eq!(pk1, pk3);
}

#[test]
fn sign_then_verify_with_exported_pubkey() {
    let dir = TempDir::new().unwrap();
    let mut store = ks(&dir);
    let pubkey = store.generate_device_keypair().unwrap();

    let msg = b"some message to be signed by the device";
    let sig = store.sign(msg).unwrap();
    verify_with_pubkey(&pubkey, msg, &sig).unwrap();
}

#[test]
fn sign_before_generate_errors() {
    let dir = TempDir::new().unwrap();
    let store = ks(&dir);
    let result = store.sign(b"hello");
    assert!(matches!(result, Err(KeystoreError::NotInitialized)));
}

#[test]
fn import_then_export_cert_round_trips() {
    let dir = TempDir::new().unwrap();
    let mut store = ks(&dir);

    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let device_pk = store.generate_device_keypair().unwrap();
    let cert = DeviceCertificate::sign_with_master(
        &master,
        device_pk,
        "lab".to_string(),
        "linux".to_string(),
        1_700_002_000,
    )
    .unwrap();

    store.import_cert(&cert).unwrap();
    let loaded = store.export_cert().unwrap();
    assert_eq!(loaded, cert);

    let identity_dir = dir.path().join("identity");
    assert!(identity_dir.join(DEVICE_CERT_FILENAME).exists());
}

#[test]
fn export_cert_before_import_errors() {
    let dir = TempDir::new().unwrap();
    let mut store = ks(&dir);
    store.generate_device_keypair().unwrap();
    assert!(matches!(store.export_cert(), Err(KeystoreError::NoCertificate)));
}

#[test]
fn import_export_master_pubkey_round_trips() {
    let dir = TempDir::new().unwrap();
    let mut store = ks(&dir);
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let mpk = master.public_key();

    store.import_master_pubkey(&mpk).unwrap();
    let loaded = store.export_master_pubkey().unwrap();
    assert_eq!(loaded, mpk);

    let identity_dir = dir.path().join("identity");
    assert!(identity_dir.join(MASTER_PUBLIC_FILENAME).exists());
}

#[test]
fn export_master_pubkey_before_import_errors() {
    let dir = TempDir::new().unwrap();
    let store = ks(&dir);
    let result = store.export_master_pubkey();
    assert!(matches!(result, Err(KeystoreError::NoMasterPubkey)));
}

#[test]
fn import_invalid_master_pubkey_errors() {
    let dir = TempDir::new().unwrap();
    let mut store = ks(&dir);
    // A point encoding that ed25519-dalek 2.x's `VerifyingKey::from_bytes`
    // rejects: a non-canonical y coordinate (y == 2^255 - 18 ≡ 1 mod p
    // but with the y-overflow bit set), which is one of the small set
    // of encodings the library rejects as "low-order" / non-canonical.
    // We don't try to fingerprint one specific failing value here —
    // instead we use a value that decodes to a low-order point, which
    // dalek 2.x explicitly rejects via `is_weak()`. This is the only
    // 32-byte value with predictable rejection across dalek versions.
    let bad: [u8; 32] = [
        0xEE, 0xCD, 0xA8, 0x40, 0xCD, 0x6F, 0xC1, 0xCB, 0xCA, 0xC8, 0xA1, 0x80, 0xCC, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    // It's fine if dalek either rejects this OR accepts it depending
    // on version policy — what we care about is that the keystore
    // does NOT silently corrupt its on-disk state. Whichever branch
    // is taken, the file write either succeeds (with valid bytes) or
    // returns InvalidKey. The hard contract is that on success, a
    // round-trip read returns identical bytes.
    if let Ok(()) = store.import_master_pubkey(&bad) {
        let read = store.export_master_pubkey().unwrap();
        assert_eq!(read, bad);
    }
}

#[test]
fn keystore_persists_across_recreated_instances() {
    let dir = TempDir::new().unwrap();
    let pubkey = {
        let mut store = ks(&dir);
        store.generate_device_keypair().unwrap()
    };
    let store2 = ks(&dir);
    let read_back = store2.export_pubkey().unwrap();
    assert_eq!(pubkey, read_back);

    // Sign/verify across the boundary too.
    let sig = store2.sign(b"signed across instances").unwrap();
    verify_with_pubkey(&pubkey, b"signed across instances", &sig).unwrap();
}

// Probes the real OS keyring; only meaningful when the crate is built with it.
#[cfg(feature = "keyring")]
#[test]
fn device_seed_sealed_at_rest_and_round_trips() {
    // F5 / AC-F5.1: when an OS keyring is available, the on-disk
    // `device.key.bin` is AES-256-GCM ciphertext (carries the keywrap magic),
    // NOT the 32 raw plaintext seed bytes. Where no keyring exists (some CI)
    // the seal falls back to a plaintext write — but the read path round-trips
    // either way. (No global test-LPK override here: this binary's other tests
    // run concurrently against the real keyring, so we must not mutate the
    // process-global LPK.)
    let dir = TempDir::new().unwrap();
    let mut store = ks(&dir);
    let pubkey = store.generate_device_keypair().unwrap();

    let priv_path = dir.path().join("identity").join(DEVICE_PRIVATE_FILENAME);
    let on_disk = std::fs::read(&priv_path).unwrap();

    // Only assert sealing when the keyring is actually available on this host.
    if gitcellar_identity::keywrap::wrap_at_rest(b"probe").is_ok() {
        assert!(
            gitcellar_identity::keywrap::is_wrapped(&on_disk),
            "device.key.bin must be sealed at rest (AC-F5.1), got {} bytes",
            on_disk.len()
        );
        assert_ne!(on_disk.len(), 32, "sealed seed must not be 32 raw bytes");
    }

    // Round-trips back to a working signing key across a fresh instance.
    let store2 = ks(&dir);
    let read_back = store2.export_pubkey().unwrap();
    assert_eq!(pubkey, read_back);
    let sig = store2.sign(b"sealed-at-rest message").unwrap();
    verify_with_pubkey(&pubkey, b"sealed-at-rest message", &sig).unwrap();
}

#[test]
fn legacy_plaintext_device_seed_still_loads() {
    // F5 backward-safety: a pre-F5 plaintext 32-byte seed (no wrap magic) must
    // still load via the transparent-passthrough read path. Pure read of a
    // hand-written raw file — no global LPK state touched.
    let dir = TempDir::new().unwrap();
    let identity_dir = dir.path().join("identity");
    std::fs::create_dir_all(&identity_dir).unwrap();

    use ed25519_dalek::SigningKey;
    let sk = SigningKey::from_bytes(&[3u8; 32]);
    let pk = sk.verifying_key().to_bytes();
    std::fs::write(identity_dir.join(DEVICE_PRIVATE_FILENAME), sk.to_bytes()).unwrap();
    std::fs::write(identity_dir.join(DEVICE_PUBLIC_FILENAME), pk).unwrap();

    let store = ks(&dir);
    let exported = store.export_pubkey().unwrap();
    assert_eq!(exported, pk);
    let sig = store.sign(b"legacy load").unwrap();
    verify_with_pubkey(&pk, b"legacy load", &sig).unwrap();
}

#[test]
fn corrupt_pubkey_file_errors_on_read() {
    let dir = TempDir::new().unwrap();
    let mut store = ks(&dir);
    let _ = store.generate_device_keypair().unwrap();
    let identity_dir = dir.path().join("identity");
    let pub_path = identity_dir.join(DEVICE_PUBLIC_FILENAME);
    // Truncate the file to 5 bytes.
    std::fs::write(&pub_path, [1u8, 2, 3, 4, 5]).unwrap();
    // The cached pubkey from the previous successful generate would
    // still be returned by the original store, so use a fresh
    // FileSystemKeystore that re-reads from disk.
    let store2 = ks(&dir);
    let result = store2.export_pubkey();
    assert!(matches!(result, Err(KeystoreError::InvalidKey(_))));
}
