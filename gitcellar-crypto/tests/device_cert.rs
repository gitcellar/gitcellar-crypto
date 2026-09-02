//! Integration tests for `gitcellar-crypto::device_cert` (Contract C-1).
//!
//! Pinned at the public API: `DeviceCertificate::sign_with_master`,
//! `sign_with_device`, `verify`, `to_cbor` / `from_cbor`, plus the
//! cross-signing accept/reject contract from MDR-035 + DEC-MDR-06/07.

use ed25519_dalek::SigningKey;
use gitcellar_crypto::device_cert::{
    CertError, DeviceCertificate, SignerRole, MAX_LABEL_BYTES,
};
use gitcellar_crypto::master::MaterializedMaster;
use rand::rngs::OsRng;

const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon abandon abandon art";

const ALT_PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner \
                          thank year wave sausage worth useful legal winner thank year wave \
                          sausage worth title";

fn fresh_device() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

fn pk(s: &SigningKey) -> [u8; 32] {
    s.verifying_key().to_bytes()
}

#[test]
fn master_signed_cert_round_trips_through_cbor() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let device = fresh_device();
    let cert = DeviceCertificate::sign_with_master(
        &master,
        pk(&device),
        "Office laptop".to_string(),
        "windows".to_string(),
        1_700_000_000,
    )
    .unwrap();

    let bytes = cert.to_cbor().unwrap();
    let decoded = DeviceCertificate::from_cbor(&bytes).unwrap();
    assert_eq!(cert, decoded);
}

#[test]
fn master_signed_cert_verifies_against_master_pubkey() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let device = fresh_device();
    let cert = DeviceCertificate::sign_with_master(
        &master,
        pk(&device),
        "Office laptop".to_string(),
        "linux".to_string(),
        1_700_000_000,
    )
    .unwrap();

    // No eligible devices needed — master-signed certs verify with an
    // empty eligible-set.
    cert.verify(&master.public_key(), &[]).unwrap();
    assert_eq!(cert.payload.signer_role, SignerRole::Master);
    assert_eq!(cert.payload.signer_pubkey, master.public_key());
}

#[test]
fn cross_signed_cert_verifies_when_signer_is_in_eligible_set() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();

    // Device A (already enrolled) cross-signs Device B's cert.
    let device_a = fresh_device();
    let device_b = fresh_device();

    let cert_b = DeviceCertificate::sign_with_device(
        &device_a,
        master.public_key(),
        pk(&device_b),
        "Phone".to_string(),
        "android".to_string(),
        1_700_000_500,
    )
    .unwrap();

    // Cloud API would pass `eligible_device_pubkeys = [device_a, ...other live devices]`.
    cert_b.verify(&master.public_key(), &[pk(&device_a)]).unwrap();
    assert_eq!(cert_b.payload.signer_role, SignerRole::Device);
    assert_eq!(cert_b.payload.signer_pubkey, pk(&device_a));
}

#[test]
fn cross_signed_cert_rejected_when_signer_not_in_eligible_set() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();

    let device_a = fresh_device();
    let device_b = fresh_device();
    let cert_b = DeviceCertificate::sign_with_device(
        &device_a,
        master.public_key(),
        pk(&device_b),
        "Phone".to_string(),
        "android".to_string(),
        1_700_000_500,
    )
    .unwrap();

    // Eligible set excludes device_a (it has been revoked).
    let other = fresh_device();
    let result = cert_b.verify(&master.public_key(), &[pk(&other)]);
    assert!(matches!(result, Err(CertError::UnknownSigner)));

    // Empty eligible set also rejects.
    assert!(matches!(
        cert_b.verify(&master.public_key(), &[]),
        Err(CertError::UnknownSigner)
    ));
}

#[test]
fn cert_with_wrong_master_pubkey_rejected() {
    let master_a = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let master_b = MaterializedMaster::from_phrase(ALT_PHRASE).unwrap();

    let device = fresh_device();
    let cert = DeviceCertificate::sign_with_master(
        &master_a,
        pk(&device),
        "lab".to_string(),
        "macos".to_string(),
        1_700_000_001,
    )
    .unwrap();

    let result = cert.verify(&master_b.public_key(), &[]);
    assert!(matches!(result, Err(CertError::MasterMismatch)));
}

#[test]
fn cert_with_signer_pubkey_equal_to_master_but_role_device_rejected() {
    // Construct a malformed cert: signer_role = Device but
    // signer_pubkey = master_pubkey. Rejected as SignerRoleMismatch.
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let device = fresh_device();

    // Build a real cert first, then mutate the role discriminator and
    // re-sign with the master key bound under SignerRole::Device.
    let mut cert = DeviceCertificate::sign_with_master(
        &master,
        pk(&device),
        "lab".to_string(),
        "linux".to_string(),
        1_700_000_002,
    )
    .unwrap();
    cert.payload.signer_role = SignerRole::Device;
    // Re-sign with master so the signature is valid (otherwise we'd
    // hit SignatureFailed first). We exercise the
    // signer-role-mismatch branch.
    let signed = cert.signed_payload_bytes().unwrap();
    cert.signature = master.sign(&signed);

    let result = cert.verify(&master.public_key(), &[master.public_key()]);
    assert!(matches!(result, Err(CertError::SignerRoleMismatch)));
}

#[test]
fn cert_with_master_role_but_wrong_signer_pubkey_rejected() {
    // signer_role = Master but signer_pubkey != master_pubkey.
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let device = fresh_device();

    let mut cert = DeviceCertificate::sign_with_master(
        &master,
        pk(&device),
        "lab".to_string(),
        "windows".to_string(),
        1_700_000_003,
    )
    .unwrap();
    cert.payload.signer_pubkey = pk(&device);
    let signed = cert.signed_payload_bytes().unwrap();
    cert.signature = master.sign(&signed);

    let result = cert.verify(&master.public_key(), &[]);
    assert!(matches!(result, Err(CertError::SignerRoleMismatch)));
}

#[test]
fn tampered_payload_rejected() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let device = fresh_device();
    let mut cert = DeviceCertificate::sign_with_master(
        &master,
        pk(&device),
        "lab".to_string(),
        "linux".to_string(),
        1_700_000_004,
    )
    .unwrap();

    // Mutate the label after signing — signature no longer covers the
    // mutated bytes.
    cert.payload.label = "tampered".to_string();
    let result = cert.verify(&master.public_key(), &[]);
    assert!(matches!(result, Err(CertError::SignatureFailed)));
}

#[test]
fn tampered_signature_byte_rejected() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let device = fresh_device();
    let mut cert = DeviceCertificate::sign_with_master(
        &master,
        pk(&device),
        "lab".to_string(),
        "linux".to_string(),
        1_700_000_005,
    )
    .unwrap();

    cert.signature[7] ^= 0x80;
    let result = cert.verify(&master.public_key(), &[]);
    assert!(matches!(result, Err(CertError::SignatureFailed)));
}

#[test]
fn label_at_max_size_accepted() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let device = fresh_device();
    let label = "x".repeat(MAX_LABEL_BYTES);
    let cert = DeviceCertificate::sign_with_master(
        &master,
        pk(&device),
        label,
        "linux".to_string(),
        1_700_000_006,
    )
    .unwrap();
    cert.verify(&master.public_key(), &[]).unwrap();
}

#[test]
fn label_over_max_size_rejected() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let device = fresh_device();
    let label = "x".repeat(MAX_LABEL_BYTES + 1);
    let result = DeviceCertificate::sign_with_master(
        &master,
        pk(&device),
        label,
        "linux".to_string(),
        1_700_000_007,
    );
    assert!(matches!(result, Err(CertError::LabelTooLong(_))));
}

#[test]
fn canonical_encoding_is_stable() {
    // Two certs constructed with identical inputs MUST serialize to
    // byte-for-byte identical CBOR. This is the pinning test for
    // canonical-encoding determinism — without it, signatures would
    // not be reproducible across signer/verifier and the cross-signing
    // chain would not work in distributed deployments.
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let device_pk = pk(&fresh_device());

    let cert1 = DeviceCertificate::sign_with_master(
        &master,
        device_pk,
        "Office laptop".to_string(),
        "linux".to_string(),
        1_700_000_008,
    )
    .unwrap();
    let cert2 = DeviceCertificate::sign_with_master(
        &master,
        device_pk,
        "Office laptop".to_string(),
        "linux".to_string(),
        1_700_000_008,
    )
    .unwrap();

    assert_eq!(cert1.signed_payload_bytes().unwrap(), cert2.signed_payload_bytes().unwrap());
    // Ed25519 is deterministic — signatures match too.
    assert_eq!(cert1.signature, cert2.signature);
    assert_eq!(cert1.to_cbor().unwrap(), cert2.to_cbor().unwrap());
}

#[test]
fn corrupt_cbor_returns_deserialization_error() {
    let result = DeviceCertificate::from_cbor(&[0xFF, 0xAA, 0x55]);
    assert!(matches!(result, Err(CertError::Deserialization(_))));
}

#[test]
fn unsupported_version_rejected() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let device = fresh_device();
    let mut cert = DeviceCertificate::sign_with_master(
        &master,
        pk(&device),
        "lab".to_string(),
        "linux".to_string(),
        1_700_000_009,
    )
    .unwrap();
    cert.payload.cert_version = 99;
    let result = cert.verify(&master.public_key(), &[]);
    assert!(matches!(result, Err(CertError::UnsupportedVersion { expected: 1, got: 99 })));
}

// --------------------------------------------------------------------
// Property tests for the cross-signing contract — the heart of the
// Probandurgy testability scaffolding for this module.
// --------------------------------------------------------------------

mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_device() -> impl Strategy<Value = SigningKey> {
        any::<[u8; 32]>().prop_map(|seed| SigningKey::from_bytes(&seed))
    }

    proptest! {
        // Master-signed certs verify against the right master pubkey
        // for any well-formed inputs.
        #[test]
        fn master_signed_always_verifies(
            label in "[a-zA-Z0-9_ ]{0,64}",
            platform in "(windows|macos|linux|android|ios|other)",
            ts in any::<i64>(),
            device in arb_device(),
        ) {
            let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
            let cert = DeviceCertificate::sign_with_master(
                &master,
                pk(&device),
                label,
                platform,
                ts,
            ).unwrap();
            cert.verify(&master.public_key(), &[]).unwrap();
        }

        // Cross-signed cert by an in-set device MUST verify; the same
        // cert with that device REMOVED from the eligible set MUST
        // reject. This is the central security property of the
        // revocation enforcement model.
        #[test]
        fn cross_signing_accept_then_revoke_rejects(
            label in "[a-zA-Z0-9_ ]{0,64}",
            platform in "(windows|macos|linux|android|ios|other)",
            ts in any::<i64>(),
            signer in arb_device(),
            target in arb_device(),
        ) {
            // Cannot have signer == target as device-signs-itself
            // would be a degenerate case the cross-signing flow does
            // not produce in practice.
            prop_assume!(pk(&signer) != pk(&target));

            let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
            let cert = DeviceCertificate::sign_with_device(
                &signer,
                master.public_key(),
                pk(&target),
                label,
                platform,
                ts,
            ).unwrap();

            // In-set: accept.
            cert.verify(&master.public_key(), &[pk(&signer)]).unwrap();
            // Removed: reject.
            prop_assert!(matches!(
                cert.verify(&master.public_key(), &[]),
                Err(CertError::UnknownSigner)
            ));
        }

        // Tampering ANY single byte of the signed payload MUST fail
        // verification. This is the canonical-CBOR + Ed25519 tamper
        // detection contract.
        #[test]
        fn tamper_detection_one_byte(
            label in "[a-zA-Z0-9_ ]{1,16}",
            platform in "(windows|macos|linux)",
            ts in 1_500_000_000_i64..2_000_000_000_i64,
            device in arb_device(),
            label_byte in 0u8..=255,
        ) {
            let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
            let mut cert = DeviceCertificate::sign_with_master(
                &master,
                pk(&device),
                label.clone(),
                platform,
                ts,
            ).unwrap();

            // Mutate label deterministically based on input. If the
            // mutation produces a non-mutated label (label was empty
            // and label_byte happens to add a no-op suffix), skip via
            // assume.
            let mut chars: Vec<u8> = cert.payload.label.bytes().collect();
            chars.push(label_byte);
            cert.payload.label = String::from_utf8_lossy(&chars).into_owned();

            prop_assert!(matches!(
                cert.verify(&master.public_key(), &[]),
                Err(CertError::SignatureFailed)
                | Err(CertError::LabelTooLong(_))
            ));
        }
    }
}

// ─── Option-D dual-role signing (DEC-MDR-04) ─────────────────────────────────
//
// Under Option D the migration reuses the legacy secret.pgp keypair as BOTH
// master and device, so master_pubkey == device_pubkey. Because onboarding
// writes secret.pgp and never mints a native device cert, EVERY onboarded user
// is in this posture — so these two tests cover the real, universal path, not
// an edge case.
//
// Regression origin (2026-07-15): `device_authorize` unconditionally called
// `sign_with_device`, whose `signer_role: Device` + signer_pubkey == master is
// a contradiction `verify` rejects — so adding a second device failed for every
// user, and nothing caught it because the multi-device E2E builds certs via the
// test-helper instead of driving the real authorize path.

#[test]
fn option_d_dual_role_authorize_signs_as_master() {
    // The Option-D posture: one key is both master and device.
    let legacy = SigningKey::from_bytes(&[7u8; 32]);
    let dual_role_pubkey = legacy.verifying_key().to_bytes();
    let new_device_pubkey = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();

    let mut legacy_seed = legacy.to_bytes();
    let master = MaterializedMaster::from_secret_bytes(&mut legacy_seed)
        .expect("materialize master from the legacy seed");
    assert_eq!(
        master.public_key(),
        dual_role_pubkey,
        "Option D: the materialized master IS the legacy keypair"
    );

    // What `device_authorize` must do when master == device.
    let cert = DeviceCertificate::sign_with_master(
        &master,
        new_device_pubkey,
        "laptop".to_string(),
        "windows".to_string(),
        1_700_000_000,
    )
    .expect("master-signing succeeds");

    assert_eq!(cert.payload.signer_role, SignerRole::Master);

    // What the Cloud does in `pairing_authorize`. The dual-role key is also in
    // the eligible-device set (it IS the user's only device) — verification
    // must still pass via the Master branch.
    let eligible = vec![dual_role_pubkey];
    cert.verify(&dual_role_pubkey, &eligible)
        .expect("Option-D master-signed cert must verify");
}

#[test]
fn option_d_signing_as_device_is_rejected() {
    // Pins the bug itself: signing as Device while signer_pubkey == master is a
    // contradiction, and MUST stay rejected. If this ever starts passing, the
    // role/key invariant has been weakened — that is the thing to notice.
    let legacy = SigningKey::from_bytes(&[7u8; 32]);
    let dual_role_pubkey = legacy.verifying_key().to_bytes();
    let new_device_pubkey = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();

    let cert = DeviceCertificate::sign_with_device(
        &legacy,
        dual_role_pubkey, // master_pubkey
        new_device_pubkey,
        "laptop".to_string(),
        "windows".to_string(),
        1_700_000_000,
    )
    .expect("signing itself succeeds — the rejection is at verify");

    let eligible = vec![dual_role_pubkey];
    assert!(
        matches!(
            cert.verify(&dual_role_pubkey, &eligible),
            Err(CertError::SignerRoleMismatch)
        ),
        "signer_role=Device with signer_pubkey==master must be rejected"
    );
}
