//! Integration tests for `gitcellar-crypto::revocation_cert` (Contract C-2).

use ed25519_dalek::SigningKey;
use gitcellar_crypto::device_cert::SignerRole;
use gitcellar_crypto::master::MaterializedMaster;
use gitcellar_crypto::revocation_cert::{
    RevocationCertError, RevocationCertificate, RevocationReason,
};
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
fn master_signed_revocation_round_trips_through_cbor() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let target = fresh_device();
    let cert = RevocationCertificate::sign_with_master(
        &master,
        pk(&target),
        1_700_001_000,
        RevocationReason::UserInitiated,
    )
    .unwrap();
    let bytes = cert.to_cbor().unwrap();
    let decoded = RevocationCertificate::from_cbor(&bytes).unwrap();
    assert_eq!(cert, decoded);
}

#[test]
fn master_signed_revocation_verifies() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let target = fresh_device();
    let cert = RevocationCertificate::sign_with_master(
        &master,
        pk(&target),
        1_700_001_000,
        RevocationReason::Compromise,
    )
    .unwrap();
    cert.verify(&master.public_key(), &[]).unwrap();
    assert_eq!(cert.payload.signer_role, SignerRole::Master);
}

#[test]
fn cross_signed_revocation_verifies_when_signer_in_eligible_set() {
    // Device C revokes Device A; Device C is currently non-revoked.
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let device_a = fresh_device();
    let device_c = fresh_device();

    let cert = RevocationCertificate::sign_with_device(
        &device_c,
        master.public_key(),
        pk(&device_a),
        1_700_001_001,
        RevocationReason::DeviceLost,
    )
    .unwrap();

    cert.verify(&master.public_key(), &[pk(&device_c)]).unwrap();
}

#[test]
fn revocation_signed_by_now_revoked_device_rejected() {
    // Critical security property: a compromised device's revocation
    // certs stop validating once that device's own revocation has
    // propagated. Eligible_device_pubkeys excludes revoked devices.
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let attacker_device = fresh_device();
    let target = fresh_device();

    let bad_revocation = RevocationCertificate::sign_with_device(
        &attacker_device,
        master.public_key(),
        pk(&target),
        1_700_001_500,
        RevocationReason::UserInitiated,
    )
    .unwrap();

    // Attacker's pubkey is NOT in eligible set (it has been revoked).
    let result = bad_revocation.verify(&master.public_key(), &[]);
    assert!(matches!(result, Err(RevocationCertError::UnknownSigner)));
}

#[test]
fn revocation_with_wrong_master_pubkey_rejected() {
    let master_a = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let master_b = MaterializedMaster::from_phrase(ALT_PHRASE).unwrap();
    let target = fresh_device();

    let cert = RevocationCertificate::sign_with_master(
        &master_a,
        pk(&target),
        1_700_001_002,
        RevocationReason::Rotation,
    )
    .unwrap();
    let result = cert.verify(&master_b.public_key(), &[]);
    assert!(matches!(result, Err(RevocationCertError::MasterMismatch)));
}

#[test]
fn tampered_revocation_payload_rejected() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let target = fresh_device();
    let mut cert = RevocationCertificate::sign_with_master(
        &master,
        pk(&target),
        1_700_001_003,
        RevocationReason::DeviceLost,
    )
    .unwrap();

    // Mutate target_device_pubkey post-sign.
    cert.payload.target_device_pubkey = pk(&fresh_device());
    let result = cert.verify(&master.public_key(), &[]);
    assert!(matches!(result, Err(RevocationCertError::SignatureFailed)));
}

#[test]
fn tampered_signature_rejected() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let target = fresh_device();
    let mut cert = RevocationCertificate::sign_with_master(
        &master,
        pk(&target),
        1_700_001_004,
        RevocationReason::Rotation,
    )
    .unwrap();
    cert.signature[0] ^= 0xFF;
    let result = cert.verify(&master.public_key(), &[]);
    assert!(matches!(result, Err(RevocationCertError::SignatureFailed)));
}

#[test]
fn unsupported_version_rejected() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let target = fresh_device();
    let mut cert = RevocationCertificate::sign_with_master(
        &master,
        pk(&target),
        1_700_001_005,
        RevocationReason::UserInitiated,
    )
    .unwrap();
    cert.payload.cert_version = 7;
    let result = cert.verify(&master.public_key(), &[]);
    assert!(matches!(
        result,
        Err(RevocationCertError::UnsupportedVersion { expected: 1, got: 7 })
    ));
}

#[test]
fn reason_serializes_as_canonical_strings() {
    // Pin the on-the-wire reason strings (Contract C-2). Renaming any
    // of these enum variants would silently change the CBOR encoding
    // and break all outstanding revocation certs in the field.
    use gitcellar_crypto::revocation_cert::RevocationReason as R;
    let cases = [
        (R::UserInitiated, "user_initiated"),
        (R::Compromise, "compromise"),
        (R::DeviceLost, "device_lost"),
        (R::Rotation, "rotation"),
    ];
    for (reason, expected) in cases {
        // Round-trip via JSON (which serde_cbor strings encode the
        // same way as serde_json strings — both use the renaming
        // attribute).
        let json = serde_json::to_string(&reason).unwrap();
        assert_eq!(json, format!("\"{}\"", expected));
    }
}

#[test]
fn canonical_encoding_is_stable() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
    let target_pk = pk(&fresh_device());

    let cert1 = RevocationCertificate::sign_with_master(
        &master,
        target_pk,
        1_700_001_006,
        RevocationReason::Compromise,
    )
    .unwrap();
    let cert2 = RevocationCertificate::sign_with_master(
        &master,
        target_pk,
        1_700_001_006,
        RevocationReason::Compromise,
    )
    .unwrap();

    assert_eq!(cert1.signed_payload_bytes().unwrap(), cert2.signed_payload_bytes().unwrap());
    assert_eq!(cert1.signature, cert2.signature);
    assert_eq!(cert1.to_cbor().unwrap(), cert2.to_cbor().unwrap());
}

mod property_tests {
    use super::*;
    use proptest::prelude::*;

    fn arb_device() -> impl Strategy<Value = SigningKey> {
        any::<[u8; 32]>().prop_map(|seed| SigningKey::from_bytes(&seed))
    }

    fn arb_reason() -> impl Strategy<Value = RevocationReason> {
        prop_oneof![
            Just(RevocationReason::UserInitiated),
            Just(RevocationReason::Compromise),
            Just(RevocationReason::DeviceLost),
            Just(RevocationReason::Rotation),
        ]
    }

    proptest! {
        #[test]
        fn cross_signing_accept_then_revoke_rejects(
            ts in any::<i64>(),
            reason in arb_reason(),
            signer in arb_device(),
            target in arb_device(),
        ) {
            prop_assume!(pk(&signer) != pk(&target));

            let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
            let cert = RevocationCertificate::sign_with_device(
                &signer,
                master.public_key(),
                pk(&target),
                ts,
                reason,
            ).unwrap();

            cert.verify(&master.public_key(), &[pk(&signer)]).unwrap();
            prop_assert!(matches!(
                cert.verify(&master.public_key(), &[]),
                Err(RevocationCertError::UnknownSigner)
            ));
        }

        #[test]
        fn tamper_detection_target_pubkey(
            ts in 1_500_000_000_i64..2_000_000_000_i64,
            reason in arb_reason(),
            target in arb_device(),
            replacement in arb_device(),
        ) {
            prop_assume!(pk(&target) != pk(&replacement));
            let master = MaterializedMaster::from_phrase(TEST_PHRASE).unwrap();
            let mut cert = RevocationCertificate::sign_with_master(
                &master,
                pk(&target),
                ts,
                reason,
            ).unwrap();
            cert.payload.target_device_pubkey = pk(&replacement);
            prop_assert!(matches!(
                cert.verify(&master.public_key(), &[]),
                Err(RevocationCertError::SignatureFailed)
            ));
        }
    }
}
