//! Authentication challenges cannot be turned into signatures over other objects.
//!
//! Regression test (2026-09-23 security review): clients used to sign the server's challenge string raw, with the key that also
//! signs key grants, so a malicious server could serve a grant canonical as the
//! "challenge" and receive a valid owner-signed grant.

use base64::Engine as _;
use gitcellar_crypto::grant_signing::{verify_repo_key_grant, RepoKeyGrant};
use gitcellar_crypto::{
    challenge_signing_payload, generate_challenge, verify_detached_signature, ChallengePurpose,
    EncryptionEngine, Identity,
};

fn engine(email: &str) -> (EncryptionEngine, String, String) {
    let id = Identity::generate(email).unwrap();
    let cert = id.export_public_key().unwrap();
    let fp = id.fingerprint();
    (EncryptionEngine::new(id).unwrap(), cert, fp)
}

#[test]
fn a_grant_canonical_served_as_a_challenge_is_refused() {
    let (owner, _owner_cert, owner_fp) = engine("owner@example.com");
    let (_, _, victim_fp) = engine("victim@example.com");
    let grant = RepoKeyGrant::new("owner/repo", 2, &victim_fp, &owner_fp, "QUFBQQ==", 1_758_600_000);
    let as_challenge = String::from_utf8(grant.canonical()).unwrap();

    for purpose in [ChallengePurpose::Login, ChallengePurpose::RegistrationProof] {
        assert!(
            owner.sign_auth_challenge(purpose, &as_challenge).is_err(),
            "a non-nonce challenge must never be signed"
        );
    }
}

#[test]
fn a_challenge_signature_verifies_only_as_that_challenge_and_purpose() {
    let (owner, owner_cert, owner_fp) = engine("owner@example.com");
    let (_, _, victim_fp) = engine("victim@example.com");
    let challenge = generate_challenge();

    let sig = owner.sign_auth_challenge(ChallengePurpose::Login, &challenge).unwrap();

    let login = challenge_signing_payload(ChallengePurpose::Login, &challenge).unwrap();
    assert!(verify_detached_signature(&owner_cert, &login, &sig).unwrap());

    // Not over the raw challenge (the retired, unframed form) ...
    assert!(!verify_detached_signature(&owner_cert, challenge.as_bytes(), &sig).unwrap());
    // ... not as the other purpose ...
    let pop = challenge_signing_payload(ChallengePurpose::RegistrationProof, &challenge).unwrap();
    assert!(!verify_detached_signature(&owner_cert, &pop, &sig).unwrap());
    // ... and not as a grant.
    let grant = RepoKeyGrant::new("owner/repo", 2, &victim_fp, &owner_fp, "QUFBQQ==", 1_758_600_000);
    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);
    assert!(!verify_repo_key_grant(&owner_cert, &grant, &sig_b64).unwrap());
}
