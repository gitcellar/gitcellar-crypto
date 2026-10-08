//! `gc-grant-v2` (2026-10): a repo-key grant binds the
//! repository's immutable `repo_uid`, so a rename or transfer — which changes
//! only its `owner/name` — leaves every grant verifying.

use gitcellar_crypto::grant_signing::{
    build_signed_repo_grant_bundle, sign_repo_key_grant, verify_grant_bundle, verify_repo_key_grant,
    GrantBundle, GrantVerifyOutcome, RepoKeyGrant,
};
use gitcellar_crypto::{EncryptionEngine, Identity};

const UID: &str = "5f0c9e7a2b1d4c3e8f6a0b9c7d2e1f30";

fn party(email: &str) -> (EncryptionEngine, String) {
    let identity = Identity::generate(email).unwrap();
    let cert = identity.export_public_key().unwrap();
    (EncryptionEngine::new(identity).unwrap(), cert)
}

/// The rename case. Under `gc-grant-v1` a grant over `owner/old` did not
/// verify once the repository was `owner/new`. Under
/// v2 the verifier checks by the uid, which the rename does not touch, and the
/// grant names nothing else.
#[test]
fn grant_signed_before_a_rename_verifies_after_it() {
    let (owner, owner_cert) = party("owner@example.com");
    let (recipient, _) = party("collab@example.com");
    let signed = RepoKeyGrant::new(
        UID,
        1,
        &recipient.fingerprint(),
        &owner.fingerprint(),
        "V0s=",
        1_750_000_000,
    );
    let sig = sign_repo_key_grant(&owner, &signed).unwrap();
    // The owner renames owner/old to owner/new; the uid is unchanged, so the
    // tuple the recipient reconstructs is the one that was signed.
    assert!(verify_repo_key_grant(&owner_cert, &signed, &sig).unwrap());

    // The same through the bundle the recipient actually decrypts, verified by uid.
    let bundle = build_signed_repo_grant_bundle(
        &owner,
        UID,
        1,
        &recipient.fingerprint(),
        "V0s=",
        1_750_000_000,
        None,
    )
    .unwrap();
    let wire = GrantBundle::from_json(&bundle.to_json().unwrap()).unwrap();
    assert_eq!(wire.repo_uid, UID);
    assert_eq!(
        verify_grant_bundle(&wire, &owner_cert, &owner.fingerprint(), UID, 1, &recipient.fingerprint()),
        GrantVerifyOutcome::Valid
    );
    // A name verifies nothing: neither the old one nor the new one.
    for name in ["owner/old", "owner/new"] {
        assert_eq!(
            verify_grant_bundle(&wire, &owner_cert, &owner.fingerprint(), name, 1, &recipient.fingerprint()),
            GrantVerifyOutcome::SignatureInvalid
        );
    }
}

/// The uid is bound: a genuine grant cannot be re-aimed at another repository
/// by editing the uid it carries, nor verified as another uid.
#[test]
fn a_grant_does_not_verify_for_another_repository() {
    let (owner, owner_cert) = party("owner@example.com");
    let (recipient, _) = party("collab@example.com");
    let rfp = recipient.fingerprint();
    let bundle =
        build_signed_repo_grant_bundle(&owner, UID, 2, &rfp, "V0s=", 1_750_000_000, None)
            .unwrap();
    let other = "0000000000000000000000000000000a";
    assert_eq!(
        verify_grant_bundle(&bundle, &owner_cert, &owner.fingerprint(), other, 2, &rfp),
        GrantVerifyOutcome::SignatureInvalid
    );
    let mut edited = bundle.clone();
    edited.repo_uid = other.to_string();
    assert_eq!(
        verify_grant_bundle(&edited, &owner_cert, &owner.fingerprint(), other, 2, &rfp),
        GrantVerifyOutcome::SignatureInvalid
    );
    assert_eq!(
        verify_grant_bundle(&bundle, &owner_cert, &owner.fingerprint(), UID, 2, &rfp),
        GrantVerifyOutcome::Valid
    );
}

/// A bundle that names no uid is refused at parse: v2 always binds one.
#[test]
fn a_bundle_without_a_uid_is_refused() {
    let no_uid = serde_json::json!({
        "v": "gc-grant-v2",
        "key_material_b64": "V0s=",
        "granter_fingerprint": "AB",
        "timestamp_unix": 1,
        "grant_sig_b64": "V0s=",
    });
    let err = GrantBundle::from_json(&serde_json::to_vec(&no_uid).unwrap()).unwrap_err();
    assert!(format!("{err}").contains("names no repo_uid"), "{err}");
}

/// The retired v1 bundle tag is refused, never verified under v2 rules.
#[test]
fn a_v1_bundle_is_refused() {
    let v1 = serde_json::json!({
        "v": "gc-grant-v1",
        "key_material_b64": "V0s=",
        "granter_fingerprint": "AB",
        "timestamp_unix": 1,
        "grant_sig_b64": "V0s=",
    });
    let err = GrantBundle::from_json(&serde_json::to_vec(&v1).unwrap()).unwrap_err();
    assert!(format!("{err}").contains("unsupported grant bundle version"), "{err}");
}
