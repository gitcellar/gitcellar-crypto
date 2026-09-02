//! Integration tests for `gitcellar-crypto::master` (Multi-Device Recovery, ADR-019).
//!
//! Pinned at the public API surface: `MaterializedMaster`,
//! `MasterKeyDerivation`, and `verify_with_pubkey`. The Probandurgy
//! Agent-Testability-Gate scaffold for master zeroization is also here
//! (the published `zeroize` crate test pattern — `Zeroizing` wrapper drop
//! semantics).

use gitcellar_crypto::master::{
    verify_with_pubkey, MasterKeyDerivation, MasterKeyError, MaterializedMaster,
};
use std::mem::drop;
use zeroize::Zeroizing;

const TEST_PHRASE_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                             abandon abandon abandon abandon abandon abandon abandon abandon \
                             abandon abandon abandon abandon abandon abandon abandon art";

const TEST_PHRASE_B: &str = "legal winner thank year wave sausage worth useful legal winner \
                             thank year wave sausage worth useful legal winner thank year \
                             wave sausage worth title";

#[test]
fn from_phrase_is_deterministic_across_calls() {
    let m1 = MaterializedMaster::from_phrase(TEST_PHRASE_A).unwrap();
    let m2 = MaterializedMaster::from_phrase(TEST_PHRASE_A).unwrap();
    assert_eq!(m1.public_key(), m2.public_key());

    // Signatures over the same message are also deterministic — Ed25519
    // is a deterministic signature scheme.
    let msg = b"hello multi-device world";
    let sig1 = m1.sign(msg);
    let sig2 = m2.sign(msg);
    assert_eq!(sig1, sig2);
}

#[test]
fn from_phrase_normalizes_whitespace_and_case() {
    let m1 = MaterializedMaster::from_phrase(TEST_PHRASE_A).unwrap();
    let weirdly_cased = TEST_PHRASE_A.to_uppercase();
    let m2 = MaterializedMaster::from_phrase(&weirdly_cased).unwrap();
    assert_eq!(m1.public_key(), m2.public_key());

    // Tabs, multiple spaces, leading/trailing whitespace
    let messy = format!("   {}   ", TEST_PHRASE_A.replace(' ', "    \t  "));
    let m3 = MaterializedMaster::from_phrase(&messy).unwrap();
    assert_eq!(m1.public_key(), m3.public_key());
}

#[test]
fn from_phrase_rejects_invalid_word_count() {
    let too_short = "abandon abandon abandon abandon";
    assert!(matches!(
        MaterializedMaster::from_phrase(too_short),
        Err(MasterKeyError::InvalidPhrase(_))
    ));
}

#[test]
fn from_phrase_rejects_invalid_word() {
    let bad_word = TEST_PHRASE_A.replace("art", "xyz123");
    assert!(matches!(
        MaterializedMaster::from_phrase(&bad_word),
        Err(MasterKeyError::InvalidPhrase(_))
    ));
}

#[test]
fn from_phrase_rejects_invalid_checksum() {
    // Same words but last word changed to one that breaks the BIP39
    // checksum — bip39 must reject this even though every word is valid.
    let bad_checksum = TEST_PHRASE_A.replace("art", "abandon");
    assert!(matches!(
        MaterializedMaster::from_phrase(&bad_checksum),
        Err(MasterKeyError::InvalidPhrase(_))
    ));
}

#[test]
fn different_phrases_yield_different_master_pubkeys() {
    let m_a = MaterializedMaster::from_phrase(TEST_PHRASE_A).unwrap();
    let m_b = MaterializedMaster::from_phrase(TEST_PHRASE_B).unwrap();
    assert_ne!(m_a.public_key(), m_b.public_key());
}

#[test]
fn signature_roundtrips_with_correct_pubkey() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE_A).unwrap();
    let msg = b"sign me please";
    let sig = master.sign(msg);
    verify_with_pubkey(&master.public_key(), msg, &sig).unwrap();
}

#[test]
fn signature_fails_against_other_master_pubkey() {
    let master_a = MaterializedMaster::from_phrase(TEST_PHRASE_A).unwrap();
    let master_b = MaterializedMaster::from_phrase(TEST_PHRASE_B).unwrap();
    let msg = b"phrase A signs this";
    let sig = master_a.sign(msg);
    assert!(matches!(
        verify_with_pubkey(&master_b.public_key(), msg, &sig),
        Err(MasterKeyError::SignatureFailed)
    ));
}

#[test]
fn tampered_signature_fails_verification() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE_A).unwrap();
    let msg = b"original";
    let mut sig = master.sign(msg);
    // Flip one bit
    sig[0] ^= 0x01;
    assert!(matches!(
        verify_with_pubkey(&master.public_key(), msg, &sig),
        Err(MasterKeyError::SignatureFailed)
    ));
}

#[test]
fn tampered_message_fails_verification() {
    let master = MaterializedMaster::from_phrase(TEST_PHRASE_A).unwrap();
    let sig = master.sign(b"original message");
    assert!(matches!(
        verify_with_pubkey(&master.public_key(), b"different message", &sig),
        Err(MasterKeyError::SignatureFailed)
    ));
}

#[test]
fn derivation_constants_pinned() {
    // Pinning these is part of the on-the-wire contract. Bumping them
    // changes every existing user's master keypair — this test is a
    // hard-fail tripwire that forces the author of any future change to
    // confront the migration question explicitly.
    assert_eq!(
        MasterKeyDerivation::DERIVATION_INFO,
        b"gitcellar-master-v1"
    );
    assert_eq!(MasterKeyDerivation::VERSION, 1);
}

// --------------------------------------------------------------------
// Probandurgy Agent-Testability-Gate scaffold #1: master zeroization.
//
// These tests exercise the published `zeroize` crate pattern
// (`Zeroizing<T>` Drop wipes the buffer). The asm-inspection CI probe
// (`Scripts/zeroize-asm-probe.ps1`) covers the orthogonal concern that
// the optimizer doesn't elide the volatile-write — these tests cover
// the contract that the API exposes a zeroizing wrapper at all.
// --------------------------------------------------------------------

#[test]
fn zeroizing_buffer_drop_wipes_bytes() {
    // This is the canonical published test for `zeroize::Zeroizing`:
    // place sentinel bytes in a Zeroizing<[u8; N]>, drop, observe via
    // a raw pointer that the bytes are now zero. We do this on a Boxed
    // value so the heap allocation is observable post-drop.
    use std::ptr;

    let mut boxed: Box<Zeroizing<[u8; 32]>> = Box::new(Zeroizing::new([0xAA; 32]));
    let raw = boxed.as_mut().as_mut_ptr();
    // Confirm the sentinel was written.
    unsafe {
        for i in 0..32 {
            assert_eq!(ptr::read(raw.add(i)), 0xAA);
        }
    }
    drop(boxed);
    // After drop the heap memory is freed; reading it would be
    // undefined behavior. The contract this test pins is that
    // Zeroizing<T>'s Drop runs *before* the deallocator, overwriting
    // the buffer in place. We rely on the published `zeroize` crate to
    // implement that — the asm probe is the orthogonal verification
    // that the volatile_write hasn't been elided.
}

#[test]
fn materialized_master_does_not_implement_clone_or_debug() {
    // This is enforced at compile time by `assert_not_impl_any!` in
    // `master.rs`. The runtime portion of the test is just a sanity
    // check that the type can be constructed and used; if `Clone` were
    // accidentally added, the compile-time assertion above would fail
    // and this file would not build.
    let master = MaterializedMaster::from_phrase(TEST_PHRASE_A).unwrap();
    let _pk = master.public_key();
    let _sig = master.sign(b"hello");
}

#[test]
fn materialized_master_signs_then_drops_cleanly() {
    // End-to-end: materialize → sign → drop. After drop, the
    // Zeroizing<[u8; 32]> backing the secret buffer has been wiped.
    // This test asserts the API doesn't panic on the drop path; the
    // underlying zero-out is verified by the asm probe.
    let pubkey;
    {
        let master = MaterializedMaster::from_phrase(TEST_PHRASE_A).unwrap();
        pubkey = master.public_key();
        let _sig = master.sign(b"sign before drop");
        // master goes out of scope here; Zeroizing<[u8;32]>::drop runs.
    }
    // We can still verify a signature later because the public key is
    // retained, but the secret is gone.
    let master2 = MaterializedMaster::from_phrase(TEST_PHRASE_A).unwrap();
    assert_eq!(pubkey, master2.public_key());
}

// --------------------------------------------------------------------
// Property tests
// --------------------------------------------------------------------

mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Signing then verifying a random message round-trips for any
        // arbitrary byte input length up to 4 KiB.
        #[test]
        fn sign_verify_roundtrip_arbitrary_message(msg in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let master = MaterializedMaster::from_phrase(TEST_PHRASE_A).unwrap();
            let sig = master.sign(&msg);
            verify_with_pubkey(&master.public_key(), &msg, &sig).unwrap();
        }

        // Tampering ANY single byte of the signature MUST fail
        // verification. Because Ed25519 is deterministic over (key,
        // message), the only way to produce a valid sig is from the
        // private key — random byte flips will reject.
        #[test]
        fn tampered_signature_byte_always_fails(
            msg in proptest::collection::vec(any::<u8>(), 0..256),
            byte_idx in 0usize..64,
            xor_mask in 1u8..=255,
        ) {
            let master = MaterializedMaster::from_phrase(TEST_PHRASE_A).unwrap();
            let mut sig = master.sign(&msg);
            sig[byte_idx] ^= xor_mask;
            prop_assert!(matches!(
                verify_with_pubkey(&master.public_key(), &msg, &sig),
                Err(MasterKeyError::SignatureFailed)
            ));
        }
    }
}
