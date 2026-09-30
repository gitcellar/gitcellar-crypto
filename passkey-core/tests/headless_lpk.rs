//! The at-rest Local Protection Key on a host whose OS keyring is unavailable
//! or not persistent.
//!
//! On Linux the keyring crate's backend is kernel keyutils: Docker's default
//! seccomp profile blocks it, and where it works it holds the key only in the
//! session keyring, which a logout, reboot or container restart empties. So on
//! such a host the LPK comes from the headless secret (`GITCELLAR_HEADLESS_LPK_SECRET`
//! or `..._FILE`), and with neither the seal fails closed.
//!
//! The policy is pinned through the pure `choose_lpk` / `headless_lpk_from`, and
//! the real `wrap_at_rest` / `unwrap_at_rest` / `Identity::save_to` path is
//! driven on a simulated host (`__set_test_host`), because on Windows DPAPI
//! always answers and the keyring-less path could not otherwise be reached.

use std::cell::Cell;

use passkey_core::keywrap::{
    self, choose_lpk, derive_headless_lpk, headless_lpk_from, is_wrapped, unwrap_with_key,
    LpkSource, TestHost, HEADLESS_LPK_ENV, HEADLESS_LPK_FILE_ENV, HEADLESS_LPK_MIN_LEN,
    LPK_MISSING_MARKER,
};
use passkey_core::PasskeyError;
use zeroize::Zeroizing;

const SECRET: &str = "ci-headless-lpk-secret-0123456789abcdef0123456789";
const OS_KEY: [u8; 32] = [3u8; 32];

fn os_unavailable() -> passkey_core::Result<[u8; 32]> {
    Err(PasskeyError::CredentialStore(
        "LPK entry init failed: Platform secure storage failure: Unknown(1)".into(),
    ))
}

fn headless_some() -> passkey_core::Result<Option<Zeroizing<[u8; 32]>>> {
    Ok(Some(derive_headless_lpk(SECRET)))
}

fn headless_none() -> passkey_core::Result<Option<Zeroizing<[u8; 32]>>> {
    Ok(None)
}

// ---- choose_lpk: a non-persistent host (Linux) ------------------------------

#[test]
fn a_non_persistent_host_uses_the_headless_secret_and_never_calls_the_os_keyring() {
    let called = Cell::new(false);
    let (key, source) = choose_lpk(
        false,
        || {
            called.set(true);
            Ok(OS_KEY)
        },
        headless_some,
    )
    .expect("the headless secret must resolve the LPK");
    assert_eq!(source, LpkSource::Headless);
    assert_eq!(*key, *derive_headless_lpk(SECRET));
    assert!(
        !called.get(),
        "keyutils must never be touched on a non-persistent host: its key dies at logout, \
         and Docker's seccomp profile blocks the syscall"
    );
}

#[test]
fn a_non_persistent_host_without_a_headless_secret_fails_closed_even_if_the_keyring_would_answer() {
    let err = choose_lpk(false, || Ok(OS_KEY), headless_none)
        .expect_err("a key that forgets itself at reboot is not a place to seal an identity")
        .to_string();
    assert!(err.contains(HEADLESS_LPK_ENV), "the error must say what to set: {err}");
    assert!(err.contains(HEADLESS_LPK_FILE_ENV), "{err}");
    assert!(err.contains("not persistent") || err.contains("forgets"), "{err}");
    assert!(err.contains("Nothing was written"), "{err}");
}

#[test]
fn a_broken_headless_configuration_is_an_error_not_an_absence() {
    let err = choose_lpk(false, || Ok(OS_KEY), || {
        headless_lpk_from(Some("too-short".into()), None, |_| unreachable!())
    })
    .expect_err("a short secret must be refused");
    assert!(err.to_string().contains("too short"), "{err}");
}

// ---- choose_lpk: a persistent host (Windows / macOS) ------------------------

#[test]
fn a_persistent_os_keyring_that_answers_wins_over_a_configured_headless_secret() {
    let (key, source) = choose_lpk(true, || Ok(OS_KEY), headless_some).unwrap();
    assert_eq!(source, LpkSource::OsKeyring);
    assert_eq!(*key, OS_KEY);
}

#[test]
fn a_failing_persistent_os_keyring_falls_back_to_the_headless_secret() {
    let (key, source) = choose_lpk(true, os_unavailable, headless_some).unwrap();
    assert_eq!(source, LpkSource::Headless);
    assert_eq!(*key, *derive_headless_lpk(SECRET));
}

#[test]
fn a_failing_persistent_os_keyring_without_a_headless_secret_fails_closed() {
    let err = choose_lpk(true, os_unavailable, headless_none).unwrap_err().to_string();
    assert!(err.contains("Unknown(1)"), "the OS keyring's own error must be carried: {err}");
    assert!(err.contains(HEADLESS_LPK_ENV), "{err}");
}

#[test]
fn a_missing_minted_lpk_is_never_papered_over_with_the_headless_key() {
    let missing = || -> passkey_core::Result<[u8; 32]> {
        Err(PasskeyError::CredentialStore(format!(
            "{LPK_MISSING_MARKER}: the Local Protection Key minted for this install is missing"
        )))
    };
    let err = choose_lpk(true, missing, headless_some)
        .expect_err("switching keys silently would strand everything sealed under the lost one")
        .to_string();
    assert!(err.contains(LPK_MISSING_MARKER), "{err}");
}

// ---- headless_lpk_from ------------------------------------------------------

#[test]
fn the_headless_secret_is_derived_deterministically_and_trimmed() {
    let a = headless_lpk_from(Some(SECRET.into()), None, |_| unreachable!()).unwrap().unwrap();
    let b = headless_lpk_from(Some(format!("  {SECRET}\n")), None, |_| unreachable!())
        .unwrap()
        .unwrap();
    assert_eq!(*a, *b);
    assert_ne!(&a[..], &SECRET.as_bytes()[..32], "the raw secret is never the key");
    let other = derive_headless_lpk("another-headless-secret-that-is-long-enough");
    assert_ne!(*a, *other);
}

#[test]
fn unset_or_blank_headless_configuration_is_absent() {
    for (secret, file) in [
        (None, None),
        (Some(String::new()), None),
        (Some("   ".to_string()), Some(" ".to_string())),
    ] {
        assert!(headless_lpk_from(secret, file, |_| unreachable!()).unwrap().is_none());
    }
}

#[test]
fn a_secret_one_short_of_the_floor_is_refused_and_one_at_it_is_accepted() {
    let short = "x".repeat(HEADLESS_LPK_MIN_LEN - 1);
    let err = headless_lpk_from(Some(short), None, |_| unreachable!()).unwrap_err().to_string();
    assert!(err.contains("too short") && err.contains(HEADLESS_LPK_ENV), "{err}");
    assert!(headless_lpk_from(Some("x".repeat(HEADLESS_LPK_MIN_LEN)), None, |_| unreachable!())
        .unwrap()
        .is_some());
}

#[test]
fn the_secret_file_variant_derives_the_same_key_as_the_env_value() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("lpk-secret");
    std::fs::write(&path, format!("{SECRET}\n")).unwrap();
    let from_file = headless_lpk_from(None, Some(path.display().to_string()), |p| {
        std::fs::read_to_string(p)
    })
    .unwrap()
    .unwrap();
    assert_eq!(*from_file, *derive_headless_lpk(SECRET));
}

#[test]
fn an_unreadable_secret_file_is_refused_naming_the_file() {
    let err = headless_lpk_from(None, Some("/nonexistent/lpk".into()), |p| {
        std::fs::read_to_string(p)
    })
    .unwrap_err()
    .to_string();
    assert!(err.contains(HEADLESS_LPK_FILE_ENV) && err.contains("nonexistent"), "{err}");
}

#[test]
fn setting_both_the_secret_and_the_file_is_refused_as_ambiguous() {
    let err = headless_lpk_from(Some(SECRET.into()), Some("/x".into()), |_| unreachable!())
        .unwrap_err()
        .to_string();
    assert!(err.contains("exactly one"), "{err}");
}

// ---- the real seal path on a simulated host ---------------------------------

fn linux_host(secret: Option<&str>) -> TestHost {
    TestHost { os_keyring_persistent: false, headless_secret: secret.map(str::to_string) }
}

#[test]
fn wrap_at_rest_on_a_keyring_less_host_seals_under_the_headless_key() {
    keywrap::__set_test_host(Some(linux_host(Some(SECRET))));
    let plain = b"identity secret key bytes";
    let sealed = keywrap::wrap_at_rest(plain).expect("the headless secret must let the seal proceed");
    assert!(is_wrapped(&sealed));
    assert_eq!(
        unwrap_with_key(&sealed, &derive_headless_lpk(SECRET)).unwrap(),
        plain,
        "sealed under the derived headless key, which any process given the secret re-derives"
    );
    assert_eq!(keywrap::unwrap_at_rest(&sealed).unwrap(), plain);
    assert_eq!(keywrap::local_protection_source().unwrap(), LpkSource::Headless);
    keywrap::remint_local_protection_key().expect("a derived key has nothing to re-mint");
    assert_eq!(keywrap::unwrap_at_rest(&sealed).unwrap(), plain);
    keywrap::__set_test_host(None);
}

#[test]
fn wrap_at_rest_on_a_keyring_less_host_without_a_secret_refuses() {
    keywrap::__set_test_host(Some(linux_host(None)));
    let err = keywrap::wrap_at_rest(b"secret").unwrap_err().to_string();
    assert!(err.contains(HEADLESS_LPK_ENV), "{err}");
    keywrap::__set_test_host(None);
}

#[test]
fn a_seal_made_with_one_secret_does_not_open_with_another() {
    keywrap::__set_test_host(Some(linux_host(Some(SECRET))));
    let sealed = keywrap::wrap_at_rest(b"secret").unwrap();
    keywrap::__set_test_host(Some(linux_host(Some("a-different-headless-secret-0123456789"))));
    assert!(keywrap::unwrap_at_rest(&sealed).is_err());
    keywrap::__set_test_host(None);
}

#[test]
fn an_identity_saved_on_a_keyring_less_host_is_sealed_and_reloads_after_a_restart() {
    use passkey_core::identity::Identity;
    let dir = tempfile::TempDir::new().unwrap();
    keywrap::__set_test_host(Some(linux_host(Some(SECRET))));
    let identity = Identity::generate("headless@example.com").unwrap();
    identity.save_to(dir.path()).expect("the identity must save on a keyring-less host");
    let on_disk = std::fs::read(dir.path().join("secret.pgp")).unwrap();
    assert!(is_wrapped(&on_disk), "the secret key must never reach disk unsealed");

    // "Restart": a fresh thread given the same secret, nothing cached.
    let path = dir.path().to_path_buf();
    let fp = identity.fingerprint();
    std::thread::spawn(move || {
        keywrap::__set_test_host(Some(linux_host(Some(SECRET))));
        let reloaded = Identity::load_from(&path).expect("same secret, same key");
        assert_eq!(reloaded.fingerprint(), fp);
    })
    .join()
    .unwrap();
    keywrap::__set_test_host(None);
}

#[test]
fn an_identity_save_on_a_keyring_less_host_without_a_secret_writes_nothing() {
    use passkey_core::identity::Identity;
    let dir = tempfile::TempDir::new().unwrap();
    keywrap::__set_test_host(Some(linux_host(None)));
    let identity = Identity::generate("headless@example.com").unwrap();
    let err = identity.save_to(dir.path()).expect_err("fail closed").to_string();
    assert!(err.contains(HEADLESS_LPK_ENV), "{err}");
    assert!(!dir.path().join("secret.pgp").exists(), "no secret key file, sealed or not");
    keywrap::__set_test_host(None);
}
