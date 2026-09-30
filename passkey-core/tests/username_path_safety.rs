//! Usernames cannot reach outside `{config}/users/`.
//!
//! The first two tests drive a traversal delete and a traversal save through
//! the public API: both calls must be refused and the victim paths left
//! untouched. The rest pins the rule itself — the Cloud's registration
//! allowlist, the Desktop's reserved `_pending_new`, and the Windows shapes a
//! plain `PathBuf::join` mishandles.

use passkey_core::{
    create_user, delete_user, get_user_info, save_user_info, set_active_user, user_exists,
    user_has_identity, get_active_user, is_valid_user_dir_name, is_valid_username,
    validate_user_dir_name, validate_username, Identity, PasskeyConfig, UserInfo,
    RESERVED_USER_DIR_NAMES,
};
use passkey_core::identity::{delete_user_identity, ensure_identity_dir};
use tempfile::TempDir;

fn cfg(tmp: &TempDir) -> PasskeyConfig {
    PasskeyConfig::gitcellar().with_config_dir(tmp.path().join("gitcellar"))
}

/// Names that must be refused everywhere, for every entry point.
fn hostile_names(tmp: &TempDir) -> Vec<String> {
    let mut v: Vec<String> = [
        "",
        ".",
        "..",
        "../../victim-data",
        "..\\..\\victim-data",
        "a/b",
        "a\\b",
        "/etc",
        "C:\\x",
        "C:x",
        "C:/x",
        "\\\\server\\share",
        "//server/share",
        "\\\\?\\C:\\x",
        "alice\0",
        "alice:stream",
        "alice.",
        "CON",
        "nul",
        "Com1",
        "LPT9",
        "_pending_new/../../x",
        "_PENDING_NEW",
        "_shadow",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    v.push(tmp.path().join("elsewhere").to_string_lossy().into_owned());
    v
}

// ------------------------------------------------------ traversal attempts

/// A traversal delete and an absolute-path join are both refused, and the
/// victim directory survives.
#[test]
fn delete_user_traversal_is_refused() {
    let tmp = TempDir::new().unwrap();
    let cfg = cfg(&tmp);
    let victim = tmp.path().join("victim-data");
    std::fs::create_dir_all(&victim).unwrap();
    std::fs::write(victim.join("precious.txt"), b"x").unwrap();

    assert!(!user_exists(&cfg, "../../victim-data"), "a traversal name must not 'exist'");
    let err = delete_user(&cfg, "../../victim-data").expect_err("traversal delete must be refused");
    assert!(err.to_string().contains("invalid username"), "{err}");
    assert!(victim.join("precious.txt").exists(), "delete_user reached outside users/");

    // An absolute username no longer replaces the base path.
    let abs = tmp.path().join("elsewhere");
    std::fs::create_dir_all(&abs).unwrap();
    assert!(cfg.checked_user_dir(abs.to_str().unwrap()).is_err());
    assert!(cfg.checked_identity_dir(abs.to_str().unwrap()).is_err());
    assert!(delete_user(&cfg, abs.to_str().unwrap()).is_err());
    assert!(abs.exists());
}

/// Saving an identity under a traversal name writes nothing, anywhere.
#[test]
fn save_for_user_traversal_is_refused() {
    let tmp = TempDir::new().unwrap();
    let cfg = cfg(&tmp);
    #[cfg(feature = "keyring")]
    passkey_core::keywrap::__set_test_lpk(Some([1u8; 32]));
    let id = Identity::generate("x@example.com").unwrap();

    let err = id.save_for_user(&cfg, "../../outside").expect_err("traversal save must be refused");
    assert!(err.to_string().contains("invalid username"), "{err}");
    assert!(!tmp.path().join("outside").exists(), "save_for_user wrote outside users/");
    assert!(Identity::load_user(&cfg, "../../outside").is_err());
    assert!(!Identity::exists_for_user(&cfg, "../../outside"));

    // Control: the same identity saves and loads under a valid name.
    #[cfg(feature = "keyring")]
    {
        id.save_for_user(&cfg, "alice").unwrap();
        assert!(cfg.users_dir().join("alice").join("identity").join("secret.pgp").exists());
        assert_eq!(
            Identity::load_user(&cfg, "alice").unwrap().fingerprint(),
            id.fingerprint()
        );
        passkey_core::keywrap::__set_test_lpk(None);
    }
}

// ---------------------------------------------------------------- the rule

#[test]
fn username_rule_matches_the_cloud_registration_rule() {
    for ok in [
        "a", "Z", "0", "alice", "Alice", "ALICE", "a-b", "a1-b2-c3", "c003probe", "default",
        "com10", "console", "nulls", "lpt", "CON1X",
        "abcdefghijklmnopqrstuvwxyz0123456789abc", // 39
    ] {
        assert!(is_valid_username(ok), "{ok:?} should be a valid username");
        validate_username(ok).unwrap();
    }
    for bad in [
        "", "-a", "a-", "a--b", "a_b", "a.b", "a b", "él", "alice!", "a@b",
        "abcdefghijklmnopqrstuvwxyz0123456789abcd", // 40
    ] {
        assert!(!is_valid_username(bad), "{bad:?} should be refused");
        assert!(validate_username(bad).is_err());
    }
}

#[test]
fn windows_device_names_are_refused_in_any_case() {
    for dev in ["CON", "con", "Con", "PRN", "aux", "NUL", "nUl", "COM0", "com1", "COM9", "LPT0", "lpt1", "Lpt9"] {
        assert!(!is_valid_username(dev), "{dev:?} is a device name");
        assert!(!is_valid_user_dir_name(dev), "{dev:?} is a device name");
    }
}

#[test]
fn reserved_internal_names_are_directory_names_but_not_usernames() {
    assert!(RESERVED_USER_DIR_NAMES.contains(&"_pending_new"));
    for r in RESERVED_USER_DIR_NAMES {
        assert!(r.starts_with('_'), "reserved names must be outside the username space");
        assert!(!is_valid_username(r), "{r:?} must not pass as an account name");
        validate_user_dir_name(r).unwrap();
    }
    // Exact and case-sensitive: near misses stay refused.
    for near in ["_pending_new ", " _pending_new", "_Pending_New", "_PENDING_NEW", "_pending", "_pending_new2", "_shadow", "_"] {
        assert!(!is_valid_user_dir_name(near), "{near:?} is not a reserved name");
    }
}

#[test]
fn every_hostile_name_is_refused_by_the_validators() {
    let tmp = TempDir::new().unwrap();
    for bad in hostile_names(&tmp) {
        assert!(!is_valid_user_dir_name(&bad), "{bad:?} passed validate_user_dir_name");
        assert!(!is_valid_username(&bad), "{bad:?} passed validate_username");
    }
}

// ---------------------------------------------------------------- the entry points

#[test]
fn every_path_writing_entry_point_refuses_hostile_names() {
    let tmp = TempDir::new().unwrap();
    let cfg = cfg(&tmp);
    let info = UserInfo::default();
    let before = snapshot(tmp.path());

    for bad in hostile_names(&tmp) {
        assert!(cfg.checked_user_dir(&bad).is_err(), "checked_user_dir({bad:?})");
        assert!(create_user(&cfg, &bad).is_err(), "create_user({bad:?})");
        assert!(delete_user(&cfg, &bad).is_err(), "delete_user({bad:?})");
        assert!(save_user_info(&cfg, &bad, &info).is_err(), "save_user_info({bad:?})");
        assert!(set_active_user(&cfg, &bad).is_err(), "set_active_user({bad:?})");
        assert!(ensure_identity_dir(&cfg, &bad).is_err(), "ensure_identity_dir({bad:?})");
        assert!(delete_user_identity(&cfg, &bad).is_err(), "delete_user_identity({bad:?})");
        assert!(Identity::load_user(&cfg, &bad).is_err(), "load_user({bad:?})");
        // Read-side probes answer "no" rather than erroring.
        assert!(!user_exists(&cfg, &bad), "user_exists({bad:?})");
        assert!(!user_has_identity(&cfg, &bad), "user_has_identity({bad:?})");
        assert!(!Identity::exists_for_user(&cfg, &bad), "exists_for_user({bad:?})");
        assert!(get_user_info(&cfg, &bad).is_none(), "get_user_info({bad:?})");
    }

    assert_eq!(snapshot(tmp.path()), before, "a refused call touched the filesystem");
    assert!(get_active_user(&cfg).is_none(), "a refused set_active_user wrote the pointer");
}

/// The Desktop's staging flow (`create_user("_pending_new")`,
/// `set_active_user("_pending_new")`, `user_exists("_pending_new")`) still works
/// end to end, and the directory lands directly under users/.
#[test]
fn pending_new_staging_flow_still_works() {
    let tmp = TempDir::new().unwrap();
    let cfg = cfg(&tmp);
    let pending = "_pending_new";

    assert!(!user_exists(&cfg, pending));
    create_user(&cfg, pending).unwrap();
    assert!(user_exists(&cfg, pending));
    assert_eq!(cfg.checked_user_dir(pending).unwrap(), cfg.users_dir().join(pending));
    assert!(cfg.users_dir().join(pending).join("identity").is_dir());

    set_active_user(&cfg, pending).unwrap();
    assert_eq!(get_active_user(&cfg).as_deref(), Some(pending));
    save_user_info(&cfg, pending, &UserInfo::default()).unwrap();
    assert!(get_user_info(&cfg, pending).is_some());

    // list_users is unchanged: it still reports the staging directory.
    assert_eq!(passkey_core::list_users(&cfg), vec![pending.to_string()]);

    delete_user(&cfg, pending).unwrap();
    assert!(!user_exists(&cfg, pending));
    assert!(get_active_user(&cfg).is_none(), "deleting the active user clears the pointer");
}

#[test]
fn mixed_case_usernames_are_accepted_as_the_cloud_accepts_them() {
    let tmp = TempDir::new().unwrap();
    let cfg = cfg(&tmp);
    create_user(&cfg, "Alice-2").unwrap();
    set_active_user(&cfg, "Alice-2").unwrap();
    assert!(user_exists(&cfg, "Alice-2"));
    assert_eq!(cfg.checked_user_dir("Alice-2").unwrap(), cfg.users_dir().join("Alice-2"));
}

/// A `users/<name>` entry that is a link to a directory elsewhere is refused
/// by the resolved-path check, so `delete_user` cannot follow it out.
#[cfg(unix)]
#[test]
fn a_user_dir_linked_outside_users_is_refused() {
    let tmp = TempDir::new().unwrap();
    let cfg = cfg(&tmp);
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::create_dir_all(cfg.users_dir()).unwrap();
    std::os::unix::fs::symlink(&outside, cfg.users_dir().join("mallory")).unwrap();
    assert!(cfg.checked_user_dir("mallory").is_err());
    assert!(delete_user(&cfg, "mallory").is_err());
    assert!(outside.exists());
}

fn snapshot(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p.clone());
                }
                out.push(p);
            }
        }
    }
    out.sort();
    out
}
