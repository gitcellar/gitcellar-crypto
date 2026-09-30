//! Username validation: the one guard between a username and a filesystem path.
//!
//! Every public entry point that turns a username into a path under
//! `{config}/users/` — or writes the `active_user` pointer — goes through
//! [`validate_user_dir_name`] (via [`PasskeyConfig::checked_user_dir`]). Before
//! this existed, `PathBuf::join` let `../../x` walk out of `users/` and an
//! absolute name (`C:\x`, `\\server\share`, `/etc`) replace the base path
//! outright.
//!
//! Two rules, deliberately separate:
//!
//! - [`validate_username`] — the account-name rule, identical to the Cloud's
//!   registration rule (`is_valid_username` in the Cloud's onboarding route):
//!   1–39 ASCII alphanumerics and single interior dashes, starting and ending
//!   with an alphanumeric. Case is preserved and both cases are allowed, as the
//!   Cloud allows. Windows reserved device names are refused on top, because
//!   `CON` or `nul` pass an alphanumeric allowlist yet do not name a directory.
//! - [`validate_user_dir_name`] — the directory rule: a valid username, **or**
//!   one of the exact [`RESERVED_USER_DIR_NAMES`] the application itself uses
//!   for internal state. A reserved name starts with `_`, which no account name
//!   can, so the two sets never collide.

use crate::error::{PasskeyError, Result};

/// Longest account name the Cloud registers.
pub const MAX_USERNAME_LEN: usize = 39;

/// Internal user-directory names that are not account names but are created
/// through the same library paths.
///
/// `_pending_new` is the GitCellar Desktop's staging directory for an identity
/// being created or paired before the account name is known (`create_user`,
/// `set_active_user`, `user_exists` are all called with it). It is renamed to the
/// real username on success. Add a name here only when an application creates
/// it through this library; every entry must start with `_`.
pub const RESERVED_USER_DIR_NAMES: &[&str] = &["_pending_new"];

/// Windows reserved device names. A path component equal to one of these
/// (case-insensitively) addresses a device, not a file or directory.
const WINDOWS_DEVICE_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL",
    "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn invalid(name: &str, why: &str) -> PasskeyError {
    PasskeyError::Other(format!("invalid username {:?}: {}", name, why))
}

/// Validate an account username.
///
/// Accepts exactly what the Cloud registers: 1–39 characters, ASCII letters
/// (either case) and digits, with single dashes allowed only between
/// alphanumerics (no leading, trailing or doubled dash). Additionally refuses
/// Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`,
/// `LPT0`–`LPT9`, any case).
///
/// Everything else — empty, `.`, `..`, separators, drive prefixes, UNC paths,
/// non-ASCII, underscores — is refused, so a name that passes is always a
/// single, plain path component.
pub fn validate_username(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(invalid(name, "empty"));
    }
    if name.len() > MAX_USERNAME_LEN {
        return Err(invalid(name, "longer than 39 characters"));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(invalid(name, "only ASCII letters, digits and '-' are allowed"));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(invalid(name, "must start and end with a letter or digit"));
    }
    if name.contains("--") {
        return Err(invalid(name, "consecutive dashes"));
    }
    if WINDOWS_DEVICE_NAMES.iter().any(|d| d.eq_ignore_ascii_case(name)) {
        return Err(invalid(name, "a reserved device name"));
    }
    Ok(())
}

/// Whether `name` passes [`validate_username`].
pub fn is_valid_username(name: &str) -> bool {
    validate_username(name).is_ok()
}

/// Validate a name used as a directory under `{config}/users/`: a valid
/// username ([`validate_username`]) or an exact entry of
/// [`RESERVED_USER_DIR_NAMES`]. The reserved match is exact and case-sensitive.
pub fn validate_user_dir_name(name: &str) -> Result<()> {
    if RESERVED_USER_DIR_NAMES.contains(&name) {
        return Ok(());
    }
    validate_username(name)
}

/// Whether `name` passes [`validate_user_dir_name`].
pub fn is_valid_user_dir_name(name: &str) -> bool {
    validate_user_dir_name(name).is_ok()
}
