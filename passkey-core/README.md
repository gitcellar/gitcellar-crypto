# passkey-core

## Summary

The identity library underneath GitCellar's no-password authentication: Ed25519/X25519 certificate generation and on-disk multi-user storage, challenge/signature verification, BIP39 24-word recovery codes and their HKDF derivation, stable machine IDs, at-rest key wrap, and the OS-keyring credential store.

Encryption *using* that identity (`.gckey` transfer, identity backup) is `gitcellar-crypto`, reached through `gitcellar-identity`; per-chunk sealing is `vault-core`. "PassKey" here means this Ed25519 keypair, not the WebAuthn browser API, which GitCellar does not use.

Authentication challenges are signed through `challenge_signing_payload`: the client refuses anything that is not a 64-hex nonce and signs it under a purpose tag (`gc-auth-login-v1`, `gc-auth-registration-pop-v1`), never raw. The server is untrusted, and the same key signs other objects.

Cross-platform PassKey-native authentication library providing Ed25519 identity management, challenge-response authentication, and BIP39 recovery codes.

## File Index

| Entry | Purpose |
|---|---|
| `Cargo.toml` | Crate manifest. |
| `src/` | The library, one module per concern. |
| `tests/` | Cargo integration tests, one binary per file (at-rest fail-closed, v4 cert profile, headless Local Protection Key, username path safety). Consumed by `cargo test`; not a module. |

## Features

- **Identity Management** - Generate, load, and save Ed25519/X25519 OpenPGP certificates
- **Challenge-Response Auth** - Cryptographic signature verification without passwords
- **BIP39 Recovery** - 24-word mnemonic phrases for account recovery
- **Multi-User Support** - Multiple identities on a single machine
- **Credential Store** - OS-native keyring integration (Windows Credential Manager, macOS Keychain, Linux Secret Service)
- **JWT Support** - Token generation and validation (optional)

## Quick Start

```rust
use passkey_core::{Identity, PasskeyConfig, generate_recovery_code};
use passkey_core::multi_user::{evaluate_state, IdentityState};

// Configure for your application
let config = PasskeyConfig::new("myapp");

// Check current identity state
match evaluate_state(&config) {
    IdentityState::NoIdentity => {
        // Onboarding flow
        let identity = Identity::generate("user@example.com")?;
        let recovery = generate_recovery_code()?;
        println!("Save this recovery phrase:\n{}", recovery.format_for_display());

        // Save identity
        passkey_core::create_user(&config, "username")?;
        identity.save_for_user(&config, "username")?;
        passkey_core::set_active_user(&config, "username")?;
    }
    IdentityState::Ready { username } => {
        println!("Ready with user: {}", username);
        let identity = Identity::load_user(&config, &username)?;
    }
    // ... handle other states
    _ => {}
}
```

## Directory Structure

passkey-core uses a multi-user directory structure:

```
{config_dir}/
├── active_user           # Current username
├── machine_id            # Machine identifier
└── users/
    └── {username}/
        ├── identity/
        │   ├── secret.pgp
        │   └── public.pgp
        └── user_info.json
```

### Usernames are validated before they become paths

A username is joined into `users/{username}/`, so an unchecked one could walk out of `users/` (`../../x`) or, as an absolute path (`C:\x`, `\\server\share`), replace the base path entirely. Every function here that turns a username into a path or writes `active_user` validates it first, and `tests/username_path_safety.rs` pins that.

- **`validate_username(&str) -> Result<()>`** (and `is_valid_username`) is the account-name rule. It is the Cloud's registration rule: 1–39 ASCII letters (either case) and digits, with single dashes only between them. It also refuses the Windows device names `CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9` and `LPT0`–`LPT9`, in any case.
- **`validate_user_dir_name(&str) -> Result<()>`** (and `is_valid_user_dir_name`) accepts a valid username or an exact entry of `RESERVED_USER_DIR_NAMES`. Today that list is only `_pending_new`, the Desktop's staging directory. A reserved name starts with `_`, which no username can.
- **`PasskeyConfig::checked_user_dir(name) -> Result<PathBuf>`** and `checked_identity_dir` validate the name, join it, and check the result is a direct child of `users_dir()`. When the path exists, the check is repeated after links are resolved. `user_dir`, `identity_dir`, `user_data_path` and `user_info_path` remain **unchecked** path builders.
- **Enforced in** `create_user`, `delete_user`, `save_user_info`, `set_active_user`, `Identity::save_for_user`, `Identity::load_user`, `ensure_identity_dir` and `delete_user_identity`, which return an `invalid username` error (`PasskeyError::Other`) and touch nothing. The read-side probes `user_exists`, `user_has_identity`, `Identity::exists_for_user` and `get_user_info` answer `false` or `None`. `list_users` and `get_active_user` are unchanged: they report what is on disk.

## Authentication Flow

passkey-core eliminates passwords by using Ed25519 keypairs:

1. **Client** generates an Ed25519 identity (stored locally)
2. **Client** exports public key and sends to server
3. **Server** generates a random challenge
4. **Client** signs challenge with private key
5. **Server** verifies signature with client's public key

```rust
use passkey_core::auth::{generate_challenge, verify_detached_signature};

// Server generates challenge
let challenge = generate_challenge();

// Client signs (requires signing implementation)
// let signature = sign_data(&identity, challenge.as_bytes());

// Server verifies
let public_key = identity.export_public_key()?;
let valid = verify_detached_signature(&public_key, challenge.as_bytes(), &signature)?;
```

## Machine ID

Derive stable machine identifiers from identity fingerprints:

```rust
use passkey_core::auth::{derive_machine_id_from_identity, is_valid_machine_id};

let machine_id = derive_machine_id_from_identity(&config, &identity);
// Returns: "mya-<fingerprint hex>" (prefix + the key's whole fingerprint, lowercased)

assert!(is_valid_machine_id(&config, &machine_id));
```

## Recovery Codes

Generate BIP39 24-word mnemonic phrases for account recovery:

```rust
use passkey_core::{generate_recovery_code, RecoveryCode};

// Generate new recovery code
let code = generate_recovery_code()?;
println!("{}", code.format_with_numbers());

// Derive key material for encrypting backups
// (domain-separated HKDF-SHA256 over the BIP39 seed,
//  info = "gitcellar-passkey-recovery-v1" — see RecoveryKeyDerivation)
let key = code.derive_key_material();

// Later, restore from phrase
let restored = RecoveryCode::from_phrase("word1 word2 ... word24")?;
```

## Credential Store

Store tokens securely using OS-native credential storage:

```rust
use passkey_core::CredentialStore;

let store = CredentialStore::new(&config);

// Store credentials
store.store_access_token("jwt_token")?;
store.store_user_id("user_uuid")?;

// Retrieve
if store.is_logged_in() {
    let token = store.get_access_token()?;
}

// Logout
store.clear_all()?;
```

## Features

- `keyring` (default) - At-rest sealing under the Local Protection Key, which comes from the OS keyring or, on a keyring-less or non-persistent host, from the headless secret (see below). **Saving an identity requires it.** The secret key is always sealed under the Local Protection Key, and there is no plaintext write. A build without `keyring`, or a seal that fails, refuses the save (`Identity::save_to`, `seal_secret_key`).
- `jwt` (default) - JWT token support

### The Local Protection Key is never silently re-minted

`keywrap::resolve_lpk` sets the policy, and `tests/at_rest_fail_closed.rs` pins it:
- **Opening sealed data never mints.**
- **Sealing mints only on an install that never minted one.** The record of that is the `lpk-v1.minted` marker in the identity root.
- **A lost LPK is an `LPK_MISSING` error.**
- **The only way past that error is to call `remint_local_protection_key`,** which the Desktop does only when it restores an identity from its recovery phrase.

Tests that save an identity where there is no OS keyring install a per-thread key with `keywrap::__set_test_lpk`, or simulate a keyring-less host with `keywrap::__set_test_host`.

### Where the Local Protection Key lives on each OS

`keywrap::choose_lpk` sets this policy, and `tests/headless_lpk.rs` pins it:
- **Windows and macOS: the OS keyring (DPAPI / Keychain) comes first.** The headless secret is used only when the keyring fails.
- **Linux: only the headless secret, and the kernel keyring is never called.** This build's Linux backend is keyutils. It keeps the key only in the session keyring, so the key is lost at logout, reboot or container restart. Docker's default seccomp profile also blocks keyutils outright.
- **The headless secret is `GITCELLAR_HEADLESS_LPK_SECRET`,** or a file named by `GITCELLAR_HEADLESS_LPK_SECRET_FILE` (a Docker or systemd secret). It must be at least 32 characters, and setting both is refused. The key is HKDF-derived from it (`derive_headless_lpk`), never minted. Every process that opens the same keys needs the same value. The Service's repo-key keyring derives its passphrase the same way, so the identity, the device key and the repo keyring on one host share one key.
- **With neither, sealing fails closed.** The error names both variables, and nothing is written.
- **A lost keyring LPK (`LPK_MISSING`) is never replaced by the headless key.** It stays the error it is.

**No Linux Desktop build ships.** The Desktop bundle is a Windows installer only, so a Linux host is a server or a CI container, and its operator sets the secret. If a Linux Desktop ever ships, it needs a persistent store first, such as Secret Service via keyring's `sync-secret-service` feature. Until then a Linux Desktop user sees the fail-closed error, which says which variable to set.
- `ffi` - C-compatible FFI exports

```toml
[dependencies]
passkey-core = { version = "0.1", default-features = false, features = ["keyring"] }
```

## Platform Support

- Windows (CNG crypto backend)
- macOS (Nettle crypto backend)
- Linux (Nettle crypto backend)

## License

MIT OR Apache-2.0, at your option.
