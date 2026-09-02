# gitcellar-identity

GitCellar-specific wrapper for the `passkey-core` identity management library.

## Purpose

This crate provides GitCellar-specific defaults for identity management:

- **App name**: `gitcellar`
- **Machine ID prefix**: `gcm` (e.g., `gcm-a1b2c3d4`)
- **Config directory**: Platform-specific (`~/.config/gitcellar` or `%APPDATA%\gitcellar`)

All identity functionality comes from `passkey-core`, which handles:

- Ed25519/X25519 key generation
- BIP39 recovery phrases (24-word mnemonic)
- Multi-user identity management
- Identity state machine validation
- Keyring integration (optional)

## Architecture

```
passkey-core (reusable identity library)
    |
    v
gitcellar-identity (this crate - applies GitCellar defaults)
    |
    v
gitcellar-crypto (adds encryption, re-exports identity types)
```

## Usage

### Quick Start

```rust
use gitcellar_identity::{Identity, config};
use gitcellar_identity::multi_user::{evaluate_state, IdentityState};

// Get GitCellar-configured settings
let cfg = config();

match evaluate_state() {
    IdentityState::Ready { username } => {
        let identity = Identity::load_user(&cfg, &username)?;
        let machine_id = gitcellar_identity::machine_id(&identity);
        println!("Machine ID: {}", machine_id);
    }
    IdentityState::NoIdentity => {
        // Show onboarding...
    }
    _ => {}
}
```

### Generate and Save Identity

```rust
use gitcellar_identity::{Identity, config};
use gitcellar_identity::multi_user::{create_user, set_active_user};

// Create user directory
create_user("alice")?;
set_active_user("alice")?;

// Generate identity
let identity = Identity::generate("alice@example.com")?;

// Save to user directory
identity.save_for_user(&config(), "alice")?;
```

### Recovery Codes

```rust
use gitcellar_identity::recovery::{generate_recovery_code, RecoveryCode};

// Generate 24-word BIP39 phrase
let code = generate_recovery_code()?;
println!("Backup your recovery phrase:\n{}", code.format_with_numbers());

// Derive key material for cloud backup
let key_material = code.derive_key_material();

// Later: restore from phrase
let restored = RecoveryCode::from_phrase("word1 word2 ... word24")?;
```

## API

### Module `gitcellar_identity::identity`

```rust
fn generate(user_id: &str) -> Result<Identity>;
fn load(username: &str) -> Result<Identity>;
fn load_active() -> Result<Identity>;
fn exists(username: &str) -> bool;
fn save(identity: &Identity, username: &str) -> Result<()>;
```

### Module `gitcellar_identity::multi_user`

```rust
fn evaluate_state() -> IdentityState;
fn repair_state() -> Result<IdentityState>;
fn list_users() -> Vec<String>;
fn get_active_user() -> Option<String>;
fn set_active_user(username: &str) -> Result<()>;
fn clear_active_user() -> Result<()>;
fn is_multi_user() -> bool;
fn create_user(username: &str) -> Result<()>;
fn delete_user(username: &str) -> Result<()>;
fn user_exists(username: &str) -> bool;
fn user_has_identity(username: &str) -> bool;
fn get_user_info(username: &str) -> Option<UserInfo>;
fn save_user_info(username: &str, info: &UserInfo) -> Result<()>;
```

### Module `gitcellar_identity::auth`

```rust
fn derive_machine_id(identity: &Identity) -> String;
fn derive_machine_id_from_public_key(public_key: &str) -> Result<String>;
fn verify_machine_id(public_key: &str, claimed: &str) -> Result<bool>;
fn is_valid_machine_id(machine_id: &str) -> bool;
```

### Module `gitcellar_identity::recovery`

```rust
fn generate_recovery_code() -> Result<RecoveryCode>;
fn is_valid_phrase(phrase: &str) -> bool;
fn find_invalid_words(phrase: &str) -> Vec<String>;
```

## Related Crates

- `passkey-core` - The underlying identity library (generic, reusable)
- `gitcellar-crypto` - Encryption library (re-exports identity types)
- `gitcellar-service` - Uses identity for authentication
- `gitcellar-desktop` - Uses identity for user management

## Design Documents

- Security whitepaper — https://gitcellar.com/security/whitepaper
- Identity state machine — startup identity validation (internal design document)
- Multi-user architecture — per-user identity directories (internal design document)
- gckey and passkey architecture — passkey-first design (internal design document)
