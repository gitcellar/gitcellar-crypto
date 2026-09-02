# passkey-core

Cross-platform PassKey-native authentication library providing Ed25519 identity management, challenge-response authentication, and BIP39 recovery codes.

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

- `keyring` (default) - OS keyring integration
- `jwt` (default) - JWT token support
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
