# gitcellar-crypto

Encryption library for GitCellar - Sequoia-based encryption with identity from passkey-core.

## Purpose

This crate provides encryption functionality for GitCellar:

- **Encryption/decryption**: Encrypt and decrypt data using the identity
- **Key transfer**: Export/import identities via .gckey files
- **Cloud backup**: Encrypted identity backup with recovery codes

Identity management (generation, loading, multi-user support) is handled by `gitcellar-identity`, which wraps the reusable `passkey-core` library. This crate re-exports identity types for convenience.

## Architecture

```
passkey-core (reusable identity library)
    |
    v
gitcellar-identity (GitCellar defaults: app_name="gitcellar", prefix="gcm")
    |
    v
gitcellar-crypto (encryption + re-exports identity types)
```

## Key Storage

Keys are stored in the GitCellar config directory with multi-user support:

| Platform | Location |
|----------|----------|
| Windows | `C:\Users\{user}\AppData\Roaming\gitcellar\users\{username}\identity\` |
| macOS/Linux | `~/.config/gitcellar/users/{username}/identity/` |

Files per user:
- `secret.pgp` - OpenPGP secret key (contains both public and private material)
- `public.pgp` - OpenPGP public key (for sharing)

## Usage

### Generate a New Identity

```rust
use gitcellar_crypto::Identity;

// Generate a new identity with Ed25519/X25519 keys
let identity = Identity::generate("user@example.com")?;

// Save to the standard location
identity.save()?;

// Get the fingerprint
println!("Fingerprint: {}", identity.fingerprint());
```

### Encrypt/Decrypt Data

```rust
use gitcellar_crypto::EncryptionEngine;

// Create engine from the default identity location
let engine = EncryptionEngine::from_default_identity()?;

// Encrypt data
let encrypted = engine.encrypt_data(b"secret data")?;

// Decrypt data
let decrypted = engine.decrypt_data(&encrypted)?;
assert_eq!(decrypted, b"secret data");
```

### Encrypt Chunks (for large files)

```rust
use gitcellar_crypto::EncryptionEngine;
use vault_core::chunking::{ChunkEngine, ChunkConfig};

let engine = EncryptionEngine::from_default_identity()?;
let chunk_engine = ChunkEngine::new(ChunkConfig::default());

// Split large data into chunks
let chunks = chunk_engine.chunk_data(&large_data)?;

// Encrypt chunks in parallel
let encrypted_chunks = engine.encrypt_chunks_parallel(&chunks).await?;

// Decrypt chunks in parallel
let decrypted_chunks = engine.decrypt_chunks_parallel(&encrypted_chunks).await?;
```

### Transfer Identity Between Machines (.gckey)

The `.gckey` file format provides a portable backup of your identity. Following
the principle that "a locked key is an oxymoron," gckey files are NOT password-
protected - the file itself IS the key. Store it securely.

```rust
use gitcellar_crypto::{Identity, IdentityBundle};

// On source machine: Export identity
let identity = Identity::load()?;
let gckey_data = IdentityBundle::export(&identity)?;
std::fs::write("backup.gckey", &gckey_data)?;

// On target machine: Import from .gckey file
let gckey_data = std::fs::read_to_string("backup.gckey")?;
let identity = IdentityBundle::import(&gckey_data)?;
identity.save()?;
```

See `docs/architecture/identity/GCKEY_AND_PASSKEY_ARCHITECTURE.md` for the full design.

## Public API

### Identity

```rust
impl Identity {
    fn generate(user_id: &str) -> Result<Self>;
    fn load() -> Result<Self>;
    fn load_from(path: &Path) -> Result<Self>;
    fn exists() -> bool;
    fn save(&self) -> Result<()>;
    fn save_to(&self, path: &Path) -> Result<()>;
    fn fingerprint(&self) -> String;
    fn key_id(&self) -> String;
    fn user_id(&self) -> &str;
    fn export_public_key(&self) -> Result<String>;
    fn export_secret_key(&self) -> Result<String>;
    fn from_armored_secret_key(armored: &str) -> Result<Self>;
}
```

### EncryptionEngine

```rust
impl EncryptionEngine {
    fn new(identity: Identity) -> Result<Self>;
    fn from_default_identity() -> Result<Self>;
    fn fingerprint(&self) -> String;
    fn key_id(&self) -> String;
    fn export_public_key(&self) -> Result<String>;
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>>;
    fn encrypt_chunk(&self, chunk: &Chunk) -> Result<Vec<u8>>;
    fn decrypt_chunk(&self, encrypted_data: &[u8]) -> Result<Vec<u8>>;
    async fn encrypt_chunks_parallel(&self, chunks: &[Chunk]) -> Result<Vec<Vec<u8>>>;
    async fn decrypt_chunks_parallel(&self, encrypted_chunks: &[Vec<u8>]) -> Result<Vec<Vec<u8>>>;
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>>;
}
```

### IdentityBundle

```rust
impl IdentityBundle {
    /// Export identity to .gckey format (v3.0, unprotected)
    fn export(identity: &Identity) -> Result<String>;

    /// Import identity from .gckey format (v2.0 or v3.0)
    fn import(gckey_content: &str) -> Result<Identity>;
}
```

## Algorithms

- **Primary key**: Ed25519 (signing)
- **Encryption subkey**: X25519 (ECDH key agreement)
- **Symmetric encryption**: AES-256 (for data encryption)
- **Cloud backup encryption**: AES-256-GCM with recovery-code-derived keys

## Dependencies

This crate uses platform-specific cryptographic backends for Sequoia:

- **Windows**: CNG (Cryptography API: Next Generation)
- **Unix**: Nettle

## Related Crates

- `passkey-core` - Reusable identity management library (Ed25519/X25519, BIP39 recovery)
- `gitcellar-identity` - GitCellar-specific wrapper for passkey-core
- `gitcellar-cli` - Uses this crate for CLI encryption operations
- `gitcellar-service` - Uses this crate for service encryption operations
- `vault-core` - Provides chunking for large files

## Cloud Backup (Recovery Codes)

The crate also provides cloud backup functionality for identity recovery:

### RecoveryCode

```rust
use gitcellar_crypto::{generate_recovery_code, RecoveryCode};

// Generate a new 24-word BIP39 recovery code
let code = generate_recovery_code()?;
println!("Recovery code:\n{}", code.format_with_numbers());

// Derive key material for encryption
let key_material = code.derive_key_material();

// Later: Parse from user input
let code = RecoveryCode::from_phrase("word1 word2 ... word24")?;
```

### CloudBackupBundle

```rust
use gitcellar_crypto::{CloudBackupBundle, Identity};

// Create backup encrypted with recovery code
let identity = Identity::load()?;
let key_material = code.derive_key_material();
let bundle = CloudBackupBundle::create_with_recovery_code(&identity, &key_material)?;

// Serialize for upload to cloud
let json = bundle.to_json()?;

// Later: Restore from backup
let bundle = CloudBackupBundle::from_json(&json)?;
let recovered_identity = bundle.decrypt_with_recovery_code(&key_material)?;
```

See `docs/architecture/encryption/DUAL_RECOVERY_MECHANISM.md` for full specification.

## Design Documents

- `docs/architecture/encryption/ENCRYPTION_SYSTEM_ARCHITECTURE.md` - Core encryption system architecture (encryption redesign, state machine, Sequoia rationale)
- `docs/architecture/identity/GCKEY_AND_PASSKEY_ARCHITECTURE.md` - Passkey-first key management and gckey design rationale
