# gitcellar-crypto

Encryption library for GitCellar — Sequoia-based OpenPGP identity, with chunk sealing delegated to `vault-core`.

## Purpose

This crate provides:

- **Identity-bound encryption/decryption**: encrypt and decrypt data under the user's OpenPGP identity
- **Chunk paths**: derives the per-repo content key and drives `vault-core`'s XChaCha20-Poly1305 chunk engine, binding each chunk's identity into the AEAD
- **Key transfer**: export/import identities via `.gckey` files
- **Cloud backup**: encrypted identity backup unlocked by a 24-word recovery code

Identity management (generation, loading, multi-user support) is handled by `gitcellar-identity`, which wraps the reusable `passkey-core` library. This crate re-exports identity types for convenience.

## Architecture

```
passkey-core (reusable identity library)
    |
    v
gitcellar-identity (GitCellar defaults: app_name="gitcellar", prefix="gcm")
    |
    v
gitcellar-crypto (identity, key grants, cloud backup)
    |
    v
vault-core (chunking + XChaCha20-Poly1305 chunk AEAD + storage)
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
use gitcellar_identity::identity;

// Generate a new identity with Ed25519/X25519 keys
let identity = Identity::generate("user@example.com")?;

// Save it under a username in the standard per-user location
identity::save(&identity, "alice")?;

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

### Encrypt Chunks (repository content)

Chunks are sealed with **XChaCha20-Poly1305** under a per-repo content key derived
with HKDF-SHA256 — not with the OpenPGP identity key, and not with AES-GCM. Each
chunk's identity (repository, chunk name, size) is bound into the AEAD as
associated data, so a stored chunk only opens under the identity it was sealed
with; a spliced or wrong-repo chunk fails authentication rather than decrypting.

```rust
use gitcellar_crypto::EncryptionEngine;
use vault_core::chunking::{ChunkEngine, ChunkConfig};

let engine = EncryptionEngine::from_default_identity()?;
let chunk_engine = ChunkEngine::new(ChunkConfig::default());

// Split large data into chunks
let chunks = chunk_engine.chunk_data(&large_data)?;

// Seal chunks in parallel, each bound to its repository identity
let encrypted_chunks = engine.encrypt_chunks_parallel(repo_id, &chunks).await?;

// Open them again, authenticating against the same identities
let decrypted_chunks = engine.decrypt_chunks_parallel(&encrypted_chunks, &aads).await?;
```

### Transfer Identity Between Machines (.gckey)

The `.gckey` file format provides a portable backup of your identity. Following
the principle that "a locked key is an oxymoron," gckey files are NOT password-
protected - the file itself IS the key. Store it securely.

```rust
use gitcellar_crypto::{Identity, IdentityBundle};

// On source machine: Export identity
let identity = gitcellar_identity::identity::load("alice")?;
let gckey_data = IdentityBundle::export(&identity)?;
std::fs::write("backup.gckey", &gckey_data)?;

// On target machine: Import from .gckey file
let gckey_data = std::fs::read_to_string("backup.gckey")?;
let identity = IdentityBundle::import(&gckey_data)?;
gitcellar_identity::identity::save(&identity, "alice")?;
```

## Public API

### Identity

```rust
impl Identity {
    fn generate(user_id: &str) -> Result<Self>;
    fn load_from(path: &Path) -> Result<Self>;
    fn load_user(config: &PasskeyConfig, username: &str) -> Result<Self>;
    fn exists_for_user(config: &PasskeyConfig, username: &str) -> bool;
    fn save_to(&self, path: &Path) -> Result<()>;
    fn save_for_user(&self, config: &PasskeyConfig, username: &str) -> Result<()>;
    fn fingerprint(&self) -> String;
    fn key_id(&self) -> String;
    fn user_id(&self) -> &str;
    fn export_public_key(&self) -> Result<String>;
    fn export_secret_key(&self) -> Result<String>;
    fn from_armored_secret_key(armored: &str) -> Result<Self>;
}
```

`gitcellar_identity::identity::{generate, load, load_active, exists, save}` wrap the same calls
with GitCellar's app defaults, keyed by username.

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

    // Chunk sealing: XChaCha20-Poly1305, identity bound as AEAD associated data
    fn encrypt_chunk(&self, chunk: &Chunk, aad: &ChunkAad) -> Result<Vec<u8>>;
    fn decrypt_chunk(&self, encrypted_data: &[u8], aad: &ChunkAad) -> Result<Vec<u8>>;
    async fn encrypt_chunks_parallel(&self, repo_id: &str, chunks: &[Chunk]) -> Result<Vec<Vec<u8>>>;
    async fn decrypt_chunks_parallel(&self, encrypted_chunks: &[Vec<u8>], aads: &[ChunkAad]) -> Result<Vec<Vec<u8>>>;

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

| Purpose | Algorithm |
|---------|-----------|
| Primary key (signing) | Ed25519 |
| Encryption subkey | X25519 (ECDH key agreement) |
| Chunk sealing — your repository's file contents | XChaCha20-Poly1305 AEAD, 24-byte nonce, per-repo content key derived via HKDF-SHA256, chunk identity bound as associated data. Implemented by `vault-core`'s `XChaChaChunkEngine`; this crate holds the identity and key-grant paths |
| Cloud backup bundles, identity bundles, keys at rest | AES-256-GCM with HKDF-SHA256-derived keys (recovery-code-derived for cloud backup). **Not the chunk path** |
| Recovery codes | BIP39 24-word mnemonic |

## Dependencies

This crate uses platform-specific cryptographic backends for Sequoia:

- **Windows**: CNG (Cryptography API: Next Generation)
- **Unix**: Nettle

## Related Crates

- `passkey-core` - Reusable identity management library (Ed25519/X25519, BIP39 recovery)
- `gitcellar-identity` - GitCellar-specific wrapper for passkey-core
- `vault-core` - Content-defined chunking, XChaCha20-Poly1305 chunk AEAD, S3-compatible storage

## Cloud Backup (Recovery Codes)

The crate also provides cloud backup functionality for identity recovery. The
backup bundle is encrypted with AES-256-GCM under a key derived from the user's
24-word recovery code — this is the bundle path, distinct from the chunk path
described above.

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
let identity = gitcellar_identity::identity::load("alice")?;
let key_material = code.derive_key_material();
let bundle = CloudBackupBundle::create_with_recovery_code(&identity, &key_material)?;

// Serialize for upload to cloud
let json = bundle.to_json()?;

// Later: Restore from backup
let bundle = CloudBackupBundle::from_json(&json)?;
let recovered_identity = bundle.decrypt_with_recovery_code(&key_material)?;
```
