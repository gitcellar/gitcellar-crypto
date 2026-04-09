# vault-core

Cross-platform encrypted backup library providing content-defined chunking, AES/GPG encryption, and S3-compatible cloud storage.

## Overview

vault-core is a shared library designed to be used across multiple applications that need encrypted cloud backup functionality:

| Project | Language | Use Case |
|---------|----------|----------|
| **GitCellar** | Rust | Encrypted Git repository hosting |
| **Foldergami** | C# (.NET) | Vantage Drive encrypted backup |
| **Vetiqbox** | C# (.NET) | Dropbox-like encrypted sync |

## Features

- **Content-Defined Chunking**: Variable-size chunks for efficient deduplication
- **AES-256-GCM Encryption**: Fast, authenticated symmetric encryption
- **GPG/OpenPGP Encryption**: Full GPG key compatibility via Sequoia
- **S3-Compatible Storage**: Works with B2, Wasabi, MinIO, AWS S3
- **Cross-Platform**: Windows, Linux, macOS
- **Multi-Language**: Rust native + C bindings + C# wrapper

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        vault-core                           │
├──────────────┬──────────────┬──────────────┬───────────────┤
│   chunking   │  encryption  │   storage    │      ffi      │
│     CDC      │  AES / GPG   │  File / S3   │  C bindings   │
└──────────────┴──────────────┴──────────────┴───────────────┘
         │                           │                │
    Rust crate                  HTTP client     C# P/Invoke
         │                           │                │
   ┌─────▼─────┐              ┌──────▼──────┐  ┌─────▼─────┐
   │ GitCellar │              │  B2/Wasabi  │  │ Foldergami│
   │  Service  │              │   MinIO/S3  │  │ Vetiqbox  │
   └───────────┘              └─────────────┘  └───────────┘
```

## Quick Start

### Rust

```rust
use vault_core::{ChunkEngine, ChunkConfig, AesEncryptionEngine, EncryptionEngine};

// 1. Create chunks
let chunker = ChunkEngine::new(ChunkConfig::default());
let data = std::fs::read("large_file.bin")?;
let chunks = chunker.chunk_data(&data)?;

// 2. Encrypt each chunk
let key = AesEncryptionEngine::generate_key();
let encryptor = AesEncryptionEngine::new(&key)?;

for chunk in &chunks {
    let encrypted = encryptor.encrypt(&chunk.data)?;
    // Store encrypted chunk...
}

// 3. Upload to cloud (example with FileStorage for testing)
use vault_core::storage::{FileStorage, StorageBackend};
let storage = FileStorage::new("/tmp/vault")?;
storage.upload("chunks/abc123", &encrypted).await?;
```

### C# (.NET)

```csharp
using VaultCore.Native;

// Generate key
var key = AesEngine.GenerateKey();

// Or derive from passphrase
var salt = AesEngine.GenerateSalt();
var key = AesEngine.DeriveKey(
    Encoding.UTF8.GetBytes("my-passphrase"),
    salt);

// Encrypt/decrypt
using var engine = new AesEngine(key);
var encrypted = engine.Encrypt(plaintext);
var decrypted = engine.Decrypt(encrypted);

// Chunk data
using var chunker = new ChunkEngine();
var chunks = chunker.Chunk(fileData);

foreach (var chunk in chunks)
{
    Console.WriteLine($"{chunk.Hash}: {chunk.Size} bytes");
}
```

## Installation

### Rust

```toml
[dependencies]
vault-core = { path = "../Shared/vault-core" }

# Or with specific features
vault-core = { path = "../Shared/vault-core", default-features = false, features = ["aes-only"] }
```

### C# (.NET)

```xml
<ItemGroup>
  <!-- Local development -->
  <ProjectReference Include="..\..\Shared\vault-core\bindings\dotnet\VaultCore.Native\VaultCore.Native.csproj" />

  <!-- Or as NuGet package (when published) -->
  <PackageReference Include="VaultCore.Native" Version="0.1.0" />
</ItemGroup>
```

## Building

### Native Library (Rust)

```bash
cd vault-core

# Build library
cargo build --release

# Run tests
cargo test

# Generate C header (requires --features ffi)
cargo build --release --features ffi
```

Output locations:
- Windows: `target/release/vault_core.dll`
- Linux: `target/release/libvault_core.so`
- macOS: `target/release/libvault_core.dylib`

### C# Bindings

```bash
cd vault-core/bindings/dotnet/VaultCore.Native

# Build
dotnet build

# Run tests
dotnet test ../VaultCore.Tests
```

## Features

| Feature | Description | Default |
|---------|-------------|---------|
| `gpg` | GPG/OpenPGP encryption via Sequoia | ✓ |
| `aes-only` | AES-256-GCM only (no GPG dependency) | |
| `ffi` | C-compatible FFI exports | |

### Feature Examples

```toml
# Full features (default)
vault-core = { path = "..." }

# AES-only (smaller binary, no GPG)
vault-core = { path = "...", default-features = false, features = ["aes-only"] }

# For building FFI library
vault-core = { path = "...", features = ["ffi"] }
```

## API Reference

### Chunking

```rust
// Content-defined chunking
let chunker = ChunkEngine::new(ChunkConfig::default());
let chunks = chunker.chunk_data(&data)?;

// Custom chunk sizes
let config = ChunkConfig::new(
    64 * 1024,   // min: 64KB
    256 * 1024,  // avg: 256KB
    512 * 1024,  // max: 512KB
);

// Reassemble
let original = ChunkEngine::reassemble_chunks(&chunks)?;

// Verify integrity
assert!(chunker.verify_chunk(&chunk));
```

### Encryption

```rust
// AES-256-GCM (recommended for new projects)
let key = AesEncryptionEngine::generate_key();
let engine = AesEncryptionEngine::new(&key)?;
let encrypted = engine.encrypt(&plaintext)?;
let decrypted = engine.decrypt(&encrypted)?;

// Key derivation from passphrase
let salt = AesEncryptionEngine::generate_salt();
let key = AesEncryptionEngine::derive_key(passphrase, &salt)?;

// GPG encryption (requires gpg feature)
#[cfg(feature = "gpg")]
{
    let engine = GpgEncryptionEngine::new("user@example.com".to_string())?;
    let encrypted = engine.encrypt(&plaintext)?;
}
```

### Storage

```rust
use vault_core::storage::{FileStorage, S3Storage, S3Config, StorageBackend};

// Local filesystem (testing)
let storage = FileStorage::new("/tmp/vault")?;

// Backblaze B2
let config = S3Config::b2("key-id", "app-key", "bucket", "us-west-000");
let storage = S3Storage::new(config)?;

// Wasabi
let config = S3Config::wasabi("key", "secret", "bucket", "us-east-1");

// AWS S3
let config = S3Config::aws("key", "secret", "bucket", "eu-west-1");

// MinIO (self-hosted)
let config = S3Config::minio("http://localhost:9000", "key", "secret", "bucket");

// Operations
storage.upload("path/to/file", &data).await?;
let data = storage.download("path/to/file").await?;
let exists = storage.exists("path/to/file").await?;
let files = storage.list("prefix/").await?;
storage.delete("path/to/file").await?;
```

## Wire Formats

### AES Encrypted Data

```
[nonce: 12 bytes][ciphertext][auth_tag: 16 bytes]
```

### Chunk Metadata (JSON)

```json
{
  "hash": "a1b2c3...",
  "size": 1048576,
  "offset": 0
}
```

## Security

- **AES-256-GCM**: Authenticated encryption with 256-bit keys
- **Argon2id**: OWASP-recommended parameters for key derivation
- **Random nonces**: Each encryption uses a fresh 96-bit nonce
- **Content-based hashing**: SHA-256 for chunk identification
- **No key storage**: Keys are provided by caller, never stored

## Thread Safety

All types are `Send + Sync` and can be safely used from multiple threads:

```rust
let engine = Arc::new(AesEncryptionEngine::new(&key)?);

// Safe to clone and use across threads
let engine_clone = Arc::clone(&engine);
tokio::spawn(async move {
    let encrypted = engine_clone.encrypt(&data)?;
});
```

## Error Handling

```rust
use vault_core::error::{VaultError, VaultResult};

match engine.encrypt(&data) {
    Ok(encrypted) => { /* success */ }
    Err(VaultError::Encryption(msg)) => { /* encryption failed */ }
    Err(VaultError::Key(msg)) => { /* key issue */ }
    Err(e) => { /* other error */ }
}
```

## License

MIT License - see LICENSE file.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit a pull request

## Related Projects

- [GitCellar](https://github.com/gitcellar/gitcellar) - Encrypted Git hosting
- [Foldergami](https://github.com/gitcellar/foldergami) - Windows virtual folders
- [Sequoia-PGP](https://sequoia-pgp.org/) - OpenPGP implementation used for GPG support
