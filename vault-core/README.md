# vault-core

Cross-platform encrypted backup library providing content-defined chunking, XChaCha20-Poly1305 chunk encryption, and S3-compatible cloud storage.

## Overview

vault-core is a shared library designed to be used across multiple applications that need encrypted cloud backup functionality:

| Project | Language | Use Case |
|---------|----------|----------|
| **GitCellar** | Rust | Encrypted Git repository hosting |
| **Foldergami** | C# (.NET) | Vantage Drive encrypted backup |
| **Vetiqbox** | C# (.NET) | Dropbox-like encrypted sync |

## Features

- **Content-Defined Chunking**: Variable-size chunks for efficient deduplication, with per-repo keyed boundaries
- **XChaCha20-Poly1305 Chunk Encryption**: `XChaChaChunkEngine` — the single chunk-encryption engine. HKDF-SHA256 content-key derivation, 24-byte nonce, chunk identity bound as AEAD associated data
- **AES-256-GCM Passphrase/FFI Helper**: `AesEncryptionEngine` — passphrase-derived encryption for `.gckey` and FFI consumers. **Not the chunk path**
- **S3-Compatible Storage**: Works with B2, Wasabi, MinIO, AWS S3
- **Cross-Platform**: Windows, Linux, macOS
- **Multi-Language**: Rust native + C bindings + C# wrapper

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        vault-core                           │
├──────────────┬──────────────┬──────────────┬───────────────┤
│   chunking   │  encryption  │   storage    │      ffi      │
│     CDC      │ XChaCha/AES  │  File / S3   │  C bindings   │
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
use vault_core::{ChunkEngine, ChunkConfig, XChaChaChunkEngine, EncryptionEngine};

// 1. Create chunks
let chunker = ChunkEngine::new(ChunkConfig::default());
let data = std::fs::read("large_file.bin")?;
let chunks = chunker.chunk_data(&data)?;

// 2. Seal each chunk (XChaCha20-Poly1305; content key derived from the
//    per-repo root key via HKDF-SHA256)
let encryptor = XChaChaChunkEngine::new(&k_repo)?;   // k_repo: &[u8; 32]

for chunk in &chunks {
    let encrypted = encryptor.encrypt_chunk(chunk, &aad)?;
    // Store encrypted chunk... wire format: [version(1)][nonce(24)][ciphertext][tag(16)]
}

// 3. Upload to cloud (example with FileStorage for testing)
use vault_core::storage::{FileStorage, StorageBackend};
let storage = FileStorage::new("/tmp/vault")?;
storage.upload("chunks/abc123", &encrypted).await?;
```

### C# (.NET)

The .NET bindings expose the AES passphrase helper (`AesEngine`) and the chunker.
Chunk sealing for GitCellar repositories happens on the Rust side.

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
vault-core = { path = "../shared/vault-core" }

# Or with specific features
vault-core = { path = "../shared/vault-core", default-features = false, features = ["aes-only"] }
```

### C# (.NET)

```xml
<ItemGroup>
  <!-- Local development -->
  <ProjectReference Include="..\..\shared\vault-core\bindings\dotnet\VaultCore.Native\VaultCore.Native.csproj" />

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
| `gpg` | No-op, retained for backward-compatible feature selection. The OpenPGP-per-chunk engine was retired; vault-core contains no OpenPGP code | |
| `aes-only` | Builds only the `AesEncryptionEngine` passphrase/FFI helper (AES-256-GCM; not the chunk path) | |
| `ffi` | C-compatible FFI exports | |

### Feature Examples

```toml
# Full features (default)
vault-core = { path = "..." }

# AES passphrase/FFI helper only
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
// Chunk sealing — XChaCha20-Poly1305 (the single chunk engine)
use vault_core::encryption::XChaChaChunkEngine;
let engine = XChaChaChunkEngine::new(&k_repo)?;         // k_repo: &[u8; 32]
let sealed = engine.encrypt_chunk(&chunk, &aad)?;       // [version(1)][nonce(24)][ct][tag(16)]
let opened = engine.decrypt_chunk(&sealed, &aad)?;      // fails closed on identity mismatch

// AES passphrase/FFI helper (AES-256-GCM; .gckey / FFI — NOT the chunk path)
use vault_core::encryption::AesEncryptionEngine;
let salt = AesEncryptionEngine::generate_salt();
let key = AesEncryptionEngine::derive_key(passphrase, &salt)?;
let aes = AesEncryptionEngine::new(&key)?;
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

### Sealed Chunk (XChaCha20-Poly1305)

```
[version: 1 byte][nonce: 24 bytes][ciphertext][auth_tag: 16 bytes]
```

Overhead is a flat 41 bytes per chunk. The chunk's identity — repository, chunk
name, size — is authenticated as associated data rather than stored in the blob.

### AES Encrypted Data (passphrase/FFI helper)

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

- **XChaCha20-Poly1305 for chunks**: authenticated encryption with a 256-bit content key and a 192-bit random nonce, so nonce collisions are a non-concern at any realistic chunk count
- **Identity binding**: each chunk is sealed against its own associated data, so a spliced, substituted, or wrong-repository blob fails authentication instead of decrypting
- **HKDF-SHA256**: per-repo content-key derivation with a domain-separated info string
- **AES-256-GCM for the passphrase/FFI helper**: authenticated encryption with 256-bit keys and a fresh 96-bit nonce per payload
- **Argon2id**: OWASP-recommended parameters for passphrase key derivation
- **Content-based hashing**: keyed HMAC-SHA256 chunk names (SHA-256 when unkeyed)
- **No key storage**: keys are provided by the caller, never stored

## Thread Safety

All types are `Send + Sync` and can be safely used from multiple threads:

```rust
let engine = Arc::new(XChaChaChunkEngine::new(&k_repo)?);

// Safe to clone and use across threads
let engine_clone = Arc::clone(&engine);
tokio::spawn(async move {
    let sealed = engine_clone.encrypt_chunk(&chunk, &aad)?;
});
```

## Error Handling

```rust
use vault_core::error::{VaultError, VaultResult};

match engine.encrypt_chunk(&chunk, &aad) {
    Ok(sealed) => { /* success */ }
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
- [RustCrypto `chacha20poly1305`](https://github.com/RustCrypto/AEADs) - XChaCha20-Poly1305 implementation used for chunk sealing
