//! Encryption module for vault-core
//!
//! Provides the chunk-encryption engine plus a passphrase file engine:
//!
//! - **[`XChaChaChunkEngine`]** — the **single** chunk-encryption engine (F2).
//!   XChaCha20-Poly1305 AEAD, 192-bit nonce (safe-by-construction — no
//!   AES-GCM birthday footgun), per-repo content key via HKDF-SHA256. Emits the
//!   versioned `[ver][24B nonce][ciphertext][16B tag]` chunk-format-v1 layout
//!   ([`crate::chunk_format`]). This is the ONE chunk engine — the legacy
//!   GPG-per-chunk engine was retired (R-1), so there is no ambiguous
//!   dual-engine dead code.
//! - **[`AesEncryptionEngine`]** — AES-256-GCM with Argon2id key derivation,
//!   used for **passphrase-derived FFI consumers** (.NET consumers) via
//!   [`crate::ffi`]. NOT a chunk engine. Repurposed as the structural template
//!   for `XChaChaChunkEngine` (R-1: swap cipher → XChaCha20-Poly1305, widen
//!   nonce 12B → 24B, add HKDF content-key derivation + the F6 version byte).
//!
//!   This engine's only consumer is [`crate::ffi`]. It is not the same thing as the
//!   Service's `.gckey` keystore, a separate same-named format that uses the
//!   `aes-gcm` crate directly and never calls into this module.
//!
//! # Encryption Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    EncryptionEngine                     │
//! │                      (trait)                            │
//! └─────────────────────────────────────────────────────────┘
//!              │                          │
//!   ┌──────────▼──────────┐    ┌──────────▼──────────┐
//!   │ XChaChaChunkEngine  │    │ AesEncryptionEngine │
//!   │ XChaCha20-Poly1305  │    │ AES-256-GCM         │
//!   │ (chunks — F2)       │    │ (FFI passphrase)    │
//!   └─────────────────────┘    └─────────────────────┘
//! ```
//!
//! # Chunk identity binding (H-1 + L-1)
//!
//! Every chunk seal/open binds a [`crate::chunk_format::ChunkAad`] — repo id,
//! keyed chunk name, offset, size — plus the format-version byte into the AEAD
//! as associated data. A stored blob therefore only opens under the identity it
//! was sealed with: splice/substitution and version-byte flips fail the
//! Poly1305 tag. The AAD is not stored; only the tag value depends on it.
//!
//! # Example: chunk encryption (F2 + H-1)
//!
//! ```rust,no_run
//! use vault_core::chunk_format::ChunkAad;
//! use vault_core::encryption::XChaChaChunkEngine;
//!
//! // Per-repo root key (K_repo); the content key is HKDF-SHA256-derived from it.
//! let k_repo = [7u8; 32];
//! let engine = XChaChaChunkEngine::new(&k_repo).unwrap();
//!
//! let plaintext = b"Hello, encrypted world!";
//! let aad = ChunkAad::for_content_chunk("alice/repo", "chunk-name-hex", plaintext.len() as u64);
//! let encrypted = engine.encrypt_with_aad(plaintext, &aad).unwrap(); // [ver][24B nonce][ct][16B tag]
//! let decrypted = engine.decrypt_with_aad(&encrypted, &aad).unwrap();
//! assert_eq!(plaintext.to_vec(), decrypted);
//! ```

use crate::chunk_format::{self, ChunkAad, ChunkFormatVersion, V1_XCHACHA20_POLY1305};
use crate::chunking::Chunk;
use crate::error::{VaultError, VaultResult};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use tracing::debug;

/// Encryption engine trait
///
/// All encryption backends implement this trait for uniform API.
pub trait EncryptionEngine: Send + Sync {
    /// Encrypt raw data (no identity binding — NOT for chunks; chunk call
    /// sites must use [`encrypt_chunk`](Self::encrypt_chunk) so the chunk's
    /// identity is bound as AEAD associated data, H-1).
    fn encrypt(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>>;

    /// Decrypt raw data sealed by [`encrypt`](Self::encrypt) (no identity
    /// binding). An AAD-bound chunk will NOT decrypt through this — that
    /// mismatch failing closed is intentional.
    fn decrypt(&self, ciphertext: &[u8]) -> VaultResult<Vec<u8>>;

    /// Get the key identifier (for logging/tracking)
    fn key_id(&self) -> &str;

    /// Encrypt a chunk, binding its identity (`aad`) into the AEAD tag (H-1).
    ///
    /// A blob sealed with one `ChunkAad` fails authentication when opened
    /// under any other — splice/substitution is defeated at the cipher layer.
    fn encrypt_chunk(&self, chunk: &Chunk, aad: &ChunkAad) -> VaultResult<Vec<u8>>;

    /// Decrypt chunk data, authenticating it against the manifest-derived
    /// identity `aad` (H-1). Fails closed on any identity mismatch.
    fn decrypt_chunk(&self, encrypted_data: &[u8], aad: &ChunkAad) -> VaultResult<Vec<u8>>;
}

// ============================================================================
// XChaCha20-Poly1305 Chunk Engine (F2 — the single chunk-encryption engine)
// ============================================================================

/// XChaCha20-Poly1305 AEAD chunk-encryption engine (F2).
///
/// This is the **one** chunk-encryption engine (R-1 retired the GPG-per-chunk
/// engine). It replaces the legacy OpenPGP-per-chunk path with a single modern
/// AEAD per chunk and emits the versioned chunk-format-v1 layout.
///
/// # Wire format (chunk-format v1; [`crate::chunk_format`])
///
/// ```text
/// ┌────────┬──────────────┬───────────────┬──────────────┐
/// │ ver(1) │ XNonce(24)   │ ciphertext(n) │ Poly1305(16) │
/// └────────┴──────────────┴───────────────┴──────────────┘
/// ```
///
/// `ver = 1` ([`V1_XCHACHA20_POLY1305`]). No OpenPGP packet, no ASCII armor
/// (F3). Stored size = plaintext + 41 bytes (1 + 24 + 16), never plaintext×1.33.
///
/// # Key derivation (AC-F2.2)
///
/// The 32-byte content key is `HKDF-SHA256(K_repo, info="gitcellar/chunk-content/v1",
/// L=32)` — a versioned, domain-separated info string, distinct from the E1
/// `id_key`/`boundary_key` info strings (which are reserved, not built here).
/// `K_repo` is the per-repo root key; the caller derives it from the per-repo
/// X25519 key and passes it to [`new`](Self::new). For published RFC-8439-style
/// test vectors, [`from_content_key`](Self::from_content_key) takes the content
/// key directly so a third party can reproduce a chunk without K_repo.
///
/// # Nonce safety (why XChaCha20 over AES-GCM)
///
/// The 192-bit (24-byte) random nonce makes collisions a non-concern at any
/// realistic chunk count — the primitive is safe-by-construction rather than
/// safe-by-key-scoping-discipline (DEC-CH-02). The retired AES-GCM-on-chunks
/// footgun (random 96-bit nonce, ~2^32-message birthday bound) is gone.
#[derive(Clone)]
pub struct XChaChaChunkEngine {
    cipher: XChaCha20Poly1305,
    key_id: String,
    /// The F6 version byte this engine emits (`byte[0]`). v1 (`F2` baseline) by
    /// default; the E1 keyed pipeline sets v2 via [`with_format_version`]. The
    /// cipher payload is identical either way; the byte records which pipeline
    /// produced the chunk (AC-E1.6). Decrypt accepts both v1 and v2.
    ///
    /// [`with_format_version`]: XChaChaChunkEngine::with_format_version
    emit_version: u8,
}

impl XChaChaChunkEngine {
    /// XChaCha20 nonce size (192 bits / 24 bytes).
    pub const NONCE_SIZE: usize = 24;

    /// Poly1305 authentication tag size (128 bits / 16 bytes).
    pub const TAG_SIZE: usize = 16;

    /// Format-version-byte size (1 byte; F6).
    pub const VERSION_SIZE: usize = 1;

    /// Content-key size (256 bits / 32 bytes).
    pub const KEY_SIZE: usize = 32;

    /// Per-chunk storage overhead over plaintext: `version + nonce + tag`.
    pub const OVERHEAD: usize = Self::VERSION_SIZE + Self::NONCE_SIZE + Self::TAG_SIZE; // 41

    /// HKDF `info` string for the chunk content key (domain separation; AC-F2.2).
    pub const CONTENT_KEY_INFO: &'static [u8] = b"gitcellar/chunk-content/v1";

    /// Build an engine from a per-repo root key `K_repo`.
    ///
    /// The content key is `HKDF-SHA256(K_repo, info="gitcellar/chunk-content/v1",
    /// L=32)`. `K_repo` may be any length (HKDF accepts arbitrary IKM).
    pub fn new(k_repo: &[u8]) -> VaultResult<Self> {
        let content_key = Self::derive_content_key(k_repo)?;
        Self::from_content_key(&content_key)
    }

    /// Derive the 32-byte content key from `K_repo` via HKDF-SHA256 (no salt;
    /// domain separation is carried by the versioned `info` string). Exposed so
    /// test vectors can publish the `K_repo → content_key` step explicitly.
    pub fn derive_content_key(k_repo: &[u8]) -> VaultResult<[u8; Self::KEY_SIZE]> {
        let hk = Hkdf::<Sha256>::new(None, k_repo);
        let mut okm = [0u8; Self::KEY_SIZE];
        hk.expand(Self::CONTENT_KEY_INFO, &mut okm)
            .map_err(|e| VaultError::Key(format!("HKDF-SHA256 expand failed: {e}")))?;
        Ok(okm)
    }

    /// Build an engine directly from a 32-byte content key.
    ///
    /// Use for published test vectors (AC-F2.4) and for callers that derive the
    /// content key themselves. Most callers want [`new`](Self::new).
    pub fn from_content_key(content_key: &[u8]) -> VaultResult<Self> {
        if content_key.len() != Self::KEY_SIZE {
            return Err(VaultError::Key(format!(
                "XChaCha20-Poly1305 content key must be {} bytes, got {}",
                Self::KEY_SIZE,
                content_key.len()
            )));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(content_key)
            .map_err(|e| VaultError::Key(format!("Failed to create XChaCha20 cipher: {e}")))?;
        let key_hash = crate::chunking::ChunkEngine::compute_hash(content_key);
        let key_id = key_hash[..16].to_string();
        Ok(Self {
            cipher,
            key_id,
            emit_version: V1_XCHACHA20_POLY1305,
        })
    }

    /// Set the F6 version byte this engine emits.
    ///
    /// `XChaCha20Poly1305V1` (default) is the F2 baseline; `KeyedCdcNamingV2` is
    /// the E1 keyed-CDC/keyed-naming pipeline. Both emit the identical
    /// XChaCha20-Poly1305 payload; only `byte[0]` differs (AC-E1.6). A version
    /// without the XChaCha20-Poly1305 layout is rejected (this engine only
    /// produces that layout).
    pub fn with_format_version(mut self, version: ChunkFormatVersion) -> VaultResult<Self> {
        if !version.is_xchacha20_poly1305_layout() {
            return Err(VaultError::Encryption(format!(
                "XChaChaChunkEngine cannot emit version 0x{:02x}: not an XChaCha20-Poly1305 layout",
                version.as_byte()
            )));
        }
        self.emit_version = version.as_byte();
        Ok(self)
    }

    /// The cipher-level AAD for a chunk: `version_byte(1) ‖ canonical_aad_bytes`
    /// (H-1 + L-1). On encrypt `version_byte` is the engine's emit-version; on
    /// decrypt it is the OBSERVED `byte[0]`, so a v1↔v2 flip fails the tag.
    fn cipher_aad(version_byte: u8, aad: &ChunkAad) -> Vec<u8> {
        let canonical = aad.canonical_aad_bytes();
        let mut out = Vec::with_capacity(1 + canonical.len());
        out.push(version_byte);
        out.extend_from_slice(&canonical);
        out
    }

    /// Encrypt with a caller-supplied nonce, binding `aad` (H-1).
    /// **Deterministic** — for test vectors only (AC-F2.4). Production code
    /// MUST use [`encrypt_chunk`](EncryptionEngine::encrypt_chunk) /
    /// [`encrypt_with_aad`](Self::encrypt_with_aad), which draw a fresh random
    /// nonce per call.
    pub fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        nonce_bytes: &[u8; Self::NONCE_SIZE],
        aad: &ChunkAad,
    ) -> VaultResult<Vec<u8>> {
        let cipher_aad = Self::cipher_aad(self.emit_version, aad);
        let nonce = XNonce::from_slice(nonce_bytes);
        let ct_and_tag = self
            .cipher
            .encrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: plaintext,
                    aad: &cipher_aad,
                },
            )
            .map_err(|e| VaultError::Encryption(format!("XChaCha20-Poly1305 encryption failed: {e}")))?;

        let mut out = Vec::with_capacity(Self::OVERHEAD + plaintext.len());
        out.push(self.emit_version); // F6 version byte (v1 baseline / v2 E1 keyed pipeline)
        out.extend_from_slice(nonce_bytes); // 24-byte XNonce
        out.extend_from_slice(&ct_and_tag); // ciphertext || 16-byte Poly1305 tag
        Ok(out)
    }

    /// Encrypt `plaintext` with a fresh random nonce, binding `aad` into the
    /// AEAD tag (H-1). This is the production chunk seal path.
    pub fn encrypt_with_aad(&self, plaintext: &[u8], aad: &ChunkAad) -> VaultResult<Vec<u8>> {
        let mut nonce_bytes = [0u8; Self::NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        self.encrypt_with_nonce(plaintext, &nonce_bytes, aad)
    }

    /// Decrypt a chunk, authenticating against `aad` (H-1). The cipher AAD is
    /// composed from the chunk's OBSERVED version byte, so a flipped format
    /// version (L-1) fails authentication like any other tamper.
    pub fn decrypt_with_aad(&self, data: &[u8], aad: &ChunkAad) -> VaultResult<Vec<u8>> {
        // F6: dispatch on the leading version byte. Unknown → explicit error.
        let version = chunk_format::version_of(data)?;
        if !version.is_xchacha20_poly1305_layout() {
            return Err(VaultError::Decryption(format!(
                "chunk version 0x{:02x} is not an XChaCha20-Poly1305 layout; \
                 XChaChaChunkEngine cannot decrypt it",
                version.as_byte()
            )));
        }
        let min = Self::OVERHEAD; // version + nonce + tag, with empty plaintext
        if data.len() < min {
            return Err(VaultError::Decryption(format!(
                "chunk too short: {} bytes < minimum {} (version+nonce+tag)",
                data.len(),
                min
            )));
        }
        let cipher_aad = Self::cipher_aad(data[0], aad);
        let nonce = XNonce::from_slice(&data[1..1 + Self::NONCE_SIZE]);
        let ct_and_tag = &data[1 + Self::NONCE_SIZE..];
        let plaintext = self
            .cipher
            .decrypt(
                nonce,
                chacha20poly1305::aead::Payload {
                    msg: ct_and_tag,
                    aad: &cipher_aad,
                },
            )
            .map_err(|_| {
                // The AEAD tag is the real integrity check (F4/H-1): any
                // tampered byte of nonce/ciphertext/tag, any wrong key, and any
                // identity (AAD) mismatch — spliced blob, wrong repo, flipped
                // version byte — lands here.
                VaultError::Decryption(
                    "XChaCha20-Poly1305 authentication failed (tampered, wrong key, or chunk-identity/AAD mismatch)"
                        .to_string(),
                )
            })?;
        debug!(
            "Decrypted chunk: {} bytes → {} bytes (XChaCha20-Poly1305 v0x{:02x}, AAD-bound)",
            data.len(),
            plaintext.len(),
            version.as_byte()
        );
        Ok(plaintext)
    }
}

impl EncryptionEngine for XChaChaChunkEngine {
    /// Raw seal with NO identity binding (empty AAD). Not the chunk path —
    /// chunks go through [`encrypt_chunk`](EncryptionEngine::encrypt_chunk)
    /// so their identity is bound (H-1). Kept for non-chunk payloads, doc
    /// examples, and tests; an AAD-bound chunk will not open via
    /// [`decrypt`](EncryptionEngine::decrypt) and vice versa (fails closed).
    fn encrypt(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        let mut nonce_bytes = [0u8; Self::NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let ct_and_tag = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| VaultError::Encryption(format!("XChaCha20-Poly1305 encryption failed: {e}")))?;
        let mut out = Vec::with_capacity(Self::OVERHEAD + plaintext.len());
        out.push(self.emit_version);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct_and_tag);
        debug!(
            "Encrypted: {} bytes → {} bytes (XChaCha20-Poly1305, no AAD)",
            plaintext.len(),
            out.len()
        );
        Ok(out)
    }

    fn decrypt(&self, data: &[u8]) -> VaultResult<Vec<u8>> {
        // F6: dispatch on the leading version byte. Unknown → explicit error.
        let version = chunk_format::version_of(data)?;
        // v1 (F2 baseline) and v2 (E1 keyed pipeline) share the identical
        // XChaCha20-Poly1305 payload, so both unwrap the same way. Any future
        // non-XChaCha layout (e.g. an AES-256-GCM-SIV build variant) is rejected
        // here rather than misparsed.
        if !version.is_xchacha20_poly1305_layout() {
            return Err(VaultError::Decryption(format!(
                "chunk version 0x{:02x} is not an XChaCha20-Poly1305 layout; \
                 XChaChaChunkEngine cannot decrypt it",
                version.as_byte()
            )));
        }
        let min = Self::OVERHEAD; // version + nonce + tag, with empty plaintext
        if data.len() < min {
            return Err(VaultError::Decryption(format!(
                "chunk too short: {} bytes < minimum {} (version+nonce+tag)",
                data.len(),
                min
            )));
        }
        let nonce = XNonce::from_slice(&data[1..1 + Self::NONCE_SIZE]);
        let ct_and_tag = &data[1 + Self::NONCE_SIZE..];
        let plaintext = self.cipher.decrypt(nonce, ct_and_tag).map_err(|_| {
            // The AEAD tag is the real integrity check (F4): any tampered
            // byte of nonce / ciphertext / tag lands here.
            VaultError::Decryption(
                "XChaCha20-Poly1305 authentication failed (tampered or wrong key)".to_string(),
            )
        })?;
        debug!(
            "Decrypted chunk: {} bytes → {} bytes (XChaCha20-Poly1305 v0x{:02x})",
            data.len(),
            plaintext.len(),
            version.as_byte()
        );
        Ok(plaintext)
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn encrypt_chunk(&self, chunk: &Chunk, aad: &ChunkAad) -> VaultResult<Vec<u8>> {
        debug!(
            "Encrypting chunk: {} ({} bytes, AAD-bound)",
            &chunk.hash[..16.min(chunk.hash.len())],
            chunk.size
        );
        self.encrypt_with_aad(&chunk.data, aad)
    }

    fn decrypt_chunk(&self, encrypted_data: &[u8], aad: &ChunkAad) -> VaultResult<Vec<u8>> {
        debug!("Decrypting chunk ({} bytes, AAD-bound)", encrypted_data.len());
        self.decrypt_with_aad(encrypted_data, aad)
    }
}

// ============================================================================
// AES-256-GCM Engine — FFI passphrase files (NOT chunks)
// ============================================================================

/// AES-256-GCM encryption engine for **FFI passphrase files**.
///
/// NOT the chunk engine — chunk encryption is [`XChaChaChunkEngine`] (F2). This
/// engine provides passphrase-derived (Argon2id) authenticated file encryption
/// for cross-language FFI consumers (.NET consumers) via [`crate::ffi`],
/// which is its sole consumer. It is also the structural template
/// `XChaChaChunkEngine` was repurposed from (R-1).
///
/// Provides authenticated encryption without requiring GPG.
/// Keys are 32 bytes (256 bits).
///
/// # Wire Format
///
/// Encrypted data format:
/// ```text
/// [nonce: 12 bytes][ciphertext + auth tag]
/// ```
///
/// # Nonce Safety (load-bearing)
///
/// This engine uses random 96-bit nonces and is for **FFI passphrase files**,
/// where one key encrypts a tiny number of payloads — far below the
/// AES-GCM birthday bound (NIST SP 800-38D: random-nonce collision risk crosses
/// ~2^-32 at ~2^32 messages per key). It is **not** used for GitCellar chunks:
/// the chunk path is [`XChaChaChunkEngine`], whose 192-bit nonce removes the
/// birthday footgun by construction (DEC-CH-02), so chunk safety no longer
/// depends on a key-scoping invariant holding forever.
///
/// # Example
///
/// ```rust,no_run
/// use vault_core::encryption::{AesEncryptionEngine, EncryptionEngine};
///
/// let key = AesEncryptionEngine::generate_key();
/// let engine = AesEncryptionEngine::new(&key).unwrap();
///
/// let encrypted = engine.encrypt(b"secret data").unwrap();
/// let decrypted = engine.decrypt(&encrypted).unwrap();
/// ```
pub struct AesEncryptionEngine {
    cipher: Aes256Gcm,
    key_id: String,
}

impl AesEncryptionEngine {
    /// Nonce size for AES-GCM (96 bits / 12 bytes)
    pub const NONCE_SIZE: usize = 12;

    /// Key size for AES-256 (256 bits / 32 bytes)
    pub const KEY_SIZE: usize = 32;

    /// Create a new AES encryption engine
    ///
    /// # Arguments
    /// * `key` - 32-byte encryption key
    ///
    /// # Errors
    /// Returns error if key is not exactly 32 bytes.
    pub fn new(key: &[u8]) -> VaultResult<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(VaultError::Key(format!(
                "AES-256 key must be {} bytes, got {}",
                Self::KEY_SIZE,
                key.len()
            )));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| VaultError::Key(format!("Failed to create cipher: {}", e)))?;

        // Use first 8 bytes of key hash as key ID (for logging)
        let key_hash = crate::chunking::ChunkEngine::compute_hash(key);
        let key_id = key_hash[..16].to_string();

        Ok(Self { cipher, key_id })
    }

    /// Generate a random 256-bit key
    pub fn generate_key() -> [u8; Self::KEY_SIZE] {
        let mut key = [0u8; Self::KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    /// Derive a key from a passphrase using Argon2id
    ///
    /// # Arguments
    /// * `passphrase` - User-provided passphrase
    /// * `salt` - 16+ byte salt (should be stored alongside encrypted data)
    ///
    /// # Security
    /// Uses Argon2id with recommended parameters for key derivation.
    pub fn derive_key(passphrase: &[u8], salt: &[u8]) -> VaultResult<[u8; Self::KEY_SIZE]> {
        use argon2::{Algorithm, Argon2, Params, Version};

        // Argon2id parameters (OWASP recommendations)
        let params = Params::new(
            65536,  // 64 MiB memory
            3,      // 3 iterations
            4,      // 4 parallel lanes
            Some(Self::KEY_SIZE),
        )
        .map_err(|e| VaultError::Key(format!("Invalid Argon2 params: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut key = [0u8; Self::KEY_SIZE];
        argon2
            .hash_password_into(passphrase, salt, &mut key)
            .map_err(|e| VaultError::Key(format!("Key derivation failed: {}", e)))?;

        Ok(key)
    }

    /// Generate a random salt for key derivation
    pub fn generate_salt() -> [u8; 16] {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }
}

impl EncryptionEngine for AesEncryptionEngine {
    fn encrypt(&self, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; Self::NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| VaultError::Encryption(format!("AES encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(Self::NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);

        debug!(
            "Encrypted: {} bytes → {} bytes",
            plaintext.len(),
            result.len()
        );

        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> VaultResult<Vec<u8>> {
        if ciphertext.len() < Self::NONCE_SIZE {
            return Err(VaultError::Decryption(
                "Ciphertext too short (missing nonce)".to_string(),
            ));
        }

        // Extract nonce and ciphertext
        let (nonce_bytes, encrypted) = ciphertext.split_at(Self::NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = self
            .cipher
            .decrypt(nonce, encrypted)
            .map_err(|e| VaultError::Decryption(format!("AES decryption failed: {}", e)))?;

        debug!(
            "Decrypted: {} bytes → {} bytes",
            ciphertext.len(),
            plaintext.len()
        );

        Ok(plaintext)
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Chunk seal with identity binding (H-1 parity). This engine is NOT the
    /// chunk engine (chunks are [`XChaChaChunkEngine`]); implemented so no
    /// `EncryptionEngine` silently ignores the AAD. Its wire format has no
    /// version byte, so the cipher AAD is the bare canonical encoding.
    fn encrypt_chunk(&self, chunk: &Chunk, aad: &ChunkAad) -> VaultResult<Vec<u8>> {
        let cipher_aad = aad.canonical_aad_bytes();
        let mut nonce_bytes = [0u8; Self::NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &chunk.data,
                    aad: &cipher_aad,
                },
            )
            .map_err(|e| VaultError::Encryption(format!("AES encryption failed: {}", e)))?;
        let mut result = Vec::with_capacity(Self::NONCE_SIZE + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    fn decrypt_chunk(&self, encrypted_data: &[u8], aad: &ChunkAad) -> VaultResult<Vec<u8>> {
        if encrypted_data.len() < Self::NONCE_SIZE {
            return Err(VaultError::Decryption(
                "Ciphertext too short (missing nonce)".to_string(),
            ));
        }
        let cipher_aad = aad.canonical_aad_bytes();
        let (nonce_bytes, encrypted) = encrypted_data.split_at(Self::NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(
                nonce,
                Payload {
                    msg: encrypted,
                    aad: &cipher_aad,
                },
            )
            .map_err(|e| {
                VaultError::Decryption(format!(
                    "AES decryption failed (tampered, wrong key, or chunk-identity/AAD mismatch): {}",
                    e
                ))
            })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // F2 — XChaCha20-Poly1305 chunk engine (the P1 phase gate)
    // ========================================================================

    /// Published deterministic test vector (AC-F2.4). A third party reproduces
    /// the exact chunk bytes from `(content_key, nonce, plaintext)` with any
    /// XChaCha20-Poly1305 implementation; the same `content_key` reproduces from
    /// `(K_repo, info)` with any HKDF-SHA256. Kept in lock-step with
    /// `test-vectors/chunk-format-v1.json` (the publishable fixture).
    const TV_K_REPO_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const TV_NONCE_HEX: &str = "404142434445464748494a4b4c4d4e4f5051525354555657";
    const TV_PLAINTEXT: &[u8] = b"GitCellar chunk-format v1 published test vector";
    // H-1: the published vector binds a chunk identity as AAD, mirroring the
    // production seal path. Kept in lock-step with the fixture's `aad` object.
    const TV_AAD_REPO_ID: &str = "alice/example-repo";
    const TV_AAD_CHUNK_NAME: &str =
        "9f2c4e8a1b3d5f70e6c2a4881d3b5f7092e4c6a8b0d2f4e6182a3c4d5e6f7081";

    fn tv_aad() -> ChunkAad {
        ChunkAad::for_content_chunk(TV_AAD_REPO_ID, TV_AAD_CHUNK_NAME, TV_PLAINTEXT.len() as u64)
    }

    fn hex_to_vec(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex")
    }

    /// A representative content-chunk AAD for tests.
    fn test_aad() -> ChunkAad {
        ChunkAad::for_content_chunk("alice/proj", "cafe0123", 29)
    }

    #[test]
    fn xchacha_round_trip() {
        let k_repo = [7u8; 32];
        let engine = XChaChaChunkEngine::new(&k_repo).unwrap();

        let plaintext = b"Hello, encrypted chunk world!";
        let aad = test_aad();
        let encrypted = engine.encrypt_with_aad(plaintext, &aad).unwrap();
        let decrypted = engine.decrypt_with_aad(&encrypted, &aad).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);

        // The raw no-AAD layer still round-trips independently…
        let raw = engine.encrypt(plaintext).unwrap();
        assert_eq!(engine.decrypt(&raw).unwrap(), plaintext.to_vec());
        // …but the two layers do NOT cross-open (fails closed both ways).
        assert!(engine.decrypt(&encrypted).is_err(), "AAD-bound chunk must not open without its AAD");
        assert!(engine.decrypt_with_aad(&raw, &aad).is_err(), "no-AAD blob must not open as an identity-bound chunk");
    }

    /// H-1 — the point of the fix: a chunk sealed under one identity fails
    /// authentication when opened under ANY other identity. Wrong repo, wrong
    /// (spliced) chunk name, wrong offset, wrong size — each must be rejected
    /// by the Poly1305 tag.
    #[test]
    fn xchacha_aad_identity_mismatch_is_rejected() {
        let engine = XChaChaChunkEngine::new(&[11u8; 32]).unwrap();
        let plaintext = b"identity-bound chunk content";
        let good = ChunkAad::new("alice/proj", "cafe0123", 7, plaintext.len() as u64);
        let chunk = engine.encrypt_with_aad(plaintext, &good).unwrap();

        // Positive control.
        assert_eq!(engine.decrypt_with_aad(&chunk, &good).unwrap(), plaintext.to_vec());

        // Each field mismatch fails closed.
        let wrong = [
            ChunkAad::new("alice/other", "cafe0123", 7, plaintext.len() as u64), // wrong repo
            ChunkAad::new("alice/proj", "beef4567", 7, plaintext.len() as u64),  // spliced name
            ChunkAad::new("alice/proj", "cafe0123", 8, plaintext.len() as u64),  // wrong offset
            ChunkAad::new("alice/proj", "cafe0123", 7, plaintext.len() as u64 + 1), // wrong size
        ];
        for w in &wrong {
            let res = engine.decrypt_with_aad(&chunk, w);
            assert!(res.is_err(), "identity mismatch NOT rejected: {w:?}");
            match res {
                Err(VaultError::Decryption(msg)) => assert!(
                    msg.contains("authentication failed"),
                    "must fail at the AEAD tag, got: {msg}"
                ),
                other => panic!("expected Decryption auth error, got {other:?}"),
            }
        }
    }

    #[test]
    fn xchacha_wire_format_is_version_nonce_ct_tag() {
        let engine = XChaChaChunkEngine::new(&[9u8; 32]).unwrap();
        let plaintext = b"abcdefghij"; // 10 bytes
        let chunk = engine.encrypt_with_aad(plaintext, &test_aad()).unwrap();

        // byte[0] is the F6 version byte = v1. The AAD is NOT stored — the
        // on-disk layout is unchanged by H-1 (only the tag value differs).
        assert_eq!(chunk[0], V1_XCHACHA20_POLY1305);
        // Layout: 1 (ver) + 24 (nonce) + n (ct) + 16 (tag) == plaintext + 41.
        assert_eq!(chunk.len(), plaintext.len() + XChaChaChunkEngine::OVERHEAD);
        assert_eq!(XChaChaChunkEngine::OVERHEAD, 41);
    }

    #[test]
    fn xchacha_random_nonce_per_call() {
        let engine = XChaChaChunkEngine::new(&[3u8; 32]).unwrap();
        let pt = b"same plaintext";
        let aad = test_aad();
        let a = engine.encrypt_with_aad(pt, &aad).unwrap();
        let b = engine.encrypt_with_aad(pt, &aad).unwrap();
        // Same key + plaintext + AAD → different chunks (fresh nonce), but both decrypt.
        assert_ne!(a, b);
        assert_ne!(&a[1..25], &b[1..25], "nonces must differ");
        assert_eq!(engine.decrypt_with_aad(&a, &aad).unwrap(), pt.to_vec());
        assert_eq!(engine.decrypt_with_aad(&b, &aad).unwrap(), pt.to_vec());
    }

    /// AC-F2.3 — the gate. Flipping ANY single byte of the chunk (version,
    /// nonce, ciphertext, or tag) must make decrypt return an authentication
    /// error. This proves AEAD integrity is real, not theater (F4).
    #[test]
    fn xchacha_per_byte_tamper_is_rejected() {
        let engine = XChaChaChunkEngine::new(&[5u8; 32]).unwrap();
        let plaintext = b"integrity must be real, not theater";
        let aad = test_aad();
        let good = engine.encrypt_with_aad(plaintext, &aad).unwrap();

        // Sanity: the pristine chunk decrypts.
        assert_eq!(engine.decrypt_with_aad(&good, &aad).unwrap(), plaintext.to_vec());

        // Flip every byte position in turn; each must be rejected.
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xFF;
            let res = engine.decrypt_with_aad(&bad, &aad);
            assert!(
                res.is_err(),
                "tampering byte {i} (region: {}) was NOT rejected",
                if i == 0 {
                    "version"
                } else if i < 1 + XChaChaChunkEngine::NONCE_SIZE {
                    "nonce"
                } else if i >= good.len() - XChaChaChunkEngine::TAG_SIZE {
                    "tag"
                } else {
                    "ciphertext"
                }
            );
        }
    }

    /// L-1 — the targeted version-byte flip. The old tamper test only proved
    /// `0x01 ^ 0xFF = 0xFE` is rejected (an UNKNOWN version — a parse error,
    /// not a crypto check). v2 is a VALID version, so pre-fix a v1→v2 flip
    /// decrypted cleanly. Post-fix the version byte is inside the AAD, so the
    /// flip fails the Poly1305 tag — in BOTH directions.
    #[test]
    fn xchacha_valid_version_flip_is_rejected() {
        let k_repo = [5u8; 32];
        let v1 = XChaChaChunkEngine::new(&k_repo).unwrap();
        let v2 = XChaChaChunkEngine::new(&k_repo)
            .unwrap()
            .with_format_version(ChunkFormatVersion::KeyedCdcNamingV2)
            .unwrap();
        let aad = test_aad();
        let pt = b"version byte is authenticated now";

        // v1 → v2 flip.
        let mut c1 = v1.encrypt_with_aad(pt, &aad).unwrap();
        assert_eq!(c1[0], 1);
        c1[0] = 2; // a VALID version byte — parses fine, must fail the tag
        let res = v1.decrypt_with_aad(&c1, &aad);
        match res {
            Err(VaultError::Decryption(msg)) => assert!(
                msg.contains("authentication failed"),
                "v1→v2 flip must fail the AEAD tag, not a parse check: {msg}"
            ),
            other => panic!("v1→v2 flip must be rejected, got {other:?}"),
        }

        // v2 → v1 flip.
        let mut c2 = v2.encrypt_with_aad(pt, &aad).unwrap();
        assert_eq!(c2[0], 2);
        c2[0] = 1;
        assert!(v2.decrypt_with_aad(&c2, &aad).is_err(), "v2→v1 flip must be rejected");
    }

    #[test]
    fn xchacha_truncated_chunk_is_rejected() {
        let engine = XChaChaChunkEngine::new(&[1u8; 32]).unwrap();
        let aad = test_aad();
        let good = engine.encrypt_with_aad(b"x", &aad).unwrap();
        // Any prefix shorter than version+nonce+tag is an explicit error.
        for len in 0..XChaChaChunkEngine::OVERHEAD {
            assert!(engine
                .decrypt_with_aad(&good[..len.min(good.len())], &aad)
                .is_err());
        }
    }

    #[test]
    fn xchacha_unknown_version_byte_is_rejected() {
        let engine = XChaChaChunkEngine::new(&[1u8; 32]).unwrap();
        let aad = test_aad();
        let mut chunk = engine.encrypt_with_aad(b"data", &aad).unwrap();
        chunk[0] = 3; // reserved-but-unimplemented version (v3 hybrid-wrap)
        assert!(engine.decrypt_with_aad(&chunk, &aad).is_err());
    }

    /// AC-E1.6 (updated for H-1/L-1) — the E1 keyed pipeline tags chunks v2.
    /// The version byte is now bound into the AEAD AAD, so a v1 and a v2 seal
    /// of the same (plaintext, nonce, identity) share everything EXCEPT the
    /// version byte and the Poly1305 tag — and each opens ONLY under its own
    /// observed version.
    #[test]
    fn xchacha_v2_emit_and_decrypt_round_trips() {
        let k_repo = [13u8; 32];
        let v1 = XChaChaChunkEngine::new(&k_repo).unwrap();
        let v2 = XChaChaChunkEngine::new(&k_repo)
            .unwrap()
            .with_format_version(ChunkFormatVersion::KeyedCdcNamingV2)
            .unwrap();

        let nonce = [0x41u8; XChaChaChunkEngine::NONCE_SIZE];
        let pt = b"E1 keyed pipeline chunk";
        let aad = test_aad();
        let c1 = v1.encrypt_with_nonce(pt, &nonce, &aad).unwrap();
        let c2 = v2.encrypt_with_nonce(pt, &nonce, &aad).unwrap();

        // Version bytes differ; the ciphertext body (same key/nonce/plaintext)
        // is identical; the TAG differs because the version byte is in the AAD
        // (L-1: the byte is now authenticated, not free-floating).
        assert_eq!(c1[0], 1);
        assert_eq!(c2[0], 2);
        let body = 1 + XChaChaChunkEngine::NONCE_SIZE..c1.len() - XChaChaChunkEngine::TAG_SIZE;
        assert_eq!(c1[body.clone()], c2[body]);
        assert_ne!(
            c1[c1.len() - XChaChaChunkEngine::TAG_SIZE..],
            c2[c2.len() - XChaChaChunkEngine::TAG_SIZE..],
            "tags must differ — the version byte is authenticated"
        );

        // Decrypt keys off the OBSERVED version byte, so either engine opens
        // either version (the emit_version only affects sealing).
        assert_eq!(v1.decrypt_with_aad(&c2, &aad).unwrap(), pt.to_vec());
        assert_eq!(v2.decrypt_with_aad(&c1, &aad).unwrap(), pt.to_vec());
        assert_eq!(v2.decrypt_with_aad(&c2, &aad).unwrap(), pt.to_vec());
    }

    #[test]
    fn xchacha_wrong_key_fails_auth() {
        let a = XChaChaChunkEngine::new(&[1u8; 32]).unwrap();
        let b = XChaChaChunkEngine::new(&[2u8; 32]).unwrap();
        let aad = test_aad();
        let chunk = a.encrypt_with_aad(b"secret", &aad).unwrap();
        assert!(b.decrypt_with_aad(&chunk, &aad).is_err());
    }

    /// W5a — cross-repo content-key ISOLATION at the
    /// content-key layer. Principle 2 (repository-level access isolation): a
    /// chunk's CONTENT encrypted under repo A's `K_repo` must NOT decrypt under
    /// repo B's content key, even though every repo runs the identical cipher.
    /// Existing coverage proves keyed chunk-*naming* scoping (E1) and a generic
    /// wrong-32-byte-key failure; this pins the property at the exact derivation
    /// the production path uses: `K_repo → HKDF-SHA256("gitcellar/chunk-content/v1")
    /// → content_key → XChaCha20-Poly1305`. The negative (cross-repo decrypt fails
    /// closed with an AEAD auth error) is the guarantee; the positive control
    /// (same repo round-trips) proves the negative isn't a false-fail.
    #[test]
    fn xchacha_cross_repo_content_key_isolation() {
        // Two DISTINCT per-repo root keys (stand-ins for two repos' `K_repo`,
        // each derived from a distinct repo cert's X25519 scalar in production).
        let k_repo_a = [0xA1u8; 32];
        let k_repo_b = [0xB2u8; 32];

        // The content keys the cipher actually uses are HKDF-derived and MUST
        // differ — this is the cryptographic root of repo isolation. If a future
        // change made K_repo influence the content key weakly (or not at all),
        // this assertion fails before the behavioral one does.
        let ck_a = XChaChaChunkEngine::derive_content_key(&k_repo_a).unwrap();
        let ck_b = XChaChaChunkEngine::derive_content_key(&k_repo_b).unwrap();
        assert_ne!(ck_a, ck_b, "distinct repos must derive distinct content keys");

        let repo_a = XChaChaChunkEngine::new(&k_repo_a).unwrap();
        let repo_b = XChaChaChunkEngine::new(&k_repo_b).unwrap();

        let plaintext = b"repo A confidential content - must be unreadable by repo B";
        let chunk_from_a = repo_a.encrypt(plaintext).unwrap();

        // NEGATIVE (the guarantee): repo B cannot decrypt repo A's chunk.
        let cross = repo_b.decrypt(&chunk_from_a);
        assert!(
            cross.is_err(),
            "repo B's content key decrypted repo A's chunk — repository isolation BROKEN"
        );
        // And the failure is the AEAD authentication check, not a format/length error.
        match cross {
            Err(VaultError::Decryption(msg)) => assert!(
                msg.contains("authentication failed"),
                "cross-repo decrypt must fail at the AEAD tag (got: {msg})"
            ),
            other => panic!("expected a Decryption auth error, got {other:?}"),
        }

        // POSITIVE control: repo A decrypts its own chunk (negative isn't a false-fail).
        assert_eq!(repo_a.decrypt(&chunk_from_a).unwrap(), plaintext.to_vec());

        // Symmetric: a chunk from B is equally opaque to A (isolation is mutual).
        let chunk_from_b = repo_b.encrypt(plaintext).unwrap();
        assert!(repo_a.decrypt(&chunk_from_b).is_err());
        assert_eq!(repo_b.decrypt(&chunk_from_b).unwrap(), plaintext.to_vec());
    }

    #[test]
    fn xchacha_empty_and_large_payloads_round_trip() {
        let engine = XChaChaChunkEngine::new(&[4u8; 32]).unwrap();
        // Empty plaintext: valid AEAD, chunk = exactly OVERHEAD bytes.
        let empty = engine.encrypt(b"").unwrap();
        assert_eq!(empty.len(), XChaChaChunkEngine::OVERHEAD);
        assert_eq!(engine.decrypt(&empty).unwrap(), Vec::<u8>::new());
        // 1 MiB payload.
        let big: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();
        let enc = engine.encrypt(&big).unwrap();
        assert_eq!(engine.decrypt(&enc).unwrap(), big);
    }

    #[test]
    fn xchacha_encrypt_chunk_trait_round_trips_with_aad() {
        let engine = XChaChaChunkEngine::new(&[8u8; 32]).unwrap();
        let chunk = Chunk {
            hash: "deadbeef".to_string(),
            data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            size: 8,
            offset: 0,
        };
        let aad = ChunkAad::for_content_chunk("alice/proj", &chunk.hash, chunk.size as u64);
        let enc = engine.encrypt_chunk(&chunk, &aad).unwrap();
        assert_eq!(engine.decrypt_chunk(&enc, &aad).unwrap(), chunk.data);
        // Opening under a different repo's identity fails closed.
        let other = ChunkAad::for_content_chunk("bob/proj", &chunk.hash, chunk.size as u64);
        assert!(engine.decrypt_chunk(&enc, &other).is_err());
    }

    /// AC-F2.4 — the published, deterministic test vector reproduces bit-for-bit.
    /// Asserts the engine matches `test-vectors/chunk-format-v1.json`, the
    /// publishable fixture (E3 AC-E3.3 consumer).
    #[test]
    fn xchacha_published_test_vector_reproduces() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../test-vectors/chunk-format-v1.json"))
                .expect("fixture parses");

        let k_repo = hex_to_vec(fixture["k_repo_hex"].as_str().unwrap());
        let content_key = hex_to_vec(fixture["content_key_hex"].as_str().unwrap());
        let nonce_v = hex_to_vec(fixture["nonce_hex"].as_str().unwrap());
        let plaintext = fixture["plaintext_utf8"].as_str().unwrap().as_bytes();
        let expected_chunk = hex_to_vec(fixture["chunk_hex"].as_str().unwrap());
        let fx_aad = &fixture["aad"];
        let expected_cipher_aad = hex_to_vec(fx_aad["cipher_aad_hex"].as_str().unwrap());

        // Cross-check the fixture against this test's own constants.
        assert_eq!(k_repo, hex_to_vec(TV_K_REPO_HEX));
        assert_eq!(nonce_v, hex_to_vec(TV_NONCE_HEX));
        assert_eq!(plaintext, TV_PLAINTEXT);
        assert_eq!(fx_aad["repo_id"].as_str().unwrap(), TV_AAD_REPO_ID);
        assert_eq!(fx_aad["chunk_name"].as_str().unwrap(), TV_AAD_CHUNK_NAME);
        assert_eq!(fx_aad["stream_offset"].as_u64().unwrap(), 0);
        assert_eq!(fx_aad["size"].as_u64().unwrap(), TV_PLAINTEXT.len() as u64);

        // Step 1: HKDF-SHA256(K_repo, "gitcellar/chunk-content/v1") == content key.
        let derived = XChaChaChunkEngine::derive_content_key(&k_repo).unwrap();
        assert_eq!(derived.to_vec(), content_key, "HKDF content-key mismatch");

        // Step 2: the published cipher-AAD bytes == version_byte ‖ canonical(ChunkAad) (H-1).
        let aad = tv_aad();
        let mut cipher_aad = vec![V1_XCHACHA20_POLY1305];
        cipher_aad.extend_from_slice(&aad.canonical_aad_bytes());
        assert_eq!(cipher_aad, expected_cipher_aad, "published cipher-AAD mismatch");

        // Step 3: (content_key, nonce, plaintext, aad) → exact chunk bytes.
        let mut nonce = [0u8; XChaChaChunkEngine::NONCE_SIZE];
        nonce.copy_from_slice(&nonce_v);
        let engine = XChaChaChunkEngine::from_content_key(&content_key).unwrap();
        let chunk = engine.encrypt_with_nonce(plaintext, &nonce, &aad).unwrap();
        assert_eq!(chunk, expected_chunk, "published chunk vector mismatch");

        // Step 4: it round-trips under the same identity, and NOT without it.
        assert_eq!(engine.decrypt_with_aad(&chunk, &aad).unwrap(), plaintext.to_vec());
        assert!(engine.decrypt(&chunk).is_err(), "vector chunk is identity-bound");
    }

    /// One-shot generator for the published fixture. Ignored by default; run with
    /// `cargo test -p vault-core gen_published_test_vector -- --ignored --nocapture`
    /// to (re)materialize `test-vectors/chunk-format-v1.json`. Kept in-tree so the
    /// fixture is reproducible from source, never hand-edited.
    #[test]
    #[ignore]
    fn gen_published_test_vector() {
        let k_repo = hex_to_vec(TV_K_REPO_HEX);
        let content_key = XChaChaChunkEngine::derive_content_key(&k_repo).unwrap();
        let mut nonce = [0u8; XChaChaChunkEngine::NONCE_SIZE];
        nonce.copy_from_slice(&hex_to_vec(TV_NONCE_HEX));
        let engine = XChaChaChunkEngine::from_content_key(&content_key).unwrap();
        let aad = tv_aad();
        let mut cipher_aad = vec![V1_XCHACHA20_POLY1305];
        cipher_aad.extend_from_slice(&aad.canonical_aad_bytes());
        let chunk = engine.encrypt_with_nonce(TV_PLAINTEXT, &nonce, &aad).unwrap();
        println!("content_key_hex = {}", hex::encode(content_key));
        println!("cipher_aad_hex  = {}", hex::encode(&cipher_aad));
        println!("chunk_hex       = {}", hex::encode(&chunk));
    }

    // ========================================================================
    // AES-256-GCM `.gckey` / FFI passphrase engine (NOT chunks)
    // ========================================================================

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = AesEncryptionEngine::generate_key();
        let engine = AesEncryptionEngine::new(&key).unwrap();

        let plaintext = b"Hello, encrypted world!";
        let encrypted = engine.encrypt(plaintext).unwrap();
        let decrypted = engine.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_aes_different_nonces() {
        let key = AesEncryptionEngine::generate_key();
        let engine = AesEncryptionEngine::new(&key).unwrap();

        let plaintext = b"Same plaintext";
        let encrypted1 = engine.encrypt(plaintext).unwrap();
        let encrypted2 = engine.encrypt(plaintext).unwrap();

        // Same plaintext should produce different ciphertext (different nonces)
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt correctly
        assert_eq!(engine.decrypt(&encrypted1).unwrap(), plaintext.to_vec());
        assert_eq!(engine.decrypt(&encrypted2).unwrap(), plaintext.to_vec());
    }

    #[test]
    fn test_aes_invalid_key_size() {
        let short_key = [0u8; 16]; // 128-bit key, should fail
        let result = AesEncryptionEngine::new(&short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes_key_derivation() {
        let passphrase = b"my-secure-passphrase";
        let salt = AesEncryptionEngine::generate_salt();

        let key1 = AesEncryptionEngine::derive_key(passphrase, &salt).unwrap();
        let key2 = AesEncryptionEngine::derive_key(passphrase, &salt).unwrap();

        // Same passphrase + salt should produce same key
        assert_eq!(key1, key2);

        // Different salt should produce different key
        let different_salt = AesEncryptionEngine::generate_salt();
        let key3 = AesEncryptionEngine::derive_key(passphrase, &different_salt).unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_aes_chunk_encryption() {
        let key = AesEncryptionEngine::generate_key();
        let engine = AesEncryptionEngine::new(&key).unwrap();

        let chunk = Chunk {
            hash: "abc123".to_string(),
            data: vec![1, 2, 3, 4, 5],
            size: 5,
            offset: 0,
        };
        let aad = ChunkAad::for_content_chunk("alice/proj", &chunk.hash, chunk.size as u64);

        let encrypted = engine.encrypt_chunk(&chunk, &aad).unwrap();
        let decrypted = engine.decrypt_chunk(&encrypted, &aad).unwrap();
        assert_eq!(chunk.data, decrypted);

        // Identity mismatch fails closed here too (no engine ignores the AAD).
        let other = ChunkAad::for_content_chunk("alice/proj", "def456", chunk.size as u64);
        assert!(engine.decrypt_chunk(&encrypted, &other).is_err());
    }

    #[test]
    fn test_aes_large_data() {
        let key = AesEncryptionEngine::generate_key();
        let engine = AesEncryptionEngine::new(&key).unwrap();

        // 1MB of random-ish data
        let plaintext: Vec<u8> = (0..1024 * 1024).map(|i| (i % 256) as u8).collect();

        let encrypted = engine.encrypt(&plaintext).unwrap();
        let decrypted = engine.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_aes_tampered_ciphertext() {
        let key = AesEncryptionEngine::generate_key();
        let engine = AesEncryptionEngine::new(&key).unwrap();

        let plaintext = b"Original data";
        let mut encrypted = engine.encrypt(plaintext).unwrap();

        // Tamper with ciphertext
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;

        // Decryption should fail (authentication tag won't match)
        let result = engine.decrypt(&encrypted);
        assert!(result.is_err());
    }
}
