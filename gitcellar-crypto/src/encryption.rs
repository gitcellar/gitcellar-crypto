//! Chunk encryption and decryption
//!
//! Provides Sequoia-based encryption for GitCellar chunks.
//! All encryption uses the identity stored in GitCellar's config directory.

use crate::error::{CryptoError, Result};
use crate::Identity;
use sequoia_openpgp as openpgp;
use openpgp::crypto::SessionKey;
use openpgp::crypto::mpi;
use openpgp::packet::key::SecretKeyMaterial;
use openpgp::parse::Parse;
use openpgp::parse::stream::{DecryptorBuilder, MessageLayer, MessageStructure};
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message};
use sha2::Sha256;
use std::io::Write;
use std::sync::Arc;
use tracing::{debug, info};
use hkdf::Hkdf;
use vault_core::chunk_format::{ChunkAad, ChunkFormatVersion};
use vault_core::chunking::{Chunk, ChunkKeying};
// vault-core's single chunk engine (F2). Chunk seal/open goes through the
// engine's inherent AAD-bound methods (`encrypt_with_aad`/`decrypt_with_aad`,
// H-1), so the vault-core trait itself is no longer imported here.
use vault_core::encryption::XChaChaChunkEngine;
use zeroize::Zeroizing;

/// Encryption engine using Sequoia OpenPGP
pub struct EncryptionEngine {
    identity: Identity,
    policy: StandardPolicy<'static>,
}

impl EncryptionEngine {
    /// Create an encryption engine from an identity
    pub fn new(identity: Identity) -> Result<Self> {
        if !identity.has_encryption_key() {
            return Err(CryptoError::NoEncryptionKey);
        }

        Ok(Self {
            identity,
            policy: StandardPolicy::new(),
        })
    }

    /// Create an encryption engine from the default identity location
    ///
    /// Loads identity for the active user from `~/.config/gitcellar/users/{username}/identity/`
    pub fn from_default_identity() -> Result<Self> {
        let identity = gitcellar_identity::identity::load_active()?;
        Self::new(identity)
    }

    /// Create an encryption engine directly from a Sequoia Cert
    ///
    /// This bypasses the Identity wrapper and works directly with the Cert.
    /// Used primarily for per-repository keys that aren't stored in the identity dir.
    pub fn from_cert(cert: openpgp::Cert) -> Result<Self> {
        // Create identity from cert without serialization round-trip
        let user_id = cert.userids()
            .next()
            .and_then(|uid| String::from_utf8(uid.userid().value().to_vec()).ok())
            .unwrap_or_else(|| "unknown".to_string());

        let identity = Identity::from_cert(cert, user_id)?;

        // Skip has_encryption_key check - the encryption will fail naturally if no keys
        Ok(Self {
            identity,
            policy: StandardPolicy::new(),
        })
    }

    /// Get the identity used by this engine
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Get the fingerprint of the identity
    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    /// Get the key ID of the identity
    pub fn key_id(&self) -> String {
        self.identity.key_id()
    }

    /// Export the public key as ASCII-armored string
    pub fn export_public_key(&self) -> Result<String> {
        Ok(self.identity.export_public_key()?)
    }

    /// Encrypt arbitrary data
    pub fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        debug!("Encrypting {} bytes", data.len());

        let cert = self.identity.cert();

        // Get encryption-capable subkeys
        let recipients: Vec<_> = cert
            .keys()
            .with_policy(&self.policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .collect();

        if recipients.is_empty() {
            return Err(CryptoError::NoEncryptionKey);
        }

        // Create encrypted output
        let mut encrypted_data = Vec::new();

        {
            let message = Message::new(&mut encrypted_data);
            let message = Armorer::new(message).build()
                .map_err(|e| CryptoError::Encryption(format!("Failed to create armor writer: {}", e)))?;

            let message = Encryptor::for_recipients(message, recipients)
                .build()
                .map_err(|e| CryptoError::Encryption(format!("Failed to create encryptor: {}", e)))?;

            let mut message = LiteralWriter::new(message)
                .build()
                .map_err(|e| CryptoError::Encryption(format!("Failed to create literal writer: {}", e)))?;

            message.write_all(data)
                .map_err(|e| CryptoError::Encryption(format!("Failed to write data: {}", e)))?;

            message.finalize()
                .map_err(|e| CryptoError::Encryption(format!("Failed to finalize: {}", e)))?;
        }

        debug!("Encrypted {} bytes → {} bytes", data.len(), encrypted_data.len());

        Ok(encrypted_data)
    }

    /// Decrypt data
    pub fn decrypt_data(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        debug!("Decrypting {} bytes", encrypted_data.len());

        // Create decryption helper
        struct Helper<'a> {
            policy: &'a dyn Policy,
            identity: &'a Identity,
        }

        impl<'a> openpgp::parse::stream::DecryptionHelper for Helper<'a> {
            fn decrypt(
                &mut self,
                pkesks: &[openpgp::packet::PKESK],
                _skesks: &[openpgp::packet::SKESK],
                sym_algo: Option<openpgp::types::SymmetricAlgorithm>,
                decrypt: &mut dyn FnMut(
                    Option<openpgp::types::SymmetricAlgorithm>,
                    &SessionKey,
                ) -> bool,
            ) -> openpgp::Result<Option<openpgp::Cert>> {
                let cert = self.identity.cert();

                for pkesk in pkesks {
                    for ka in cert
                        .keys()
                        .with_policy(self.policy, None)
                        .supported()
                        .for_transport_encryption()
                        .for_storage_encryption()
                        .secret()
                    {
                        let mut keypair = ka
                            .key()
                            .clone()
                            .into_keypair()
                            .map_err(|e| openpgp::Error::InvalidKey(format!("Failed to create keypair: {}", e)))?;

                        if let Some((algo, session_key)) = pkesk.decrypt(&mut keypair, sym_algo) {
                            if decrypt(algo, &session_key) {
                                return Ok(None);
                            }
                        }
                    }
                }

                Err(openpgp::Error::MissingSessionKey(
                    "Failed to decrypt: no matching secret key found".to_string()
                ).into())
            }
        }

        impl<'a> openpgp::parse::stream::VerificationHelper for Helper<'a> {
            fn get_certs(
                &mut self,
                _ids: &[openpgp::KeyHandle],
            ) -> openpgp::Result<Vec<openpgp::Cert>> {
                Ok(vec![self.identity.cert().clone()])
            }

            fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
                // F4 / R-2: this is the key-grant decryption path (NOT chunks —
                // chunk integrity is now the XChaCha20-Poly1305 tag, F2). Key
                // grants are encrypt-only: confidentiality comes from the SEIPD
                // packet's own integrity protection, and there is no enclosed
                // signature to verify. So we do NOT return a blanket `Ok(())`
                // that *pretends* to verify a signature (the old no-op was
                // integrity theater). Instead we walk the structure and fail
                // loudly if an unexpected signature layer appears.
                for layer in structure.iter() {
                    match layer {
                        MessageLayer::Encryption { .. } => { /* expected: confidentiality */ }
                        MessageLayer::Compression { .. } => { /* benign */ }
                        MessageLayer::SignatureGroup { .. } => {
                            return Err(openpgp::Error::BadSignature(
                                "unexpected OpenPGP signature layer on an encryption-only \
                                 key-grant payload; this path verifies confidentiality, not \
                                 signatures"
                                    .to_string(),
                            )
                            .into());
                        }
                    }
                }
                Ok(())
            }
        }

        let helper = Helper {
            policy: &self.policy,
            identity: &self.identity,
        };

        let mut decryptor = DecryptorBuilder::from_bytes(encrypted_data)
            .map_err(|e| CryptoError::Decryption(format!("Failed to parse message: {}", e)))?
            .with_policy(&self.policy, None, helper)
            .map_err(|e| CryptoError::Decryption(format!("Failed to create decryptor: {}", e)))?;

        let mut decrypted_data = Vec::new();
        std::io::copy(&mut decryptor, &mut decrypted_data)
            .map_err(|e| CryptoError::Decryption(format!("Failed to read decrypted data: {}", e)))?;

        debug!("Decrypted {} bytes → {} bytes", encrypted_data.len(), decrypted_data.len());

        Ok(decrypted_data)
    }

    // ========================================================================
    // Chunk encryption — XChaCha20-Poly1305 AEAD (F2, crypto-hardening P1)
    //
    // Chunks are NO LONGER OpenPGP. The chunk data path is a single
    // XChaCha20-Poly1305 AEAD per chunk (vault-core `XChaChaChunkEngine`),
    // emitting the versioned `[ver][24B nonce][ct][16B tag]` chunk-format-v1
    // layout — no SEIPD packet, no ASCII armor (F3). OpenPGP (above) is retained
    // ONLY for identity/signing/key-wrap (`encrypt_data`/`decrypt_data`/
    // `sign_data`), never for chunk content.
    // ========================================================================

    /// HKDF `info` for the per-repo root `K_repo` (I-2). Versioned: `v2` is the
    /// HKDF construction; `v1` was the retired bare `SHA-256(tag ‖ scalar)`.
    /// Bumping this re-derives every repo content key and makes all previously
    /// written chunks/packs undecryptable — only ever change it together with a
    /// dev-data reset (pre-launch) or a real migration (post-launch).
    pub const K_REPO_INFO: &'static [u8] = b"gitcellar/krepo/v2";

    /// Derive the per-repo content-encryption root `K_repo`.
    ///
    /// `K_repo = HKDF-SHA256(ikm = x25519_secret_scalar, salt = None,
    /// info = "gitcellar/krepo/v2", 32)`, where the scalar is taken from this
    /// identity's X25519 (Cv25519 ECDH) encryption subkey secret material.
    ///
    /// ## I-2 — why HKDF, and why v2 (2026-07-15 pre-launch hardening)
    ///
    /// v1 was `SHA-256("gitcellar/k-repo/v1" ‖ scalar)` — a bare
    /// hash-of-concatenation. That is the classic **length-extension shape**:
    /// SHA-256 is a Merkle–Damgård construction, so from `H(tag ‖ scalar)` an
    /// attacker who learns the digest can compute `H(tag ‖ scalar ‖ padding ‖
    /// suffix)` WITHOUT knowing the scalar. It was benign here only by accident
    /// of use (the digest is never published, the scalar is fixed-length, and
    /// no attacker-controlled data follows it in the preimage) — i.e. the
    /// construction was load-bearing on its context rather than on itself. A
    /// bare hash is also not a KDF: it makes no PRF claim about its output, so
    /// every downstream `HKDF(K_repo, …)` sub-key (E1 naming/boundary keys, the
    /// F2 content key) inherited that weaker footing.
    ///
    /// HKDF-SHA256 is HMAC-based (RFC 5869): the extract step keys HMAC with
    /// the salt and the scalar as IKM, so the length-extension shape is gone by
    /// construction and the output carries a real PRF claim. Domain separation
    /// moves from a hashed prefix into HKDF's `info` parameter — the same
    /// discipline `derive_e1_key` already applies to every sub-key of this root
    /// (`salt = None`, versioned `info`), so the whole key ladder is now one
    /// consistent construction rather than a bare hash with HKDF bolted on top.
    ///
    /// **This is a BREAKING at-rest change, by design.** v2 derives a different
    /// `K_repo` from the same cert, so every chunk/pack written under v1 is
    /// undecryptable — exactly like H-1/H-2. Done pre-launch (no real users) to
    /// avoid a migration later. The `info` string carries the version: bumping
    /// it is the only supported way to change this derivation, and doing so
    /// requires a coordinated dev-data reset.
    ///
    /// Properties this relies on:
    ///
    /// - **Deterministic** for a given cert → encrypt and decrypt derive the same
    ///   key; the chunk round-trips.
    /// - **Shared by every key-holder** — collaborators import the same per-repo
    ///   keypair, so they derive the same `K_repo` (per-repo dedup/decrypt holds).
    /// - **Never available to the provider** — it requires the secret scalar.
    /// - **Domain-separated** by the versioned `info` string, so the scalar bytes
    ///   cannot collide with any other use of the same secret.
    ///
    /// The content key the chunk cipher actually uses is one further HKDF-SHA256
    /// step on top of this (`gitcellar/chunk-content/v1`), done inside
    /// `XChaChaChunkEngine` (AC-F2.2).
    fn derive_k_repo(&self) -> Result<Zeroizing<[u8; 32]>> {
        let cert = self.identity.cert();

        // P2-8: K_repo is derived from the secret scalar
        // of *the* transport-encryption subkey. If a cert carries MORE THAN ONE
        // transport-encryption subkey, `.next()` would silently pick whichever the
        // key iterator yields first — an order-dependent choice that can diverge
        // between two parties (or between encrypt and decrypt), yielding different
        // content keys and undecryptable chunks. GitCellar repo certs are
        // generated with exactly one transport-encryption subkey, so a cert with
        // two is malformed/adversarial: refuse to derive rather than guess.
        //
        // F-8 (hardening review, Aug 2026): the filter carries `.alive()` +
        // `.revoked(false)` so it matches `encrypt_data` (`:104-112`) exactly.
        // Without them the guard counted REVOKED and EXPIRED subkeys as
        // ambiguity, which turned any legitimate encryption-subkey rotation
        // (add new, revoke old) into a permanent refusal to derive `K_repo` —
        // i.e. into data loss, since `K_repo` gates the content key, the naming
        // key, the boundary key and the object-key prefix. It also let `K_repo`
        // derive from an expired subkey that `encrypt_data` would refuse to
        // encrypt to, so the two filters disagreed about which key is "the"
        // encryption key.
        let kas: Vec<_> = cert
            .keys()
            .with_policy(&self.policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .secret()
            .collect();
        if kas.len() > 1 {
            return Err(CryptoError::Encryption(format!(
                "ambiguous repo cert: {} live, unrevoked transport-encryption subkeys with \
                 secret material (expected exactly 1) — refusing to derive K_repo, as the \
                 choice would be order-dependent and diverge between parties",
                kas.len()
            )));
        }
        let ka = kas.into_iter().next().ok_or(CryptoError::NoEncryptionKey)?;

        let scalar: Zeroizing<Vec<u8>> = match ka.key().optional_secret() {
            Some(SecretKeyMaterial::Unencrypted(unenc)) => unenc.map(|s| match s {
                mpi::SecretKeyMaterial::ECDH { scalar } => {
                    Ok(Zeroizing::new(scalar.value().to_vec()))
                }
                other => Err(CryptoError::Encryption(format!(
                    "repo encryption subkey secret is not ECDH: {:?}",
                    other
                ))),
            }),
            Some(SecretKeyMaterial::Encrypted(_)) => Err(CryptoError::Encryption(
                "repo encryption subkey secret is password-encrypted; cannot derive content key"
                    .to_string(),
            )),
            None => Err(CryptoError::NoEncryptionKey),
        }?;

        // I-2: HKDF-SHA256 over the scalar as IKM. `salt = None` (RFC 5869's
        // all-zero salt) matches `derive_e1_key`; the versioned `info` string is
        // what separates this domain. NOT a bare `SHA-256(tag ‖ scalar)` — see
        // the fn docs for why that shape is gone.
        let hk = Hkdf::<Sha256>::new(None, &scalar);
        let mut k_repo = Zeroizing::new([0u8; 32]);
        hk.expand(Self::K_REPO_INFO, &mut *k_repo).map_err(|e| {
            CryptoError::Encryption(format!("K_repo HKDF-SHA256 expand failed: {}", e))
        })?;
        Ok(k_repo)
    }

    /// Build the chunk AEAD engine bound to this identity's per-repo content key.
    fn chunk_engine(&self) -> Result<XChaChaChunkEngine> {
        let k_repo = self.derive_k_repo()?;
        XChaChaChunkEngine::new(&*k_repo)
            .map_err(|e| CryptoError::Encryption(format!("chunk cipher init failed: {}", e)))
    }

    // ========================================================================
    // E1 — keyed chunk naming + keyed CDC (crypto-hardening P2)
    //
    // Two further HKDF-SHA256 outputs from the same per-repo root `K_repo`,
    // domain-separated from the F2 content key by distinct versioned `info`
    // strings (AC-E1.5). They are independent (Borg's "independent keys per
    // purpose" rule): the provider receives none of them.
    //   id_key_repo       = HKDF(K_repo, "gitcellar/chunk-name/v1",   32)  → HMAC names (AC-E1.1)
    //   boundary_key_repo = HKDF(K_repo, "gitcellar/cdc-boundary/v1", 32)  → keyed Gear table (AC-E1.2)
    // E1 chunks are tagged with F6 version byte v2 (same XChaCha20-Poly1305
    // payload as v1; the marker records the keyed pipeline — AC-E1.6).
    // ========================================================================

    /// HKDF `info` for `id_key_repo` (keyed chunk naming; AC-E1.1/E1.5).
    pub const E1_ID_KEY_INFO: &'static [u8] = b"gitcellar/chunk-name/v1";

    /// HKDF `info` for `boundary_key_repo` (keyed FastCDC Gear table; AC-E1.2/E1.5).
    pub const E1_BOUNDARY_KEY_INFO: &'static [u8] = b"gitcellar/cdc-boundary/v1";

    /// HKDF `info` for `id_key_repo_prefix` (P1-4b storage-key opaquing).
    ///
    /// Domain-separated from the F2 content key and the E1 naming/CDC keys by
    /// this distinct versioned string, so the same `K_repo` root yields an
    /// independent sub-key for the object-key prefix (Borg's "independent keys
    /// per purpose"). The provider/storage backend never receives it.
    pub const OBJECT_KEY_PREFIX_INFO: &'static [u8] = b"gitcellar/object-key-prefix/v1";

    /// Derive the **opaque storage object-key prefix segment** for `repo_id`
    /// (P1-4b). Replaces the plaintext `{owner}/{name}` path segment so a bucket
    /// `LIST` cannot enumerate repo identity.
    ///
    /// `prefix = hex(HMAC-SHA256(id_key_repo_prefix, repo_id))`, where
    /// `id_key_repo_prefix = HKDF-SHA256(K_repo, "gitcellar/object-key-prefix/v1")`.
    ///
    /// Properties inherited from [`derive_k_repo`](Self::derive_k_repo):
    /// - **Deterministic** per cert → the same prefix every time (list/delete/move
    ///   by prefix all recompute it).
    /// - **Shared by every key-holder** of *this* cert (collaborators agree).
    /// - **Provider-opaque + non-reversible** — the HMAC key requires the X25519
    ///   secret scalar; the provider sees only the hex digest.
    ///
    /// `repo_id` is the HMAC *message*, so a rename/transfer (different `repo_id`,
    /// same cert) yields a different prefix — exactly why the storage layer
    /// recomputes both old and new prefixes on a move. A key **rotation**
    /// (different cert, same `repo_id`) also yields a different prefix; the
    /// storage layer therefore tracks one prefix per key-version (active for
    /// writes, all versions for read-fallback / list / delete / move sweeps).
    pub fn derive_object_key_prefix(&self, repo_id: &str) -> Result<String> {
        let k_repo = self.derive_k_repo()?;
        let id_key = Self::derive_e1_key(&*k_repo, Self::OBJECT_KEY_PREFIX_INFO)?;
        Ok(object_key_prefix_hex(&id_key, repo_id))
    }

    /// `HKDF-SHA256(K_repo, info, 32)` — one E1 sub-key. No salt; domain
    /// separation is carried by the versioned `info` string, matching the F2
    /// content-key derivation.
    fn derive_e1_key(k_repo: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let hk = Hkdf::<Sha256>::new(None, k_repo);
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(info, &mut *okm)
            .map_err(|e| CryptoError::Encryption(format!("E1 HKDF-SHA256 expand failed: {}", e)))?;
        Ok(okm)
    }

    /// Build this repo's [`ChunkKeying`] — the keyed Gear table
    /// (`boundary_key_repo`) + HMAC naming key (`id_key_repo`) the keyed
    /// `StreamChunker` uses for E1 boundaries and chunk names (AC-E1.1/E1.2).
    ///
    /// Deterministic per identity/cert and shared by every key-holder, exactly
    /// like [`derive_k_repo`](Self::derive_k_repo), so per-repo dedup and decrypt
    /// hold across collaborators.
    pub fn chunk_keying(&self) -> Result<ChunkKeying> {
        let k_repo = self.derive_k_repo()?;
        let id_key = Self::derive_e1_key(&*k_repo, Self::E1_ID_KEY_INFO)?;
        let boundary_key = Self::derive_e1_key(&*k_repo, Self::E1_BOUNDARY_KEY_INFO)?;
        Ok(ChunkKeying::derive(&boundary_key, &id_key))
    }

    /// The E1 chunk AEAD engine — identical XChaCha20-Poly1305 cipher as
    /// [`chunk_engine`](Self::chunk_engine) but emits F6 version byte v2 to mark
    /// the keyed pipeline (AC-E1.6).
    fn chunk_engine_e1(&self) -> Result<XChaChaChunkEngine> {
        let k_repo = self.derive_k_repo()?;
        XChaChaChunkEngine::new(&*k_repo)
            .and_then(|e| e.with_format_version(ChunkFormatVersion::KeyedCdcNamingV2))
            .map_err(|e| CryptoError::Encryption(format!("E1 chunk cipher init failed: {}", e)))
    }

    /// Build the H-1 identity AAD for a content chunk of `repo_id`: binds the
    /// repo, the keyed HMAC chunk name, and the plaintext size. `stream_offset`
    /// is fixed to 0 by [`ChunkAad::for_content_chunk`] because keyed-name
    /// dedup stores one blob for many stream positions (see `ChunkAad` docs).
    fn content_chunk_aad(repo_id: &str, chunk: &Chunk) -> ChunkAad {
        ChunkAad::for_content_chunk(repo_id, &chunk.hash, chunk.size as u64)
    }

    /// Encrypt an E1 chunk (XChaCha20-Poly1305, F6 v2), binding the chunk's
    /// identity (`aad`) into the AEAD tag (H-1). The chunk's name is the keyed
    /// HMAC produced upstream by the keyed `StreamChunker`; this step encrypts
    /// content and authenticates identity. Decryptable by
    /// [`decrypt_chunk`](Self::decrypt_chunk) under the SAME identity;
    /// version-agnostic (v1|v2).
    pub fn encrypt_chunk_e1(&self, chunk: &Chunk, aad: &ChunkAad) -> Result<Vec<u8>> {
        let engine = self.chunk_engine_e1()?;
        engine
            .encrypt_with_aad(&chunk.data, aad)
            .map_err(|e| CryptoError::Encryption(format!("E1 chunk encryption failed: {}", e)))
    }

    /// Encrypt many E1 chunks of `repo_id` in parallel (XChaCha20-Poly1305,
    /// F6 v2), each identity-bound via its own [`ChunkAad`] (H-1). Mirrors
    /// [`encrypt_chunks_parallel`](Self::encrypt_chunks_parallel) with the v2
    /// engine.
    pub async fn encrypt_chunks_e1_parallel(
        &self,
        repo_id: &str,
        chunks: &[Chunk],
    ) -> Result<Vec<Vec<u8>>> {
        info!("Encrypting {} E1 chunks in parallel", chunks.len());
        let engine = Arc::new(self.chunk_engine_e1()?);

        let mut tasks = Vec::new();
        for chunk in chunks {
            let data = chunk.data.clone();
            let aad = Self::content_chunk_aad(repo_id, chunk);
            let engine = Arc::clone(&engine);
            tasks.push(tokio::task::spawn_blocking(move || {
                engine.encrypt_with_aad(&data, &aad)
            }));
        }

        let mut encrypted_chunks = Vec::new();
        for task in tasks {
            let encrypted = task
                .await
                .map_err(|e| CryptoError::Encryption(format!("Task failed: {}", e)))?
                .map_err(|e| CryptoError::Encryption(format!("E1 chunk encryption failed: {}", e)))?;
            encrypted_chunks.push(encrypted);
        }
        Ok(encrypted_chunks)
    }

    /// Encrypt a chunk with XChaCha20-Poly1305 (chunk-format v1), binding the
    /// chunk's identity (`aad`) into the AEAD tag (H-1).
    pub fn encrypt_chunk(&self, chunk: &Chunk, aad: &ChunkAad) -> Result<Vec<u8>> {
        debug!(
            "Encrypting chunk: {} ({} bytes)",
            &chunk.hash[..16.min(chunk.hash.len())],
            chunk.size
        );
        let engine = self.chunk_engine()?;
        engine
            .encrypt_with_aad(&chunk.data, aad)
            .map_err(|e| CryptoError::Encryption(format!("Chunk encryption failed: {}", e)))
    }

    /// Decrypt chunk data, authenticating it against the manifest-derived
    /// identity `aad` (H-1). The XChaCha20-Poly1305 tag is the integrity check:
    /// a tampered, wrong-key, or identity-mismatched (spliced / wrong-repo /
    /// version-flipped) chunk yields an authentication error (F4/H-1/L-1).
    pub fn decrypt_chunk(&self, encrypted_data: &[u8], aad: &ChunkAad) -> Result<Vec<u8>> {
        let engine = self.chunk_engine()?;
        engine
            .decrypt_with_aad(encrypted_data, aad)
            .map_err(|e| CryptoError::Decryption(format!("Chunk decryption failed: {}", e)))
    }

    /// Encrypt multiple chunks of `repo_id` in parallel (v1), each
    /// identity-bound via its own [`ChunkAad`] (H-1).
    pub async fn encrypt_chunks_parallel(
        &self,
        repo_id: &str,
        chunks: &[Chunk],
    ) -> Result<Vec<Vec<u8>>> {
        info!("Encrypting {} chunks in parallel", chunks.len());

        // Derive the per-repo content key once; the cipher clones cheaply into
        // each blocking task (XChaCha20-Poly1305 is Send + Sync + Clone).
        let engine = Arc::new(self.chunk_engine()?);

        let mut tasks = Vec::new();
        for chunk in chunks {
            let data = chunk.data.clone();
            let aad = Self::content_chunk_aad(repo_id, chunk);
            let engine = Arc::clone(&engine);
            tasks.push(tokio::task::spawn_blocking(move || {
                engine.encrypt_with_aad(&data, &aad)
            }));
        }

        let mut encrypted_chunks = Vec::new();
        for task in tasks {
            let encrypted = task
                .await
                .map_err(|e| CryptoError::Encryption(format!("Task failed: {}", e)))?
                .map_err(|e| CryptoError::Encryption(format!("Chunk encryption failed: {}", e)))?;
            encrypted_chunks.push(encrypted);
        }

        info!("Encrypted {} chunks successfully", encrypted_chunks.len());
        Ok(encrypted_chunks)
    }

    /// Decrypt multiple chunks in parallel, authenticating each against its
    /// manifest-derived identity (H-1). `aads` pairs positionally with
    /// `encrypted_chunks`.
    pub async fn decrypt_chunks_parallel(
        &self,
        encrypted_chunks: &[Vec<u8>],
        aads: &[ChunkAad],
    ) -> Result<Vec<Vec<u8>>> {
        info!("Decrypting {} chunks in parallel", encrypted_chunks.len());
        if encrypted_chunks.len() != aads.len() {
            return Err(CryptoError::Decryption(format!(
                "chunk/AAD count mismatch: {} chunks but {} identities",
                encrypted_chunks.len(),
                aads.len()
            )));
        }

        let engine = Arc::new(self.chunk_engine()?);

        let mut tasks = Vec::new();
        for (encrypted_data, aad) in encrypted_chunks.iter().zip(aads.iter()) {
            let encrypted_data = encrypted_data.clone();
            let aad = aad.clone();
            let engine = Arc::clone(&engine);
            tasks.push(tokio::task::spawn_blocking(move || {
                engine.decrypt_with_aad(&encrypted_data, &aad)
            }));
        }

        let mut decrypted_chunks = Vec::new();
        for task in tasks {
            let decrypted = task
                .await
                .map_err(|e| CryptoError::Decryption(format!("Task failed: {}", e)))?
                .map_err(|e| CryptoError::Decryption(format!("Chunk decryption failed: {}", e)))?;
            decrypted_chunks.push(decrypted);
        }

        info!("Decrypted {} chunks successfully", decrypted_chunks.len());
        Ok(decrypted_chunks)
    }

    /// Sign data (for protocol message authentication)
    ///
    /// Creates a detached OpenPGP signature over the provided data.
    /// For detached signatures, we write directly to the Signer (no LiteralWriter).
    pub fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        use openpgp::serialize::stream::{Signer, Message};

        debug!("Signing {} bytes", data.len());

        let cert = self.identity.cert();

        // Find THE signing-capable key.
        //
        // F-7 (hardening review, Aug 2026): this used a bare `.next()` with no
        // `.alive()` / `.revoked(false)`, which meant (a) a revoked or expired
        // signing subkey holding secret material was still eligible — this side
        // would happily emit signatures that every verifier rejects under
        // `StandardPolicy`, a self-DoS surfacing simultaneously across grants,
        // key assertions, audit entries, repo-owner bindings and checkpoints —
        // and (b) a cert with two signing subkeys signed with whichever the
        // iterator yielded first, an order-dependent choice no signal reports.
        // `sign_data` is the signing chokepoint for every signed protocol
        // in this crate (grants, audit entries, key assertions, bindings),
        // so it now gets the same treatment `derive_k_repo` already had (P2-8):
        // filter to live+unrevoked, then REFUSE ambiguity rather than guess.
        // GitCellar certs carry exactly one signing subkey (`passkey-core`
        // `CertBuilder::new().add_signing_subkey()`; the primary is
        // certification-only), so >1 is malformed or adversarial.
        let signing_kas: Vec<_> = cert
            .keys()
            .with_policy(&self.policy, None)
            .supported()
            .alive()
            .revoked(false)
            .for_signing()
            .secret()
            .collect();
        if signing_kas.len() > 1 {
            return Err(CryptoError::Other(anyhow::anyhow!(
                "ambiguous cert: {} live, unrevoked signing subkeys with secret material \
                 (expected exactly 1) — refusing to sign, as the choice would be \
                 order-dependent and silently change which key signs across a rotation",
                signing_kas.len()
            )));
        }
        let signing_keypair = signing_kas
            .into_iter()
            .next()
            .ok_or(CryptoError::NoSigningKey)?
            .key()
            .clone()
            .into_keypair()
            .map_err(|e| CryptoError::Other(anyhow::anyhow!("Failed to create keypair: {}", e)))?;

        let mut signature_bytes = Vec::new();

        {
            let message = Message::new(&mut signature_bytes);

            // For detached signatures, write directly to the Signer (no LiteralWriter)
            let mut signer = Signer::new(message, signing_keypair)
                .map_err(|e| CryptoError::Other(anyhow::anyhow!("Failed to create signer: {}", e)))?
                .detached()
                .build()
                .map_err(|e| CryptoError::Other(anyhow::anyhow!("Failed to create signer: {}", e)))?;

            // Write the data to be signed directly to the signer
            signer.write_all(data)
                .map_err(|e| CryptoError::Other(anyhow::anyhow!("Failed to write data: {}", e)))?;

            signer.finalize()
                .map_err(|e| CryptoError::Other(anyhow::anyhow!("Failed to finalize: {}", e)))?;
        }

        debug!("Created signature: {} bytes", signature_bytes.len());

        Ok(signature_bytes)
    }
}

/// `hex(HMAC-SHA256(prefix_key, repo_id))` — the opaque storage object-key
/// segment (P1-4b). Free function (not a method) so the Service's storage layer,
/// its test prefix providers, and the e2e `object-key-prefix` CLI helper all
/// compute byte-identical prefixes from the same `id_key_repo_prefix`.
pub fn object_key_prefix_hex(prefix_key: &[u8; 32], repo_id: &str) -> String {
    use hmac::{Hmac, Mac};
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(prefix_key)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(repo_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::chunking::{ChunkConfig, ChunkEngine, StreamChunker};

    fn create_test_identity() -> Identity {
        Identity::generate("test@example.com").unwrap()
    }

    // ========================================================================
    // I-2 — K_repo is HKDF-SHA256, not a bare SHA-256(tag ‖ scalar)
    // ========================================================================

    /// The RETIRED v1 derivation, reproduced here (and ONLY here) so the tests
    /// can prove v2 is not it. Never call this from production code.
    fn legacy_v1_k_repo(scalar: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(b"gitcellar/k-repo/v1");
        hasher.update(scalar);
        hasher.finalize().into()
    }

    /// Pull the X25519 secret scalar out of an engine's cert — the IKM both the
    /// v1 and v2 derivations consume. Mirrors `derive_k_repo`'s extraction.
    fn secret_scalar(engine: &EncryptionEngine) -> Vec<u8> {
        let cert = engine.identity.cert();
        let ka = cert
            .keys()
            .with_policy(&engine.policy, None)
            .supported()
            .for_transport_encryption()
            .secret()
            .next()
            .expect("test cert has a transport-encryption subkey");
        match ka.key().optional_secret() {
            Some(SecretKeyMaterial::Unencrypted(unenc)) => unenc
                .map(|s| match s {
                    mpi::SecretKeyMaterial::ECDH { scalar } => scalar.value().to_vec(),
                    other => panic!("unexpected secret material: {:?}", other),
                }),
            _ => panic!("test cert secret must be unencrypted ECDH"),
        }
    }

    /// The construction proof: `K_repo` is EXACTLY
    /// `HKDF-SHA256(ikm=scalar, salt=None, info="gitcellar/krepo/v2", 32)`,
    /// recomputed independently here. Asserting only "it differs from v1" would
    /// pass for any arbitrary change; this pins the actual construction.
    #[test]
    fn k_repo_is_hkdf_sha256_over_the_scalar() {
        let engine = EncryptionEngine::new(create_test_identity()).unwrap();
        let scalar = secret_scalar(&engine);

        let mut expected = [0u8; 32];
        Hkdf::<Sha256>::new(None, &scalar)
            .expand(b"gitcellar/krepo/v2", &mut expected)
            .unwrap();

        assert_eq!(&*engine.derive_k_repo().unwrap(), &expected);
        // The info string const and the literal above must not drift apart.
        assert_eq!(EncryptionEngine::K_REPO_INFO, b"gitcellar/krepo/v2");
    }

    /// The v1→v2 flip actually changes the key. (If this ever fails, the
    /// "breaking, reset dev data" premise of I-2 is false.)
    #[test]
    fn v2_k_repo_differs_from_retired_v1_derivation() {
        let engine = EncryptionEngine::new(create_test_identity()).unwrap();
        let scalar = secret_scalar(&engine);

        let v1 = legacy_v1_k_repo(&scalar);
        let v2 = engine.derive_k_repo().unwrap();
        assert_ne!(&*v2, &v1, "v2 must not reproduce the retired bare-SHA-256 key");
    }

    /// Domain separation is real: a different `info` yields an unrelated key, so
    /// a future version bump cannot silently collide with v2.
    #[test]
    fn k_repo_info_version_flip_yields_a_different_key() {
        let engine = EncryptionEngine::new(create_test_identity()).unwrap();
        let scalar = secret_scalar(&engine);
        let hk = Hkdf::<Sha256>::new(None, &scalar);

        let mut v2 = [0u8; 32];
        hk.expand(b"gitcellar/krepo/v2", &mut v2).unwrap();
        let mut v3 = [0u8; 32];
        hk.expand(b"gitcellar/krepo/v3", &mut v3).unwrap();

        assert_ne!(v2, v3);
        assert_eq!(&*engine.derive_k_repo().unwrap(), &v2);
    }

    /// Determinism — encrypt and decrypt must derive the same root, and every
    /// key-holder of the same cert must agree (per-repo dedup/decrypt depends
    /// on it).
    #[test]
    fn k_repo_derivation_is_deterministic_across_engines() {
        let identity = create_test_identity();
        let a = EncryptionEngine::new(identity.clone()).unwrap();
        let b = EncryptionEngine::new(identity).unwrap();
        assert_eq!(&*a.derive_k_repo().unwrap(), &*b.derive_k_repo().unwrap());

        // Different identities → different roots (no cross-repo key reuse).
        let other = EncryptionEngine::new(create_test_identity()).unwrap();
        assert_ne!(&*a.derive_k_repo().unwrap(), &*other.derive_k_repo().unwrap());
    }

    /// OLD-KEY REJECTION (the breaking-change proof): a chunk sealed under the
    /// retired v1 root does NOT open under the live v2 engine, and vice-versa.
    /// This is exactly the at-rest break I-2 accepts by design — dev data must
    /// be reset, and a stale pack must fail loudly rather than silently.
    #[test]
    fn chunks_sealed_under_v1_key_do_not_open_under_v2() {
        let engine = EncryptionEngine::new(create_test_identity()).unwrap();
        let scalar = secret_scalar(&engine);
        let v1_engine = XChaChaChunkEngine::new(&legacy_v1_k_repo(&scalar)).unwrap();

        let chunk = Chunk {
            hash: "v1-legacy-chunk".to_string(),
            data: b"content written before the I-2 derivation change".to_vec(),
            size: 47,
            offset: 0,
        };
        let aad = aad_for(&chunk);

        // Sealed under v1 → the live (v2) path refuses it.
        let sealed_v1 = v1_engine.encrypt_with_aad(&chunk.data, &aad).unwrap();
        assert!(
            engine.decrypt_chunk(&sealed_v1, &aad).is_err(),
            "a v1-era chunk must NOT decrypt under the v2 derivation"
        );

        // Sealed under v2 → the old key cannot open it either.
        let sealed_v2 = engine.encrypt_chunk(&chunk, &aad).unwrap();
        assert!(
            v1_engine.decrypt_with_aad(&sealed_v2, &aad).is_err(),
            "a v2 chunk must NOT open under the retired v1 key"
        );

        // And v2 round-trips cleanly with itself (the derivation still works).
        assert_eq!(engine.decrypt_chunk(&sealed_v2, &aad).unwrap(), chunk.data);
    }

    /// Test repo id + the H-1 identity AAD for a test chunk.
    const TEST_REPO_ID: &str = "test/repo";

    fn aad_for(chunk: &Chunk) -> ChunkAad {
        ChunkAad::for_content_chunk(TEST_REPO_ID, &chunk.hash, chunk.size as u64)
    }

    #[test]
    fn test_encrypt_decrypt_data() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let original = b"Hello, encrypted world!";
        let encrypted = engine.encrypt_data(original).unwrap();

        assert!(!encrypted.is_empty());
        assert_ne!(encrypted, original);

        let decrypted = engine.decrypt_data(&encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_encrypt_decrypt_chunk() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let chunk_engine = ChunkEngine::new(ChunkConfig::default());
        let data = b"Hello, chunked and encrypted world!";
        let chunks = chunk_engine.chunk_data(data).unwrap();
        let aad = aad_for(&chunks[0]);

        let encrypted = engine.encrypt_chunk(&chunks[0], &aad).unwrap();
        assert!(!encrypted.is_empty());

        let decrypted = engine.decrypt_chunk(&encrypted, &aad).unwrap();
        assert_eq!(decrypted, chunks[0].data);

        // H-1: the same bytes under a different claimed identity fail closed.
        let wrong = ChunkAad::for_content_chunk(TEST_REPO_ID, "other-name", chunks[0].size as u64);
        assert!(engine.decrypt_chunk(&encrypted, &wrong).is_err());
    }

    /// F2 (AC-F2.1/F2.5/F2.6) — a written chunk is the raw XChaCha20-Poly1305
    /// v1 format, NOT an OpenPGP packet and NOT ASCII armor. This is the live
    /// integration proof that the chunk write path no longer emits SEIPD/OpenPGP.
    #[test]
    fn live_chunk_is_raw_aead_not_openpgp() {
        let engine = EncryptionEngine::new(create_test_identity()).unwrap();
        let chunk = Chunk {
            hash: "abc".to_string(),
            data: b"some repository content bytes".to_vec(),
            size: 29,
            offset: 0,
        };
        let out = engine.encrypt_chunk(&chunk, &aad_for(&chunk)).unwrap();

        // byte[0] is the F6 version byte (== 1), not an OpenPGP packet tag.
        // OpenPGP binary packet headers always have the high bit set (>= 0x80);
        // ASCII-armored output starts with '-' (0x2d). v1 == 0x01 is neither, so
        // `gpg --list-packets` cannot parse a stored chunk (AC-F2.6).
        assert_eq!(out[0], 1, "leading byte must be chunk-format version 1");
        assert!(out[0] < 0x80, "must not look like an OpenPGP packet tag");
        assert_ne!(out[0], b'-', "must not be ASCII armor");
        // Size == plaintext + 41 (1 ver + 24 nonce + 16 tag), not plaintext×1.33 (F3).
        assert_eq!(out.len(), chunk.data.len() + 41);
        // No OpenPGP armor banner anywhere in the bytes.
        assert!(!out.windows(5).any(|w| w == b"-----"));

        // Round-trips.
        assert_eq!(engine.decrypt_chunk(&out, &aad_for(&chunk)).unwrap(), chunk.data);
    }

    /// F2 (AC-F2.3) — per-byte tamper rejection on the live path: the AEAD tag
    /// is the real integrity check (F4), not theater.
    #[test]
    fn live_chunk_tamper_is_rejected() {
        let engine = EncryptionEngine::new(create_test_identity()).unwrap();
        let chunk = Chunk {
            hash: "abc".to_string(),
            data: b"integrity is real".to_vec(),
            size: 17,
            offset: 0,
        };
        let aad = aad_for(&chunk);
        let good = engine.encrypt_chunk(&chunk, &aad).unwrap();
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xFF;
            assert!(
                engine.decrypt_chunk(&bad, &aad).is_err(),
                "tampering byte {i} was not rejected"
            );
        }

        // L-1: a targeted flip to the OTHER VALID version byte (v1→v2) must
        // also be rejected — the version byte is authenticated in the AAD, so
        // this fails the tag rather than sneaking past the version parser.
        let mut flipped = good.clone();
        assert_eq!(flipped[0], 1);
        flipped[0] = 2;
        assert!(
            engine.decrypt_chunk(&flipped, &aad).is_err(),
            "v1→v2 version flip was not rejected (L-1)"
        );
    }

    /// F2 — a different identity (different per-repo key) cannot decrypt: the
    /// content key derives from the X25519 secret scalar, which the provider /
    /// other repos never hold.
    #[test]
    fn live_chunk_wrong_identity_cannot_decrypt() {
        let a = EncryptionEngine::new(create_test_identity()).unwrap();
        let b = EncryptionEngine::new(create_test_identity()).unwrap();
        let chunk = Chunk {
            hash: "abc".to_string(),
            data: b"secret".to_vec(),
            size: 6,
            offset: 0,
        };
        let aad = aad_for(&chunk);
        let enc = a.encrypt_chunk(&chunk, &aad).unwrap();
        assert!(b.decrypt_chunk(&enc, &aad).is_err());
        // Same identity loaded via from_cert derives the same K_repo → decrypts.
        let a2 = EncryptionEngine::from_cert(a.identity().cert().clone()).unwrap();
        assert_eq!(a2.decrypt_chunk(&enc, &aad).unwrap(), chunk.data);
    }

    // ========================================================================
    // E1 — keyed naming + keyed CDC derivation (AC-E1.1/E1.2/E1.5/E1.6)
    // ========================================================================

    /// AC-E1.5 — `id_key_repo`/`boundary_key_repo` are domain-separated HKDF
    /// outputs of `K_repo`: deterministic per identity, shared by every
    /// key-holder (same cert ⇒ same keying), and the keyed name is NOT the public
    /// SHA-256 (the provider cannot compute it). AC-E1.1 dedup + oracle-closed.
    #[test]
    fn e1_keying_is_domain_separated_and_key_scoped() {
        let a = EncryptionEngine::new(create_test_identity()).unwrap();
        let b = EncryptionEngine::new(create_test_identity()).unwrap();

        let keying_a = a.chunk_keying().unwrap();
        // Same cert via from_cert → identical keying (collaborator dedup holds).
        let a2 = EncryptionEngine::from_cert(a.identity().cert().clone()).unwrap();
        let keying_a2 = a2.chunk_keying().unwrap();
        let keying_b = b.chunk_keying().unwrap();

        let data = b"repository content bytes for keyed naming".repeat(40);
        let engine_a = ChunkEngine::new_keyed(ChunkConfig::e1_keyed(), keying_a);
        let engine_a2 = ChunkEngine::new_keyed(ChunkConfig::e1_keyed(), keying_a2);
        let engine_b = ChunkEngine::new_keyed(ChunkConfig::e1_keyed(), keying_b);

        let chunks_a = engine_a.chunk_data(&data).unwrap();
        let chunks_a2 = engine_a2.chunk_data(&data).unwrap();
        let chunks_b = engine_b.chunk_data(&data).unwrap();

        // Same repo key → identical names (per-repo dedup preserved).
        let names_a: Vec<_> = chunks_a.iter().map(|c| &c.hash).collect();
        let names_a2: Vec<_> = chunks_a2.iter().map(|c| &c.hash).collect();
        assert_eq!(names_a, names_a2);
        // Different identity → different names AND the name is not the SHA-256.
        assert_ne!(chunks_a[0].hash, chunks_b[0].hash);
        assert_ne!(chunks_a[0].hash, ChunkEngine::compute_hash(&chunks_a[0].data));
    }

    /// AC-E1.6 — `encrypt_chunk_e1` tags the chunk v2 (keyed pipeline), the
    /// payload is XChaCha20-Poly1305, and the version-agnostic `decrypt_chunk`
    /// round-trips it. v1 `encrypt_chunk` still tags v1 (F2 baseline unchanged).
    #[test]
    fn e1_encrypt_chunk_is_v2_and_round_trips() {
        let engine = EncryptionEngine::new(create_test_identity()).unwrap();
        let chunk = Chunk {
            hash: "deadbeef".to_string(),
            data: b"E1 keyed pipeline content".to_vec(),
            size: 25,
            offset: 0,
        };
        let aad = aad_for(&chunk);
        let v1 = engine.encrypt_chunk(&chunk, &aad).unwrap();
        let v2 = engine.encrypt_chunk_e1(&chunk, &aad).unwrap();

        assert_eq!(v1[0], 1, "F2 baseline still emits v1");
        assert_eq!(v2[0], 2, "E1 pipeline emits v2 (AC-E1.6)");
        // Same plaintext+nonce-independent layout: both decrypt to the plaintext
        // (decrypt authenticates against the OBSERVED version byte).
        assert_eq!(engine.decrypt_chunk(&v1, &aad).unwrap(), chunk.data);
        assert_eq!(engine.decrypt_chunk(&v2, &aad).unwrap(), chunk.data);
        // v2 overhead is the F2 41-byte overhead (no extra E1 bytes in the chunk).
        assert_eq!(v2.len(), chunk.data.len() + 41);
    }

    /// End-to-end E1: keyed `StreamChunker` (HMAC names + keyed boundaries) →
    /// `encrypt_chunks_e1_parallel` (v2) → `decrypt_chunks_parallel` →
    /// reassembles to the original bytes, all under this identity's keying.
    #[tokio::test]
    async fn e1_keyed_chunk_pipeline_round_trips_end_to_end() {
        let engine = EncryptionEngine::new(create_test_identity()).unwrap();
        let keying = engine.chunk_keying().unwrap();

        // ~600 KiB of high-entropy data so the keyed CDC produces several chunks.
        let mut x: u64 = 0x1234_5678_9abc_def1;
        let data: Vec<u8> = (0..600 * 1024)
            .map(|_| {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                (x.wrapping_mul(0x2545F4914F6CDD1D) >> 33) as u8
            })
            .collect();

        let mut chunker = StreamChunker::new_keyed(ChunkConfig::e1_keyed(), keying);
        chunker.feed(&data);
        let chunks = chunker.finalize();
        assert!(chunks.len() > 1, "keyed CDC should produce multiple chunks");

        let encrypted = engine
            .encrypt_chunks_e1_parallel(TEST_REPO_ID, &chunks)
            .await
            .unwrap();
        assert!(encrypted.iter().all(|c| c[0] == 2), "all E1 chunks are v2");

        let aads: Vec<ChunkAad> = chunks.iter().map(aad_for).collect();
        let decrypted = engine.decrypt_chunks_parallel(&encrypted, &aads).await.unwrap();
        let reassembled: Vec<u8> = decrypted.concat();
        assert_eq!(reassembled, data);
    }

    /// P2-8 — a cert with TWO transport-encryption
    /// subkeys must be REFUSED by the content-key derivation, because picking
    /// "the first" is order-dependent and would diverge `K_repo` between parties
    /// (→ undecryptable chunks). Pre-fix `derive_k_repo` used `.next()` and
    /// silently picked one; post-fix it errors. A normal single-subkey cert is
    /// the positive control.
    #[test]
    fn p2_8_multiple_transport_encryption_subkeys_refused() {
        use openpgp::cert::prelude::*;

        let (cert, _rev) = CertBuilder::new()
            .add_userid("ambiguous@example.com")
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .add_transport_encryption_subkey() // second one → ambiguous K_repo
            .generate()
            .unwrap();

        let engine = EncryptionEngine::from_cert(cert).unwrap();
        let chunk = Chunk {
            hash: "x".to_string(),
            data: b"secret".to_vec(),
            size: 6,
            offset: 0,
        };
        // encrypt_chunk → chunk_engine → derive_k_repo, so the ambiguity surfaces here.
        let res = engine.encrypt_chunk(&chunk, &aad_for(&chunk));
        assert!(
            res.is_err(),
            "P2-8: a cert with 2 transport-encryption subkeys must be refused (K_repo would diverge)"
        );
        assert!(
            format!("{:#}", res.unwrap_err()).contains("transport-encryption subkeys"),
            "error must name the ambiguous-subkey condition"
        );

        // Positive control: a standard single-subkey identity still encrypts.
        let ok_engine = EncryptionEngine::new(create_test_identity()).unwrap();
        assert!(
            ok_engine.encrypt_chunk(&chunk, &aad_for(&chunk)).is_ok(),
            "single-transport-subkey cert must still work"
        );
    }

    // ========================================================================
    // F-7 / F-8 (hardening review, Aug 2026) — key selection must agree with
    // `encrypt_data`: live + unrevoked only, and refuse ambiguity.
    // ========================================================================

    /// Revoke one subkey of `cert` (hard revocation by the primary key) and
    /// return the updated cert. Used to build the "rotated away" certs the
    /// F-7/F-8 filters must handle.
    fn revoke_subkey_at(cert: openpgp::Cert, subkey_index: usize) -> openpgp::Cert {
        use openpgp::cert::prelude::*;
        use openpgp::types::ReasonForRevocation;

        let mut primary_signer = cert
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()
            .expect("test cert carries primary secret material")
            .into_keypair()
            .expect("primary key is unencrypted in tests");

        let target = cert
            .keys()
            .subkeys()
            .nth(subkey_index)
            .expect("subkey index in range")
            .key()
            .clone();

        let sig = SubkeyRevocationBuilder::new()
            .set_reason_for_revocation(ReasonForRevocation::KeyRetired, b"rotated (test)")
            .unwrap()
            .build(&mut primary_signer, &cert, &target, None)
            .expect("subkey revocation builds");

        // sequoia 2.x: `insert_packets` returns `(Cert, bool)` (the bool reports
        // whether anything changed); 1.x returned just the Cert.
        cert.insert_packets(sig).expect("revocation inserts").0
    }

    /// F-8 — the `K_repo` ambiguity guard must count only LIVE, UNREVOKED
    /// transport-encryption subkeys. Pre-fix the filter omitted
    /// `.alive().revoked(false)`, so a cert that had legitimately rotated its
    /// encryption subkey (add new, revoke old) counted 2 and `derive_k_repo`
    /// refused forever — permanently undecryptable chunks, because `K_repo`
    /// gates the content key, the naming key, the boundary key and the
    /// object-key prefix. Post-fix the revoked one is invisible and derivation
    /// proceeds from the single live subkey.
    #[test]
    fn f8_revoked_transport_encryption_subkey_does_not_brick_k_repo() {
        use openpgp::cert::prelude::*;

        let (cert, _rev) = CertBuilder::new()
            .add_userid("rotated@example.com")
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .add_transport_encryption_subkey() // subkey 1 — will be revoked
            .add_transport_encryption_subkey() // subkey 2 — the live one
            .generate()
            .unwrap();

        // Revoke the FIRST transport-encryption subkey (subkeys[0] is the
        // signing subkey, so the first encryption subkey is index 1).
        let rotated = revoke_subkey_at(cert, 1);

        let engine = EncryptionEngine::from_cert(rotated).unwrap();
        let chunk = Chunk {
            hash: "x".to_string(),
            data: b"secret".to_vec(),
            size: 6,
            offset: 0,
        };

        let sealed = engine
            .encrypt_chunk(&chunk, &aad_for(&chunk))
            .expect("F-8: a revoked encryption subkey must not count as ambiguity");
        let opened = engine
            .decrypt_chunk(&sealed, &aad_for(&chunk))
            .expect("round-trip under the surviving live subkey");
        assert_eq!(opened, chunk.data);
    }

    /// F-7 — `sign_data` must not sign with a REVOKED signing subkey. Pre-fix it
    /// took `.next()` off an unfiltered iterator, so it emitted signatures no
    /// verifier accepts (Sequoia's `StandardPolicy` rejects a revoked signer) —
    /// a self-DoS that surfaces simultaneously across every signed protocol.
    /// Post-fix it fails closed at signing time with a clear error.
    #[test]
    fn f7_revoked_signing_subkey_is_refused_at_signing_time() {
        use openpgp::cert::prelude::*;

        let (cert, _rev) = CertBuilder::new()
            .add_userid("revoked-signer@example.com")
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate()
            .unwrap();

        // subkeys[0] is the signing subkey.
        let revoked = revoke_subkey_at(cert, 0);

        let engine = EncryptionEngine::from_cert(revoked).unwrap();
        let res = engine.sign_data(b"authorize this");
        assert!(
            res.is_err(),
            "F-7: signing with a revoked signing subkey must be refused, not silently produce \
             a signature every verifier rejects"
        );

        // Positive control: a normal identity still signs.
        let ok_engine = EncryptionEngine::new(create_test_identity()).unwrap();
        assert!(ok_engine.sign_data(b"authorize this").is_ok());
    }

    /// F-7 — a cert with two LIVE signing subkeys is ambiguous: `.next()` would
    /// pick whichever the iterator yields first, so a rotation would silently
    /// change which key signs with no signal to anyone. Refuse, the same way
    /// `derive_k_repo` already refuses (P2-8).
    #[test]
    fn f7_two_live_signing_subkeys_are_refused() {
        use openpgp::cert::prelude::*;

        let (cert, _rev) = CertBuilder::new()
            .add_userid("ambiguous-signer@example.com")
            .set_cipher_suite(CipherSuite::Cv25519)
            .add_signing_subkey()
            .add_signing_subkey()
            .add_transport_encryption_subkey()
            .generate()
            .unwrap();

        let engine = EncryptionEngine::from_cert(cert).unwrap();
        let res = engine.sign_data(b"authorize this");
        assert!(res.is_err(), "F-7: two signing subkeys must be refused, not guessed");
        assert!(
            format!("{:#}", res.unwrap_err()).contains("signing subkeys"),
            "error must name the ambiguous-subkey condition"
        );
    }

    // ========================================================================
    // P1-4b — opaque storage object-key prefix derivation
    // ========================================================================

    /// P1-4b — `derive_object_key_prefix` is deterministic per cert, shared by
    /// every key-holder of that cert (collaborator-agreement), differs per
    /// `repo_id` and per identity, and never embeds the plaintext repo identity
    /// (non-reversibility of the leak). This is the unit-level proof behind the
    /// storage layer's opaque keys.
    #[test]
    fn p1_4b_object_key_prefix_is_deterministic_scoped_and_opaque() {
        let a = EncryptionEngine::new(create_test_identity()).unwrap();
        let b = EncryptionEngine::new(create_test_identity()).unwrap();

        let repo = "alice/secret-project";

        // Deterministic: same engine, same repo → same prefix.
        let p1 = a.derive_object_key_prefix(repo).unwrap();
        let p2 = a.derive_object_key_prefix(repo).unwrap();
        assert_eq!(p1, p2, "prefix must be deterministic for a given cert+repo");

        // Collaborator-agreement: the SAME cert loaded via from_cert derives the
        // identical prefix (every key-holder lists/reads under the same path).
        let a2 = EncryptionEngine::from_cert(a.identity().cert().clone()).unwrap();
        assert_eq!(a2.derive_object_key_prefix(repo).unwrap(), p1);

        // Different identity (different K_repo) → different prefix.
        assert_ne!(b.derive_object_key_prefix(repo).unwrap(), p1);

        // Different repo_id under the SAME cert → different prefix (rename/transfer
        // recomputes; HMAC message is repo_id).
        assert_ne!(a.derive_object_key_prefix("alice/other").unwrap(), p1);

        // Opaque + non-reversible: the hex digest contains neither the owner nor
        // the repo name — the bucket-inventory identity leak is closed.
        assert!(!p1.contains("alice"), "prefix must not leak owner: {p1}");
        assert!(!p1.contains("secret-project"), "prefix must not leak repo name: {p1}");
        // Shape: 64 lowercase hex chars (SHA-256 HMAC output).
        assert_eq!(p1.len(), 64, "prefix is hex(HMAC-SHA256) = 64 chars");
        assert!(p1.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    /// P1-4b — the free `object_key_prefix_hex` is a pure HMAC-SHA256 that the
    /// e2e CLI helper and storage layer share. Locks the exact construction so a
    /// drift between the Service and the harness is caught at unit-test time.
    #[test]
    fn p1_4b_object_key_prefix_hex_is_stable_hmac() {
        let key = [7u8; 32];
        let got = object_key_prefix_hex(&key, "alice/proj");
        // Recompute independently with the hmac crate to pin the construction.
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).unwrap();
        mac.update(b"alice/proj");
        assert_eq!(got, hex::encode(mac.finalize().into_bytes()));
        // Different message → different digest; deterministic for same inputs.
        assert_ne!(got, object_key_prefix_hex(&key, "alice/other"));
        assert_eq!(got, object_key_prefix_hex(&key, "alice/proj"));
    }

    #[test]
    fn test_encrypt_empty_data() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let encrypted = engine.encrypt_data(b"").unwrap();
        let decrypted = engine.decrypt_data(&encrypted).unwrap();

        assert_eq!(decrypted, b"");
    }

    #[test]
    fn test_encrypt_large_data() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let original: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let encrypted = engine.encrypt_data(&original).unwrap();
        let decrypted = engine.decrypt_data(&encrypted).unwrap();

        assert_eq!(decrypted, original);
    }

    #[tokio::test]
    async fn test_parallel_encryption() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let chunk_engine = ChunkEngine::new(ChunkConfig::default());
        let data = vec![42u8; 1024 * 1024]; // 1MB
        let chunks = chunk_engine.chunk_data(&data).unwrap();

        let encrypted = engine
            .encrypt_chunks_parallel(TEST_REPO_ID, &chunks)
            .await
            .unwrap();
        assert_eq!(encrypted.len(), chunks.len());

        // Verify each chunk can be decrypted under its own identity.
        for (i, enc) in encrypted.iter().enumerate() {
            let dec = engine.decrypt_chunk(enc, &aad_for(&chunks[i])).unwrap();
            assert_eq!(dec, chunks[i].data);
        }
    }

    #[test]
    fn test_sign_data() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let data = b"Data to be signed";
        let signature = engine.sign_data(data).unwrap();

        assert!(!signature.is_empty());
    }

    #[test]
    fn test_export_public_key() {
        let identity = create_test_identity();
        let engine = EncryptionEngine::new(identity).unwrap();

        let public_key = engine.export_public_key().unwrap();
        assert!(public_key.contains("BEGIN PGP PUBLIC KEY BLOCK"));
    }
}
