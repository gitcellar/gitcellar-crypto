//! Chunk-format version byte registry and dispatch (F6).
//!
//! Every stored GitCellar chunk begins with a single format-version byte
//! (`byte[0]`). The decrypt path reads it and dispatches to the matching
//! unwrap routine; an unknown value is an explicit, typed error — **never** a
//! silent fallthrough or misparse (AC-F6.3). This is the crypto-agility seam:
//! all future on-disk format change (PQC key-wrap, keyed-CDC variants,
//! enterprise cipher modes) routes through a new version value here, never
//! through a user-facing cipher toggle (DEC-CH-03).
//!
//! ## Version registry (AC-F6.2)
//!
//! | Byte | Meaning                                                        | Status |
//! |------|----------------------------------------------------------------|--------|
//! | `1`  | XChaCha20-Poly1305, AAD bound the repo *name*, no key version  | **retired** — refused |
//! | `2`  | as `1`, marking the E1 keyed-CDC / keyed-naming pipeline       | **retired** — refused |
//! | `3`  | XChaCha20-Poly1305, AAD binds the immutable `repo_uid` and the key version | **implemented** (the only one) |
//! | `4`  | AES-256-GCM-SIV enterprise / FIPS build variant                | DEC-CH-03 — reserved |
//! | `5`  | keyed-CDC via AES-per-byte (eprint 2025/558 provable)           | E1 AC-E1.8 — reserved |
//! | `6`  | hybrid-wrapped session key (X25519 + ML-KEM-768, KMAC256 KDF)   | E5 (P3 dark) — reserved |
//! | other| **explicit error** — refuse to misparse                        | AC-F6.3 |
//!
//! ## v3 (2026-10)
//!
//! v3 chunk **bytes** keep the `[ver][24B XNonce][ct][16B tag]` layout of v1/v2.
//! What changed is what the AEAD's associated data binds ([`ChunkAad`]):
//!
//! - **the repository's immutable `repo_uid`, never its name**. A rename
//!   or transfer changes nothing sealed in storage, so it needs no re-seal;
//! - **the key version that sealed the blob**. Readers open a blob only
//!   under that version's key (no trial loop over every key held), so a
//!   collaborator removed by a rotation cannot substitute a pre-rotation chunk
//!   sealed under the retired key it still holds and have it accepted.
//!
//! The parser refuses `1` and `2`. There is no compatibility reader: data in
//! those formats must be regenerated. The
//! hybrid-wrap reservation moved from `3` to `6` to free `3` for this format.
//!
//! Reserved values are documented and **not** emitted until their requirement
//! ships; `parse_version` rejects every byte except the implemented one, so a
//! reserved-but-unimplemented chunk fails loudly rather than being mis-decoded.

use crate::error::{VaultError, VaultResult};

/// v1 — retired (the AAD bound the repo name and no key version). Refused by
/// [`parse_version`]. The constant names the byte so the registry stays readable.
pub const V1_XCHACHA20_POLY1305: u8 = 1;

/// v2 — retired (v1 plus the E1 keyed-pipeline marker). Refused by [`parse_version`].
pub const V2_KEYED_CDC_NAMING: u8 = 2;

/// v3 — XChaCha20-Poly1305 whose AAD binds `repo_uid` and the sealing key
/// version ([`ChunkAad::canonical_aad_bytes`]). The only format emitted or read.
pub const V3_REPO_UID_KEY_VERSION: u8 = 3;

/// v4 (reserved) — AES-256-GCM-SIV enterprise / FIPS build variant (DEC-CH-03).
pub const V4_AES_256_GCM_SIV: u8 = 4;

/// v5 (reserved) — keyed-CDC via AES-per-byte, eprint 2025/558 provable construction (E1 AC-E1.8).
pub const V5_KEYED_CDC_AES_PER_BYTE: u8 = 5;

/// v6 (reserved) — hybrid-wrapped session key (X25519 + ML-KEM-768, KMAC256 KDF) (E5, P3 dark).
pub const V6_HYBRID_WRAP: u8 = 6;

/// A known, dispatchable chunk-format version (one variant per *implemented* format).
///
/// Retired (v1, v2) and reserved (v4–v6) registry values deliberately have no
/// variant: a chunk carrying one is rejected by [`parse_version`]. This keeps
/// "documented" and "dispatchable" honestly distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkFormatVersion {
    /// v3 — XChaCha20-Poly1305, AAD binds `repo_uid` + key version.
    RepoUidKeyVersionV3,
}

impl ChunkFormatVersion {
    /// The on-disk version byte for this format.
    pub fn as_byte(self) -> u8 {
        match self {
            ChunkFormatVersion::RepoUidKeyVersionV3 => V3_REPO_UID_KEY_VERSION,
        }
    }

    /// Whether this version's payload is the XChaCha20-Poly1305 AEAD layout
    /// (`[ver][24B nonce][ct][16B tag]`).
    pub fn is_xchacha20_poly1305_layout(self) -> bool {
        matches!(self, ChunkFormatVersion::RepoUidKeyVersionV3)
    }
}

// ============================================================================
// H-1 (+L-1, v3) — per-chunk identity bound into the AEAD as AAD
// ============================================================================

/// Per-chunk identity, bound into the XChaCha20-Poly1305 AEAD as associated
/// data (H-1, folding in L-1; v3 adds the repo uid and the key version).
///
/// All of a repo's chunks share one content key per key version, so without
/// AAD any same-key blob decrypts cleanly anywhere — a malicious storage
/// provider could splice, reorder, or substitute blobs undetected. Binding the
/// chunk's identity as AAD makes a blob sealed under *its* real identity fail
/// the Poly1305 tag when opened under the manifest's *claimed* identity.
///
/// The cipher-level AAD is `version_byte(1) ‖ canonical_aad_bytes()` — the
/// engine prepends its emit-version byte on encrypt and the *observed*
/// `byte[0]` on decrypt, so a flipped format-version byte fails authentication
/// too (the L-1 fix).
///
/// ## No NUL in a string field (load-bearing)
///
/// The canonical encoding separates the two variable-length fields with
/// `0x00`, which is injective only when neither field contains `0x00`.
/// [`ChunkAad::new`] refuses such a field, and so does every seal and
/// open ([`ChunkAad::check`]), however the value was built.
///
/// ## `stream_offset` and dedup (load-bearing)
///
/// `chunk_name` is the keyed HMAC of the *plaintext* (`HMAC(id_key_repo, pt)`,
/// AC-E1.1), and GitCellar dedups storage by that name: one stored blob is
/// legitimately referenced at **many stream offsets** — duplicate content
/// within one push, and (critically) unchanged chunks whose offsets shift on
/// every incremental push (CDC insert/delete moves all later chunks). A blob
/// is sealed exactly once, so a position-dependent AAD would make every
/// deduplicated reference undecryptable. Production content chunks therefore
/// bind `stream_offset = 0`; positional integrity (no gap/overlap/reorder in
/// the covering set) is enforced structurally on the read side against the
/// *authenticated* manifest instead (`assert_contiguous_tiling` in the
/// Service). The field stays in the canonical encoding so the wire format
/// needs no change if a future format version chooses to bind real positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkAad {
    /// The repository's immutable id (`repo_uid`: 32 lowercase hex, minted
    /// with the repository's first key). Never the `owner/name`, which a
    /// rename or transfer changes. A wiki binds `"{repo_uid}.wiki"`, so its
    /// objects stay distinct from its parent's while sharing the parent's key.
    pub repo_uid: String,
    /// The chunk's manifest name — the keyed HMAC hex name for content chunks
    /// (`StreamChunkEntry.hash`), or a fixed object name for singleton repo
    /// objects (`"stream-manifest"`, `"metadata"`, `"contribution/<head>"`).
    pub chunk_name: String,
    /// The repository key version that sealed this blob. A reader opens the
    /// blob only under that version's key, and the AEAD fails if the claimed
    /// version is not the sealing one.
    pub key_version: u32,
    /// Stream offset bound into the AAD. `0` for production content chunks and
    /// singleton objects (see the dedup note on the struct).
    pub stream_offset: u64,
    /// Plaintext size in bytes (`StreamChunkEntry.size`). `0` for singleton
    /// objects whose size the reader cannot know before decrypting.
    pub size: u64,
}

impl ChunkAad {
    /// The key version the provisional, version-less constructors
    /// ([`for_content_chunk`](Self::for_content_chunk),
    /// [`for_named_object`](Self::for_named_object)) bind: a repository's first
    /// key version.
    pub const DEFAULT_KEY_VERSION: u32 = 1;

    /// Construct from explicit parts. Refuses a `0x00` byte in `repo_uid` or
    /// `chunk_name`, which would make the canonical encoding ambiguous.
    pub fn new(
        repo_uid: impl Into<String>,
        chunk_name: impl Into<String>,
        key_version: u32,
        stream_offset: u64,
        size: u64,
    ) -> VaultResult<Self> {
        let aad = Self {
            repo_uid: repo_uid.into(),
            chunk_name: chunk_name.into(),
            key_version,
            stream_offset,
            size,
        };
        aad.check()?;
        Ok(aad)
    }

    /// AAD for a content chunk sealed under `key_version`: binds `repo_uid`,
    /// the keyed HMAC `chunk_name`, the key version and the plaintext `size`;
    /// `stream_offset` is fixed to `0` because keyed-name dedup stores one blob
    /// for many stream positions (see the struct docs). The seal site (from
    /// `Chunk.hash`/`Chunk.size`) and the open site (from the manifest entry)
    /// MUST both use this constructor.
    pub fn content(repo_uid: &str, chunk_name: &str, key_version: u32, size: u64) -> VaultResult<Self> {
        Self::new(repo_uid, chunk_name, key_version, 0, size)
    }

    /// AAD for a singleton repo object (the encrypted stream manifest, the
    /// metadata bundle, a contribution) sealed under `key_version`: binds
    /// `repo_uid`, the object's fixed name and the key version; offset and size
    /// are `0` (the reader cannot know the size before decrypting).
    pub fn named(repo_uid: &str, object_name: &str, key_version: u32) -> VaultResult<Self> {
        Self::new(repo_uid, object_name, key_version, 0, 0)
    }

    /// [`content`](Self::content) at [`DEFAULT_KEY_VERSION`](Self::DEFAULT_KEY_VERSION).
    ///
    /// Provisional: kept for callers that build an AAD without a key version.
    /// Every production seal and open passes the real version through
    /// [`content`](Self::content).
    /// A NUL in a field is refused at seal and open time ([`Self::check`]).
    pub fn for_content_chunk(repo_uid: &str, chunk_name: &str, size: u64) -> Self {
        Self {
            repo_uid: repo_uid.to_string(),
            chunk_name: chunk_name.to_string(),
            key_version: Self::DEFAULT_KEY_VERSION,
            stream_offset: 0,
            size,
        }
    }

    /// [`named`](Self::named) at [`DEFAULT_KEY_VERSION`](Self::DEFAULT_KEY_VERSION).
    /// Provisional, for the same callers as [`for_content_chunk`](Self::for_content_chunk).
    pub fn for_named_object(repo_uid: &str, object_name: &str) -> Self {
        Self {
            repo_uid: repo_uid.to_string(),
            chunk_name: object_name.to_string(),
            key_version: Self::DEFAULT_KEY_VERSION,
            stream_offset: 0,
            size: 0,
        }
    }

    /// Refuse a value whose canonical encoding would be ambiguous: a `0x00`
    /// byte in either string field. Every seal and open calls
    /// this, so a struct built field by field cannot slip past it.
    pub fn check(&self) -> VaultResult<()> {
        if self.repo_uid.as_bytes().contains(&0) {
            return Err(VaultError::Encryption(
                "chunk AAD refused: repo_uid contains a NUL byte, which would make the \
                 canonical AAD encoding ambiguous"
                    .to_string(),
            ));
        }
        if self.chunk_name.as_bytes().contains(&0) {
            return Err(VaultError::Encryption(
                "chunk AAD refused: chunk_name contains a NUL byte, which would make the \
                 canonical AAD encoding ambiguous"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Canonical AAD encoding, WITHOUT the leading version byte (the engine
    /// prepends that — emit-version on encrypt, observed `byte[0]` on decrypt):
    ///
    /// ```text
    /// repo_uid ‖ 0x00 ‖ chunk_name ‖ 0x00 ‖ key_version(u32 LE)
    ///          ‖ stream_offset(u64 LE) ‖ size(u64 LE)
    /// ```
    ///
    /// Injective because neither string field contains `0x00` ([`Self::check`]),
    /// so the two separators delimit the variable-length fields, and the
    /// fixed-width LE integers close the encoding.
    pub fn canonical_aad_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.repo_uid.len() + 1 + self.chunk_name.len() + 1 + 4 + 8 + 8,
        );
        out.extend_from_slice(self.repo_uid.as_bytes());
        out.push(0x00);
        out.extend_from_slice(self.chunk_name.as_bytes());
        out.push(0x00);
        out.extend_from_slice(&self.key_version.to_le_bytes());
        out.extend_from_slice(&self.stream_offset.to_le_bytes());
        out.extend_from_slice(&self.size.to_le_bytes());
        out
    }
}

/// Parse the leading format-version byte into a dispatchable version.
///
/// A retired value (v1, v2), a reserved-but-unimplemented one and any unknown
/// byte return an explicit typed error (AC-F6.3). The decrypt path must
/// propagate this rather than guessing a format.
pub fn parse_version(byte: u8) -> VaultResult<ChunkFormatVersion> {
    match byte {
        V3_REPO_UID_KEY_VERSION => Ok(ChunkFormatVersion::RepoUidKeyVersionV3),
        V1_XCHACHA20_POLY1305 | V2_KEYED_CDC_NAMING => Err(VaultError::Decryption(format!(
            "retired chunk-format version byte 0x{byte:02x}: its AAD bound the repository name \
             and no key version; only v3 is read (no compatibility \
             reader — regenerate the data)"
        ))),
        other => Err(VaultError::Decryption(format!(
            "unknown chunk-format version byte 0x{other:02x}: not a recognized/implemented \
             GitCellar chunk format — refusing to misparse (F6 AC-F6.3)"
        ))),
    }
}

/// Read and validate the format-version byte from a stored chunk's first byte.
///
/// Errors if the chunk is empty (no version byte) or the byte is not v3.
pub fn version_of(chunk: &[u8]) -> VaultResult<ChunkFormatVersion> {
    let first = chunk.first().ok_or_else(|| {
        VaultError::Decryption("empty chunk: missing format-version byte (F6)".to_string())
    })?;
    parse_version(*first)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_byte_is_three_and_round_trips() {
        assert_eq!(V3_REPO_UID_KEY_VERSION, 3);
        assert_eq!(parse_version(3).unwrap(), ChunkFormatVersion::RepoUidKeyVersionV3);
        assert_eq!(ChunkFormatVersion::RepoUidKeyVersionV3.as_byte(), 3);
        assert!(ChunkFormatVersion::RepoUidKeyVersionV3.is_xchacha20_poly1305_layout());
    }

    #[test]
    fn retired_and_unknown_version_bytes_are_explicit_errors_never_silent() {
        // Every value except v3 must error — the retired v1/v2, the reserved
        // registry values (4..=6) and arbitrary bytes.
        for b in [0u8, 1, 2, 4, 5, 6, 42, 200, 255] {
            let err = parse_version(b).unwrap_err();
            assert!(
                matches!(err, VaultError::Decryption(_)),
                "byte {b} must be an explicit Decryption error, got {err:?}"
            );
        }
        assert!(format!("{}", parse_version(2).unwrap_err()).contains("retired"));
    }

    #[test]
    fn version_of_rejects_empty_chunk() {
        assert!(version_of(&[]).is_err());
    }

    // ------------------------------------------------------------------
    // ChunkAad canonical encoding (v3)
    // ------------------------------------------------------------------

    /// Golden encoding: pins the exact byte layout
    /// `repo_uid ‖ 0x00 ‖ chunk_name ‖ 0x00 ‖ key_version(u32 LE) ‖ offset(u64 LE) ‖ size(u64 LE)`.
    #[test]
    fn chunk_aad_canonical_bytes_golden() {
        let aad = ChunkAad::new("0f1e2d3c", "abcd", 0x0506_0708, 0x0102, 0x0304).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"0f1e2d3c");
        expected.push(0);
        expected.extend_from_slice(b"abcd");
        expected.push(0);
        expected.extend_from_slice(&0x0506_0708u32.to_le_bytes());
        expected.extend_from_slice(&0x0102u64.to_le_bytes());
        expected.extend_from_slice(&0x0304u64.to_le_bytes());
        assert_eq!(aad.canonical_aad_bytes(), expected);
    }

    /// Every field participates: changing any one field changes the encoding.
    #[test]
    fn chunk_aad_every_field_is_load_bearing() {
        let base = ChunkAad::new("aa11", "cafe", 2, 7, 42).unwrap();
        let variants = [
            ChunkAad::new("bb22", "cafe", 2, 7, 42).unwrap(),
            ChunkAad::new("aa11", "beef", 2, 7, 42).unwrap(),
            ChunkAad::new("aa11", "cafe", 3, 7, 42).unwrap(),
            ChunkAad::new("aa11", "cafe", 2, 8, 42).unwrap(),
            ChunkAad::new("aa11", "cafe", 2, 7, 43).unwrap(),
        ];
        for v in &variants {
            assert_ne!(
                v.canonical_aad_bytes(),
                base.canonical_aad_bytes(),
                "field change must change the canonical AAD: {v:?}"
            );
        }
    }

    /// The NUL separators keep the variable-length fields unambiguous:
    /// shifting a byte across the repo_uid/chunk_name boundary changes the bytes.
    #[test]
    fn chunk_aad_separators_prevent_field_sliding() {
        let a = ChunkAad::new("ab", "cd", 1, 0, 0).unwrap();
        let b = ChunkAad::new("abc", "d", 1, 0, 0).unwrap();
        assert_ne!(a.canonical_aad_bytes(), b.canonical_aad_bytes());
    }

    /// Constructor rules: content chunks bind offset 0 + real size; singleton
    /// objects bind offset 0 + size 0; both carry the key version given.
    #[test]
    fn chunk_aad_constructors_encode_dedup_rules() {
        let c = ChunkAad::content("aa11", "cafe", 4, 4096).unwrap();
        assert_eq!(c, ChunkAad::new("aa11", "cafe", 4, 0, 4096).unwrap());
        let o = ChunkAad::named("aa11", "stream-manifest", 4).unwrap();
        assert_eq!(o, ChunkAad::new("aa11", "stream-manifest", 4, 0, 0).unwrap());
        // The provisional version-less constructors bind the first key version.
        assert_eq!(ChunkAad::for_content_chunk("aa11", "cafe", 9).key_version, 1);
        assert_eq!(ChunkAad::for_named_object("aa11", "metadata").key_version, 1);
    }

    /// A blob in the retired v2 format — sealed exactly as the v2
    /// engine sealed it, under a name-bound AAD with no key version — is
    /// refused by the v3 reader, by its version byte, before any key is tried.
    #[test]
    fn v2_blob_is_rejected_by_a_v3_reader() {
        use crate::encryption::XChaChaChunkEngine;
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};

        let content_key = XChaChaChunkEngine::derive_content_key(&[7u8; 32]).unwrap();
        let nonce = [9u8; 24];
        // The v2 cipher AAD: 0x02 ‖ repo_id ‖ 0 ‖ chunk_name ‖ 0 ‖ offset ‖ size.
        let mut v2_aad = vec![V2_KEYED_CDC_NAMING];
        v2_aad.extend_from_slice(b"alice/proj\0cafe\0");
        v2_aad.extend_from_slice(&0u64.to_le_bytes());
        v2_aad.extend_from_slice(&5u64.to_le_bytes());
        let ct = XChaCha20Poly1305::new_from_slice(&content_key)
            .unwrap()
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: b"hello", aad: &v2_aad })
            .unwrap();
        let mut blob = vec![V2_KEYED_CDC_NAMING];
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);

        let engine = XChaChaChunkEngine::from_content_key(&content_key).unwrap();
        let v3_aad = ChunkAad::content("alice/proj", "cafe", 1, 5).unwrap();
        let err = engine.decrypt_with_aad(&blob, &v3_aad).unwrap_err();
        assert!(format!("{err}").contains("retired"), "refused by version, got: {err}");
        assert!(version_of(&blob).is_err());
    }

    /// A NUL in an AAD string field breaks the canonical's injectivity,
    /// so the constructor refuses it, and a seal or open under a value built
    /// field by field is refused too.
    #[test]
    fn aad_with_nul_is_refused() {
        use crate::encryption::XChaChaChunkEngine;
        assert!(ChunkAad::new("aa\011", "cafe", 1, 0, 5).is_err());
        assert!(ChunkAad::content("aa11", "ca\0fe", 1, 5).is_err());
        assert!(ChunkAad::named("aa11", "stream\0manifest", 1).is_err());

        let engine = XChaChaChunkEngine::new(&[7u8; 32]).unwrap();
        let smuggled = ChunkAad::for_content_chunk("aa\011", "cafe", 5);
        assert!(
            engine.encrypt_with_aad(b"hello", &smuggled).is_err(),
            "sealing under an AAD with a NUL in a string field must be refused"
        );
        let good = ChunkAad::content("aa11", "cafe", 1, 5).unwrap();
        let blob = engine.encrypt_with_aad(b"hello", &good).unwrap();
        assert!(engine.decrypt_with_aad(&blob, &smuggled).is_err());
    }

    #[test]
    fn version_of_reads_leading_byte() {
        // A v3-tagged buffer parses; retired and reserved tags are rejected.
        assert_eq!(version_of(&[3, 0xaa, 0xbb]).unwrap(), ChunkFormatVersion::RepoUidKeyVersionV3);
        assert!(version_of(&[1, 0xaa, 0xbb]).is_err());
        assert!(version_of(&[2, 0xaa, 0xbb]).is_err());
        assert!(version_of(&[6, 0xaa, 0xbb]).is_err());
    }
}
