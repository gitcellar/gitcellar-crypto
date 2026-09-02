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
//! | Byte | Meaning                                                        | Requirement |
//! |------|----------------------------------------------------------------|-------------|
//! | `1`  | XChaCha20-Poly1305 baseline, classical X25519-wrapped session key | F2 (P1) — **implemented** |
//! | `2`  | XChaCha20-Poly1305 + keyed-CDC / keyed-naming pipeline marker   | E1 (P2) — **implemented** |
//! | `3`  | hybrid-wrapped session key (X25519 + ML-KEM-768, KMAC256 KDF)   | E5 (P3 dark) — reserved |
//! | `4`  | AES-256-GCM-SIV enterprise / FIPS build variant                | DEC-CH-03 — reserved |
//! | `5`  | keyed-CDC via AES-per-byte (eprint 2025/558 provable)           | E1 AC-E1.8 — reserved |
//! | other| **explicit error** — refuse to misparse                        | AC-F6.3     |
//!
//! ## v1 vs v2 (E1)
//!
//! v2 chunk **bytes** are byte-for-byte the same XChaCha20-Poly1305 layout as v1
//! (`[ver][24B XNonce][ct][16B tag]`) and decrypt with the same content key. The
//! distinct version byte marks that the chunk was produced by the E1 keyed
//! pipeline — keyed CDC boundaries (`boundary_key_repo`) and keyed HMAC object
//! naming (`id_key_repo`) — and lets name-rotation (re-MAC) and boundary-rotation
//! (re-chunk) be reasoned about independently of the content cipher (AC-E1.6).
//!
//! Reserved values are documented and **not** emitted until their requirement
//! ships; `parse_version` rejects every byte except the implemented ones, so a
//! reserved-but-unimplemented chunk fails loudly rather than being mis-decoded.

use crate::error::{VaultError, VaultResult};

/// v1 — XChaCha20-Poly1305 baseline, classical X25519-wrapped session key (F2, P1).
pub const V1_XCHACHA20_POLY1305: u8 = 1;

/// v2 — XChaCha20-Poly1305 + keyed-CDC / keyed-naming pipeline marker (E1, P2).
/// Same cipher layout as v1; the byte records that keyed CDC + keyed naming
/// produced this chunk.
pub const V2_KEYED_CDC_NAMING: u8 = 2;

/// v3 (reserved) — hybrid-wrapped session key (X25519 + ML-KEM-768, KMAC256 KDF) (E5, P3 dark).
pub const V3_HYBRID_WRAP: u8 = 3;

/// v4 (reserved) — AES-256-GCM-SIV enterprise / FIPS build variant (DEC-CH-03).
pub const V4_AES_256_GCM_SIV: u8 = 4;

/// v5 (reserved) — keyed-CDC via AES-per-byte, eprint 2025/558 provable construction (E1 AC-E1.8).
pub const V5_KEYED_CDC_AES_PER_BYTE: u8 = 5;

/// A known, dispatchable chunk-format version (one variant per *implemented* format).
///
/// Reserved registry values (v3–v5) deliberately have no variant here: a chunk
/// carrying one is rejected by [`parse_version`] until its requirement ships and
/// adds the variant + unwrap path. This keeps "documented" and "dispatchable"
/// honestly distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkFormatVersion {
    /// v1 — XChaCha20-Poly1305 baseline (F2).
    XChaCha20Poly1305V1,
    /// v2 — XChaCha20-Poly1305 produced by the E1 keyed-CDC / keyed-naming
    /// pipeline (same cipher layout as v1; AC-E1.6).
    KeyedCdcNamingV2,
}

impl ChunkFormatVersion {
    /// The on-disk version byte for this format.
    pub fn as_byte(self) -> u8 {
        match self {
            ChunkFormatVersion::XChaCha20Poly1305V1 => V1_XCHACHA20_POLY1305,
            ChunkFormatVersion::KeyedCdcNamingV2 => V2_KEYED_CDC_NAMING,
        }
    }

    /// Whether this version's payload is the XChaCha20-Poly1305 AEAD layout
    /// (`[ver][24B nonce][ct][16B tag]`). Both v1 and v2 are — they share the
    /// content cipher and differ only in the chunking/naming pipeline that
    /// produced them (AC-E1.6).
    pub fn is_xchacha20_poly1305_layout(self) -> bool {
        matches!(
            self,
            ChunkFormatVersion::XChaCha20Poly1305V1 | ChunkFormatVersion::KeyedCdcNamingV2
        )
    }
}

// ============================================================================
// H-1 (+L-1) — per-chunk identity bound into the AEAD as associated data
// ============================================================================

/// Per-chunk identity, bound into the XChaCha20-Poly1305 AEAD as associated
/// data (H-1, folding in L-1).
///
/// All of a repo's chunks share one content key, so without AAD any same-key
/// blob decrypts cleanly anywhere — a malicious storage provider could splice,
/// reorder, or substitute blobs undetected. Binding the chunk's identity as
/// AAD makes a blob sealed under *its* real identity fail the Poly1305 tag
/// when opened under the manifest's *claimed* identity.
///
/// The cipher-level AAD is `version_byte(1) ‖ canonical_aad_bytes()` — the
/// engine prepends its emit-version byte on encrypt and the *observed*
/// `byte[0]` on decrypt, so a flipped format-version byte (v1↔v2) now fails
/// authentication too (the L-1 fix).
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
/// bind `stream_offset = 0` (see [`ChunkAad::for_content_chunk`]); positional
/// integrity (no gap/overlap/reorder in the covering set) is enforced
/// structurally on the read side against the *authenticated* manifest instead
/// (`assert_contiguous_tiling` in the Service). The field stays in the
/// canonical encoding so the wire format needs no change if a future format
/// version chooses to bind real positions (at the cost of dedup).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkAad {
    /// Repository identity (`owner/name`) the chunk belongs to.
    pub repo_id: String,
    /// The chunk's manifest name — the keyed HMAC hex name for content chunks
    /// (`StreamChunkEntry.hash`), or a fixed object name for singleton repo
    /// objects (`"stream-manifest"`, `"metadata"`).
    pub chunk_name: String,
    /// Stream offset bound into the AAD. `0` for production content chunks and
    /// singleton objects (see the dedup note on the struct).
    pub stream_offset: u64,
    /// Plaintext size in bytes (`StreamChunkEntry.size`). `0` for singleton
    /// objects whose size the reader cannot know before decrypting.
    pub size: u64,
}

impl ChunkAad {
    /// Construct from explicit parts.
    pub fn new(
        repo_id: impl Into<String>,
        chunk_name: impl Into<String>,
        stream_offset: u64,
        size: u64,
    ) -> Self {
        Self {
            repo_id: repo_id.into(),
            chunk_name: chunk_name.into(),
            stream_offset,
            size,
        }
    }

    /// AAD for a content chunk: binds `repo_id`, the keyed HMAC `chunk_name`,
    /// and the plaintext `size`; `stream_offset` is fixed to `0` because keyed
    /// -name dedup stores one blob for many stream positions (see the struct
    /// docs). Both the seal site (from `Chunk.hash`/`Chunk.size`) and the open
    /// site (from `StreamChunkEntry.hash`/`.size`) MUST use this constructor.
    pub fn for_content_chunk(repo_id: &str, chunk_name: &str, size: u64) -> Self {
        Self::new(repo_id, chunk_name, 0, size)
    }

    /// AAD for a singleton repo object (the encrypted stream manifest, the
    /// metadata bundle): binds `repo_id` and the object's fixed name; offset
    /// and size are `0` (the reader cannot know the size before decrypting).
    pub fn for_named_object(repo_id: &str, object_name: &str) -> Self {
        Self::new(repo_id, object_name, 0, 0)
    }

    /// Canonical AAD encoding, WITHOUT the leading version byte (the engine
    /// prepends that — emit-version on encrypt, observed `byte[0]` on decrypt):
    ///
    /// ```text
    /// repo_id ‖ 0x00 ‖ chunk_name ‖ 0x00 ‖ stream_offset(u64 LE) ‖ size(u64 LE)
    /// ```
    ///
    /// Injective for GitCellar inputs: `repo_id` (`owner/name`) and
    /// `chunk_name` (hex / fixed ASCII names) never contain `0x00`, so the two
    /// separators unambiguously delimit the variable-length fields, and the
    /// fixed-width LE integers close the encoding.
    pub fn canonical_aad_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.repo_id.len() + 1 + self.chunk_name.len() + 1 + 8 + 8,
        );
        out.extend_from_slice(self.repo_id.as_bytes());
        out.push(0x00);
        out.extend_from_slice(self.chunk_name.as_bytes());
        out.push(0x00);
        out.extend_from_slice(&self.stream_offset.to_le_bytes());
        out.extend_from_slice(&self.size.to_le_bytes());
        out
    }
}

/// Parse the leading format-version byte into a dispatchable version.
///
/// An unknown value — including a *reserved-but-unimplemented* registry value —
/// returns an explicit typed error (AC-F6.3). The decrypt path must propagate
/// this rather than guessing a format.
pub fn parse_version(byte: u8) -> VaultResult<ChunkFormatVersion> {
    match byte {
        V1_XCHACHA20_POLY1305 => Ok(ChunkFormatVersion::XChaCha20Poly1305V1),
        V2_KEYED_CDC_NAMING => Ok(ChunkFormatVersion::KeyedCdcNamingV2),
        other => Err(VaultError::Decryption(format!(
            "unknown chunk-format version byte 0x{other:02x}: not a recognized/implemented \
             GitCellar chunk format — refusing to misparse (F6 AC-F6.3)"
        ))),
    }
}

/// Read and validate the format-version byte from a stored chunk's first byte.
///
/// Errors if the chunk is empty (no version byte) or the byte is unknown.
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
    fn v1_byte_is_one_and_round_trips() {
        assert_eq!(V1_XCHACHA20_POLY1305, 1);
        assert_eq!(
            parse_version(1).unwrap(),
            ChunkFormatVersion::XChaCha20Poly1305V1
        );
        assert_eq!(ChunkFormatVersion::XChaCha20Poly1305V1.as_byte(), 1);
    }

    #[test]
    fn v2_byte_is_two_and_round_trips() {
        // E1 keyed-CDC/naming marker — implemented in P2.
        assert_eq!(V2_KEYED_CDC_NAMING, 2);
        assert_eq!(
            parse_version(2).unwrap(),
            ChunkFormatVersion::KeyedCdcNamingV2
        );
        assert_eq!(ChunkFormatVersion::KeyedCdcNamingV2.as_byte(), 2);
        // Both implemented versions share the XChaCha20-Poly1305 payload layout.
        assert!(ChunkFormatVersion::XChaCha20Poly1305V1.is_xchacha20_poly1305_layout());
        assert!(ChunkFormatVersion::KeyedCdcNamingV2.is_xchacha20_poly1305_layout());
    }

    #[test]
    fn unknown_version_byte_is_explicit_error_never_silent() {
        // Every value except the implemented v1/v2 must error — including the
        // reserved-but-unimplemented registry values (3..=5) and arbitrary bytes.
        for b in [0u8, 3, 4, 5, 6, 42, 200, 255] {
            let err = parse_version(b).unwrap_err();
            assert!(
                matches!(err, VaultError::Decryption(_)),
                "byte {b} must be an explicit Decryption error, got {err:?}"
            );
        }
    }

    #[test]
    fn version_of_rejects_empty_chunk() {
        assert!(version_of(&[]).is_err());
    }

    // ------------------------------------------------------------------
    // H-1 — ChunkAad canonical encoding
    // ------------------------------------------------------------------

    /// Golden encoding: pins the exact byte layout
    /// `repo_id ‖ 0x00 ‖ chunk_name ‖ 0x00 ‖ offset(u64 LE) ‖ size(u64 LE)`.
    #[test]
    fn chunk_aad_canonical_bytes_golden() {
        let aad = ChunkAad::new("alice/proj", "abcd", 0x0102, 0x0304);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"alice/proj");
        expected.push(0);
        expected.extend_from_slice(b"abcd");
        expected.push(0);
        expected.extend_from_slice(&0x0102u64.to_le_bytes());
        expected.extend_from_slice(&0x0304u64.to_le_bytes());
        assert_eq!(aad.canonical_aad_bytes(), expected);
    }

    /// Every field participates: changing any one field changes the encoding.
    #[test]
    fn chunk_aad_every_field_is_load_bearing() {
        let base = ChunkAad::new("alice/proj", "cafe", 7, 42);
        let variants = [
            ChunkAad::new("alice/other", "cafe", 7, 42),
            ChunkAad::new("alice/proj", "beef", 7, 42),
            ChunkAad::new("alice/proj", "cafe", 8, 42),
            ChunkAad::new("alice/proj", "cafe", 7, 43),
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
    /// shifting a byte across the repo_id/chunk_name boundary changes the bytes.
    #[test]
    fn chunk_aad_separators_prevent_field_sliding() {
        let a = ChunkAad::new("ab", "cd", 0, 0);
        let b = ChunkAad::new("abc", "d", 0, 0);
        assert_ne!(a.canonical_aad_bytes(), b.canonical_aad_bytes());
    }

    /// Constructor rules: content chunks bind offset 0 + real size; singleton
    /// objects bind offset 0 + size 0.
    #[test]
    fn chunk_aad_constructors_encode_dedup_rules() {
        let c = ChunkAad::for_content_chunk("alice/proj", "cafe", 4096);
        assert_eq!(c, ChunkAad::new("alice/proj", "cafe", 0, 4096));
        let o = ChunkAad::for_named_object("alice/proj", "stream-manifest");
        assert_eq!(o, ChunkAad::new("alice/proj", "stream-manifest", 0, 0));
    }

    #[test]
    fn version_of_reads_leading_byte() {
        // A v1- or v2-tagged buffer parses; a reserved-tagged buffer is rejected.
        assert_eq!(
            version_of(&[1, 0xaa, 0xbb]).unwrap(),
            ChunkFormatVersion::XChaCha20Poly1305V1
        );
        assert_eq!(
            version_of(&[2, 0xaa, 0xbb]).unwrap(),
            ChunkFormatVersion::KeyedCdcNamingV2
        );
        // v3 is reserved-but-unimplemented → rejected.
        assert!(version_of(&[3, 0xaa, 0xbb]).is_err());
    }
}
