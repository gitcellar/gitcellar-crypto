//! Content-Defined Chunking (CDC) for efficient deduplication
//!
//! Variable-size chunking via **gear-based FastCDC**. Content-defined chunking
//! enables deduplication by producing consistent chunk boundaries regardless of
//! insertions/deletions.
//!
//! ## Keyed CDC + keyed naming (E1)
//!
//! The boundary function and the chunk *name* can both be **keyed per repo**
//! (crypto-hardening E1, DEC-CH-04):
//!
//! - **Keyed boundaries (AC-E1.2/E1.3)** — the FastCDC Gear table is derived
//!   from a per-repo `boundary_key_repo` via keyed BLAKE3:
//!   `gear[i] = first-64-bits(BLAKE3_keyed(boundary_key_repo, "gear-table" ‖ LE32(i)))`.
//!   A different `boundary_key_repo` yields different cut points on identical
//!   input, so the storage provider cannot reproduce chunk boundaries or
//!   fingerprint plaintext structure from them. This is **not** an algebraic
//!   seed (no 32-bit `chunk_seed`, no secret Rabin polynomial — the
//!   eprint-2025/558-broken designs are explicitly rejected, AC-E1.3).
//! - **Keyed naming (AC-E1.1)** — the chunk object name becomes
//!   `HMAC-SHA256(id_key_repo, plaintext_chunk)` instead of a bare
//!   `SHA-256(plaintext)`. Same plaintext + same repo key → identical name
//!   (per-repo dedup preserved); a different repo key → a different name (the
//!   confirmation-of-file oracle is closed — the provider cannot compute a name
//!   without `id_key_repo`).
//!
//! Both keys are independent HKDF outputs domain-separated from the F2 content
//! key (see [`crate::encryption`] / `gitcellar-crypto`); they are passed in as a
//! [`ChunkKeying`]. When no keying is supplied the engine runs **unkeyed**:
//! FastCDC with a fixed public Gear table + SHA-256 names. The unkeyed path
//! retains a working chunker for FFI consumers while still retiring the
//! old dead rolling-hash window (R-3) — there is now a single boundary function.
//!
//! # Example
//!
//! ```rust
//! use vault_core::chunking::{ChunkEngine, ChunkConfig};
//!
//! let engine = ChunkEngine::new(ChunkConfig::default());
//! let data = vec![0u8; 5 * 1024 * 1024]; // 5MB
//! let chunks = engine.chunk_data(&data).unwrap();
//!
//! // Reassemble
//! let reassembled = ChunkEngine::reassemble_chunks(&chunks).unwrap();
//! assert_eq!(data, reassembled);
//! ```

use crate::error::VaultResult;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

type HmacSha256 = Hmac<Sha256>;

/// Number of entries in the Gear table — one per possible byte value.
const GEAR_TABLE_SIZE: usize = 256;

/// Fixed public key for the **unkeyed** Gear table. Unkeyed CDC carries no
/// confidentiality requirement (it is used by FFI backup consumers, not
/// the zero-access repo path), so a documented constant key is correct here —
/// it just gives a well-distributed, deterministic, content-defined boundary
/// function that retires the old polynomial rolling-hash window (R-3). The E1
/// repo path always supplies a real per-repo `boundary_key_repo` instead.
const UNKEYED_GEAR_KEY: &[u8; 32] = b"gitcellar/unkeyed-cdc/gear/v1!!!";

/// Derive a 256-entry FastCDC Gear table from a 32-byte key via keyed BLAKE3.
///
/// `gear[i] = first-64-bits(BLAKE3_keyed(key, "gear-table" ‖ LE32(i)))`
/// (AC-E1.2). Used for both the per-repo keyed table (`boundary_key_repo`) and
/// the fixed unkeyed table ([`UNKEYED_GEAR_KEY`]).
fn derive_gear_table(key: &[u8; 32]) -> [u64; GEAR_TABLE_SIZE] {
    let mut gear = [0u64; GEAR_TABLE_SIZE];
    let mut msg = [0u8; 14]; // b"gear-table" (10) + LE32(i) (4)
    msg[..10].copy_from_slice(b"gear-table");
    for (i, slot) in gear.iter_mut().enumerate() {
        msg[10..].copy_from_slice(&(i as u32).to_le_bytes());
        let hash = blake3::keyed_hash(key, &msg);
        let mut first8 = [0u8; 8];
        first8.copy_from_slice(&hash.as_bytes()[..8]);
        *slot = u64::from_le_bytes(first8);
    }
    gear
}

/// A mask selecting the top `n` bits of a 64-bit fingerprint.
///
/// FastCDC tests `(fp & mask) == 0` per byte; with the top-`n`-bits mask the
/// per-byte cut probability is ≈ 2⁻ⁿ, so the expected chunk size is ≈ 2ⁿ bytes.
fn top_bits_mask(n: u32) -> u64 {
    match n {
        0 => 0,
        n if n >= 64 => !0u64,
        n => (!0u64) << (64 - n),
    }
}

/// Gear-based FastCDC boundary search with normalized chunking.
///
/// Returns the cut length for the chunk starting at the front of `data`,
/// guaranteed in `[min, min(max, data.len())]` (the final chunk of a stream may
/// be shorter than `min`). Normalized chunking uses a stricter mask before the
/// target size (suppressing early cuts so chunks grow toward the average) and a
/// looser mask after it (encouraging a cut before `max`), tightening the size
/// distribution around `avg` without a hard fixed size.
fn fastcdc_boundary(
    gear: &[u64; GEAR_TABLE_SIZE],
    data: &[u8],
    min: usize,
    avg: usize,
    max: usize,
) -> usize {
    let len = data.len();
    if len <= min {
        return len;
    }
    let cap = max.min(len);
    let normal = avg.clamp(min, cap);

    // floor(log2(avg)); ±1 around it gives the two normalized masks.
    let bits = 63 - (avg.max(2) as u64).leading_zeros();
    let mask_s = top_bits_mask(bits + 1); // stricter: fewer early cuts
    let mask_l = top_bits_mask(bits.saturating_sub(1)); // looser: cut before max

    let mut fp: u64 = 0;
    let mut i = min; // FastCDC skips the first `min` bytes from the hash

    while i < normal {
        fp = (fp << 1).wrapping_add(gear[data[i] as usize]);
        if (fp & mask_s) == 0 {
            return i;
        }
        i += 1;
    }
    while i < cap {
        fp = (fp << 1).wrapping_add(gear[data[i] as usize]);
        if (fp & mask_l) == 0 {
            return i;
        }
        i += 1;
    }
    cap
}

/// Per-repo keyed-CDC + keyed-naming material (E1).
///
/// Holds the BLAKE3-derived Gear table (from `boundary_key_repo`) and the
/// `id_key_repo` used for HMAC chunk naming. Both keys are independent HKDF
/// outputs domain-separated from the F2 content key — the caller
/// (`gitcellar-crypto`) derives them from `K_repo` and constructs this via
/// [`ChunkKeying::derive`]. The provider never receives either key.
#[derive(Clone)]
pub struct ChunkKeying {
    gear: [u64; GEAR_TABLE_SIZE],
    id_key: [u8; 32],
}

impl ChunkKeying {
    /// Build keying from the two per-repo E1 keys.
    ///
    /// * `boundary_key_repo` — `HKDF(K_repo, "gitcellar/cdc-boundary/v1", 32)`;
    ///   keys the FastCDC Gear table (AC-E1.2).
    /// * `id_key_repo` — `HKDF(K_repo, "gitcellar/chunk-name/v1", 32)`; keys the
    ///   HMAC chunk name (AC-E1.1).
    pub fn derive(boundary_key_repo: &[u8; 32], id_key_repo: &[u8; 32]) -> Self {
        Self {
            gear: derive_gear_table(boundary_key_repo),
            id_key: *id_key_repo,
        }
    }

    /// `HMAC-SHA256(id_key_repo, plaintext_chunk)`, lowercase hex (AC-E1.1).
    fn name(&self, data: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.id_key).expect("HMAC-SHA256 accepts any key length");
        mac.update(data);
        format!("{:x}", mac.finalize().into_bytes())
    }
}

/// Configuration for the chunking algorithm
///
/// `default()` keeps the historical 512 KiB / 1 MiB / 2 MiB profile (used by
/// FFI consumers and existing callers). The E1 repo path uses
/// [`ChunkConfig::e1_keyed`] (16 KiB / 64 KiB / 256 KiB per AC-E1.2).
#[derive(Debug, Clone)]
#[repr(C)]
pub struct ChunkConfig {
    /// Minimum chunk size in bytes.
    ///
    /// Chunks will never be smaller than this, except for the last
    /// chunk in a file which may be any size.
    pub min_size: usize,

    /// Average/target chunk size in bytes.
    ///
    /// The boundary function aims to produce chunks of this average size.
    pub avg_size: usize,

    /// Maximum chunk size in bytes.
    ///
    /// Chunks will never exceed this size, ensuring bounded memory
    /// usage during processing.
    pub max_size: usize,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            min_size: 512 * 1024,      // 512KB
            avg_size: 1024 * 1024,     // 1MB
            max_size: 2 * 1024 * 1024, // 2MB
        }
    }
}

impl ChunkConfig {
    /// Create a new configuration with custom sizes
    ///
    /// # Arguments
    /// * `min_size` - Minimum chunk size in bytes
    /// * `avg_size` - Average/target chunk size in bytes
    /// * `max_size` - Maximum chunk size in bytes
    ///
    /// # Panics
    /// Panics if min_size > avg_size > max_size invariant is violated.
    pub fn new(min_size: usize, avg_size: usize, max_size: usize) -> Self {
        assert!(min_size <= avg_size, "min_size must be <= avg_size");
        assert!(avg_size <= max_size, "avg_size must be <= max_size");
        Self {
            min_size,
            avg_size,
            max_size,
        }
    }

    /// The E1 keyed-CDC size profile: min 16 KiB / target 64 KiB / max 256 KiB
    /// (AC-E1.2). Smaller chunks than the legacy default → finer dedup and less
    /// size leakage per object, matched to the restic-class packed-blob model.
    pub fn e1_keyed() -> Self {
        Self {
            min_size: 16 * 1024,
            avg_size: 64 * 1024,
            max_size: 256 * 1024,
        }
    }
}

/// Represents a single chunk of data
///
/// A chunk contains the actual data along with metadata for
/// storage and verification.
#[derive(Debug, Clone)]
pub struct Chunk {
    /// Chunk name / identifier.
    ///
    /// Unkeyed: `SHA-256(data)`. Keyed (E1): `HMAC-SHA256(id_key_repo, data)`
    /// (AC-E1.1). Either way it is a 64-char lowercase-hex string that serves as
    /// the storage object name, the dedup key, and an integrity reference;
    /// identical content under the same key always produces the same name.
    pub hash: String,

    /// Chunk data
    pub data: Vec<u8>,

    /// Size in bytes
    pub size: usize,

    /// Offset in original file
    ///
    /// Used during reassembly to place chunks in correct order.
    pub offset: u64,
}

/// Chunk metadata for storage (without actual data)
///
/// This lightweight struct is used for manifests and chunk lists
/// where the full data isn't needed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChunkMetadata {
    /// Chunk name (`SHA-256` unkeyed / `HMAC-SHA256` keyed).
    pub hash: String,
    /// Size in bytes
    pub size: usize,
    /// Offset in original file
    pub offset: u64,
}

impl From<&Chunk> for ChunkMetadata {
    fn from(chunk: &Chunk) -> Self {
        Self {
            hash: chunk.hash.clone(),
            size: chunk.size,
            offset: chunk.offset,
        }
    }
}

/// Content-Defined Chunking engine
///
/// Uses gear-based FastCDC to find content-defined boundaries: inserting data at
/// the start of a file changes only the first chunk; the rest remain identical.
/// Optionally keyed per repo ([`ChunkKeying`]) for E1 keyed boundaries + naming.
pub struct ChunkEngine {
    config: ChunkConfig,
    gear: [u64; GEAR_TABLE_SIZE],
    keying: Option<ChunkKeying>,
}

impl ChunkEngine {
    /// Create a new **unkeyed** chunking engine (FastCDC with the fixed public
    /// Gear table, SHA-256 names).
    pub fn new(config: ChunkConfig) -> Self {
        Self {
            config,
            gear: derive_gear_table(UNKEYED_GEAR_KEY),
            keying: None,
        }
    }

    /// Create a new chunking engine with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ChunkConfig::default())
    }

    /// Create a **keyed** (E1) chunking engine: FastCDC boundaries from the
    /// repo's `boundary_key_repo` Gear table and `HMAC-SHA256(id_key_repo, …)`
    /// names (AC-E1.1/E1.2). Pair with [`ChunkConfig::e1_keyed`].
    pub fn new_keyed(config: ChunkConfig, keying: ChunkKeying) -> Self {
        Self {
            config,
            gear: keying.gear,
            keying: Some(keying),
        }
    }

    /// Get the configuration
    pub fn config(&self) -> &ChunkConfig {
        &self.config
    }

    /// Compute the name for a chunk's data with this engine's keying
    /// (`HMAC-SHA256` keyed / `SHA-256` unkeyed).
    fn name(&self, data: &[u8]) -> String {
        match &self.keying {
            Some(k) => k.name(data),
            None => Self::compute_hash(data),
        }
    }

    /// Create chunks from data using content-defined chunking
    ///
    /// # Arguments
    /// * `data` - The data to chunk
    ///
    /// # Returns
    /// A vector of chunks in order
    pub fn chunk_data(&self, data: &[u8]) -> VaultResult<Vec<Chunk>> {
        info!("Chunking {} bytes of data", data.len());

        if data.is_empty() {
            return Ok(vec![]);
        }

        let mut chunks = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let chunk_size = self.find_chunk_boundary(&data[offset..]);
            let chunk_data = &data[offset..std::cmp::min(offset + chunk_size, data.len())];

            let hash = self.name(chunk_data);

            chunks.push(Chunk {
                hash: hash.clone(),
                data: chunk_data.to_vec(),
                size: chunk_data.len(),
                offset: offset as u64,
            });

            debug!(
                "Created chunk: {} bytes at offset {}, name: {}",
                chunk_data.len(),
                offset,
                &hash[..16]
            );
            offset += chunk_size;
        }

        info!("Created {} chunks from {} bytes", chunks.len(), data.len());
        Ok(chunks)
    }

    /// Find chunk boundary using gear-based FastCDC.
    ///
    /// Boundaries depend on this engine's Gear table — the per-repo
    /// `boundary_key_repo` table when keyed (E1), the fixed public table when
    /// unkeyed. Replaces the retired polynomial rolling-hash window (R-3).
    fn find_chunk_boundary(&self, data: &[u8]) -> usize {
        fastcdc_boundary(
            &self.gear,
            data,
            self.config.min_size,
            self.config.avg_size,
            self.config.max_size,
        )
    }

    /// Compute SHA256 hash of data
    ///
    /// Returns lowercase hexadecimal string. This is the **unkeyed** name
    /// function (and a general-purpose content hash); E1 keyed names use
    /// `HMAC-SHA256` instead (see [`ChunkKeying`]).
    pub fn compute_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        format!("{:x}", hasher.finalize())
    }

    /// Reassemble chunks back into original data
    ///
    /// # Arguments
    /// * `chunks` - Chunks in order (by offset)
    ///
    /// # Returns
    /// The reassembled data
    pub fn reassemble_chunks(chunks: &[Chunk]) -> VaultResult<Vec<u8>> {
        if chunks.is_empty() {
            return Ok(vec![]);
        }

        let total_size: usize = chunks.iter().map(|c| c.size).sum();
        let mut data = Vec::with_capacity(total_size);

        for chunk in chunks {
            data.extend_from_slice(&chunk.data);
        }

        Ok(data)
    }

    /// Verify chunk integrity by recomputing its name with this engine's keying.
    ///
    /// # Returns
    /// true if the chunk's recomputed name matches its stored name.
    pub fn verify_chunk(&self, chunk: &Chunk) -> bool {
        let computed = self.name(&chunk.data);
        computed == chunk.hash
    }

    /// Verify all chunks in a list
    ///
    /// # Arguments
    /// * `chunks` - The chunks to verify
    ///
    /// # Returns
    /// true if all chunks verify successfully
    pub fn verify_all(&self, chunks: &[Chunk]) -> bool {
        chunks.iter().all(|c| self.verify_chunk(c))
    }

    /// Get metadata for all chunks (without data)
    ///
    /// Useful for creating manifests or chunk lists.
    pub fn get_metadata(chunks: &[Chunk]) -> Vec<ChunkMetadata> {
        chunks.iter().map(ChunkMetadata::from).collect()
    }
}

/// Streaming CDC chunker for incremental data feeding
///
/// Unlike `ChunkEngine::chunk_data()` which requires all data in memory,
/// `StreamChunker` allows feeding data incrementally (e.g., file by file)
/// while producing identical chunk boundaries across the virtual stream.
///
/// Like [`ChunkEngine`], it may be **keyed** ([`StreamChunker::new_keyed`]) for
/// E1 keyed boundaries + naming, or unkeyed ([`StreamChunker::new`]).
///
/// # Example
///
/// ```rust
/// use vault_core::chunking::{StreamChunker, ChunkConfig};
///
/// let mut chunker = StreamChunker::new(ChunkConfig::default());
/// chunker.feed(b"first file content");
/// chunker.feed(b"second file content");
/// let chunks = chunker.finalize();
/// ```
pub struct StreamChunker {
    config: ChunkConfig,
    gear: [u64; GEAR_TABLE_SIZE],
    keying: Option<ChunkKeying>,
    buffer: Vec<u8>,
    offset: u64,
    chunks: Vec<Chunk>,
}

impl StreamChunker {
    /// Create a new **unkeyed** stream chunker.
    pub fn new(config: ChunkConfig) -> Self {
        Self {
            config,
            gear: derive_gear_table(UNKEYED_GEAR_KEY),
            keying: None,
            buffer: Vec::new(),
            offset: 0,
            chunks: Vec::new(),
        }
    }

    /// Create a **keyed** (E1) stream chunker: per-repo `boundary_key_repo`
    /// FastCDC boundaries + `HMAC-SHA256(id_key_repo, …)` names.
    pub fn new_keyed(config: ChunkConfig, keying: ChunkKeying) -> Self {
        Self {
            config,
            gear: keying.gear,
            keying: Some(keying),
            buffer: Vec::new(),
            offset: 0,
            chunks: Vec::new(),
        }
    }

    /// Name a chunk's data with this chunker's keying.
    fn name(&self, data: &[u8]) -> String {
        match &self.keying {
            Some(k) => k.name(data),
            None => ChunkEngine::compute_hash(data),
        }
    }

    /// Feed data into the chunker
    ///
    /// Appends data to the internal buffer and emits complete chunks
    /// whenever a CDC boundary is found. The remaining data stays in
    /// the buffer until more data is fed or `finalize()` is called.
    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        self.emit_chunks();
    }

    /// Signal end of stream and return all chunks
    ///
    /// Flushes the remaining buffer as the final chunk (if non-empty)
    /// and returns all accumulated chunks. The chunker is consumed.
    pub fn finalize(mut self) -> Vec<Chunk> {
        // Flush remaining buffer as final chunk
        if !self.buffer.is_empty() {
            let data = std::mem::take(&mut self.buffer);
            let hash = self.name(&data);
            let size = data.len();
            self.chunks.push(Chunk {
                hash,
                data,
                size,
                offset: self.offset,
            });
        }
        self.chunks
    }

    /// Scan buffer for chunk boundaries and emit complete chunks
    fn emit_chunks(&mut self) {
        loop {
            if self.buffer.len() <= self.config.min_size {
                break;
            }

            let boundary = self.find_boundary();
            if boundary >= self.buffer.len() && self.buffer.len() < self.config.max_size {
                // No boundary found and buffer isn't at max_size yet — wait for more data
                break;
            }

            // Emit chunk up to the boundary
            let chunk_size = std::cmp::min(boundary, self.buffer.len());
            let chunk_data: Vec<u8> = self.buffer.drain(..chunk_size).collect();
            let hash = self.name(&chunk_data);
            let size = chunk_data.len();

            debug!(
                "StreamChunker: chunk {} bytes at offset {}",
                size, self.offset
            );

            self.chunks.push(Chunk {
                hash,
                data: chunk_data,
                size,
                offset: self.offset,
            });
            self.offset += size as u64;
        }
    }

    /// Find the next chunk boundary in the buffer using the same gear-based
    /// FastCDC as [`ChunkEngine::find_chunk_boundary`].
    fn find_boundary(&self) -> usize {
        fastcdc_boundary(
            &self.gear,
            &self.buffer,
            self.config.min_size,
            self.config.avg_size,
            self.config.max_size,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two independent 32-byte E1 keys for keyed-path tests.
    fn keying_a() -> ChunkKeying {
        ChunkKeying::derive(&[0x11; 32], &[0x22; 32])
    }
    fn keying_b() -> ChunkKeying {
        ChunkKeying::derive(&[0xAA; 32], &[0xBB; 32])
    }

    /// Deterministic high-entropy bytes (xorshift64*) — stands in for real repo
    /// content. Plain periodic patterns (e.g. `(i*k) as u8`) are pathological for
    /// any rolling/gear CDC: their period is shorter than the hash window, so the
    /// fingerprint cycles through a handful of values and boundaries never fire —
    /// not a property of the algorithm, just of degenerate input.
    fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x >> 12;
                x ^= x << 25;
                x ^= x >> 27;
                (x.wrapping_mul(0x2545F4914F6CDD1D) >> 33) as u8
            })
            .collect()
    }

    #[test]
    fn test_default_config() {
        let config = ChunkConfig::default();
        assert_eq!(config.min_size, 512 * 1024);
        assert_eq!(config.avg_size, 1024 * 1024);
        assert_eq!(config.max_size, 2 * 1024 * 1024);
    }

    #[test]
    fn test_e1_keyed_config_sizes() {
        // AC-E1.2: min 16 KiB / target 64 KiB / max 256 KiB.
        let c = ChunkConfig::e1_keyed();
        assert_eq!(c.min_size, 16 * 1024);
        assert_eq!(c.avg_size, 64 * 1024);
        assert_eq!(c.max_size, 256 * 1024);
    }

    #[test]
    fn test_chunk_empty_data() {
        let engine = ChunkEngine::new(ChunkConfig::default());
        let chunks = engine.chunk_data(&[]).unwrap();
        assert_eq!(chunks.len(), 0);
    }

    #[test]
    fn test_chunk_small_data() {
        let engine = ChunkEngine::new(ChunkConfig::default());
        let data = vec![0u8; 1024]; // 1KB (less than min_size)
        let chunks = engine.chunk_data(&data).unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].size, 1024);
        assert_eq!(chunks[0].offset, 0);
    }

    #[test]
    fn test_chunk_large_data() {
        let engine = ChunkEngine::new(ChunkConfig::default());
        let data = vec![0u8; 10 * 1024 * 1024]; // 10MB
        let chunks = engine.chunk_data(&data).unwrap();

        assert!(chunks.len() > 1);

        // Verify all chunks are within size bounds
        for chunk in &chunks[..chunks.len() - 1] {
            // All but last chunk
            assert!(chunk.size >= engine.config.min_size);
            assert!(chunk.size <= engine.config.max_size);
        }
    }

    #[test]
    fn test_reassemble_chunks() {
        let engine = ChunkEngine::new(ChunkConfig::default());
        let original_data = vec![42u8; 5 * 1024 * 1024]; // 5MB

        let chunks = engine.chunk_data(&original_data).unwrap();
        let reassembled = ChunkEngine::reassemble_chunks(&chunks).unwrap();

        assert_eq!(original_data, reassembled);
    }

    #[test]
    fn test_verify_chunk() {
        let engine = ChunkEngine::new(ChunkConfig::default());
        let data = vec![1, 2, 3, 4, 5];
        let chunks = engine.chunk_data(&data).unwrap();

        assert!(engine.verify_chunk(&chunks[0]));

        // Corrupt chunk
        let mut corrupted = chunks[0].clone();
        corrupted.data[0] = 99;
        assert!(!engine.verify_chunk(&corrupted));
    }

    #[test]
    fn test_content_based_hashing() {
        let engine = ChunkEngine::new(ChunkConfig::default());

        // Same content should produce same hash
        let data1 = vec![42u8; 1024];
        let data2 = vec![42u8; 1024];

        let chunks1 = engine.chunk_data(&data1).unwrap();
        let chunks2 = engine.chunk_data(&data2).unwrap();

        assert_eq!(chunks1[0].hash, chunks2[0].hash);
    }

    #[test]
    fn test_chunk_metadata() {
        let engine = ChunkEngine::new(ChunkConfig::default());
        let data = vec![1u8; 1024];
        let chunks = engine.chunk_data(&data).unwrap();

        let metadata = ChunkEngine::get_metadata(&chunks);
        assert_eq!(metadata.len(), chunks.len());
        assert_eq!(metadata[0].hash, chunks[0].hash);
        assert_eq!(metadata[0].size, chunks[0].size);
        assert_eq!(metadata[0].offset, chunks[0].offset);
    }

    #[test]
    fn test_stream_chunker_matches_chunk_data() {
        let config = ChunkConfig::default();
        let engine = ChunkEngine::new(config.clone());

        // Build a large data block
        let data = vec![42u8; 5 * 1024 * 1024]; // 5MB

        // Chunk with ChunkEngine (all-at-once)
        let expected = engine.chunk_data(&data).unwrap();

        // Chunk with StreamChunker (single feed)
        let mut chunker = StreamChunker::new(config);
        chunker.feed(&data);
        let actual = chunker.finalize();

        assert_eq!(expected.len(), actual.len());
        for (e, a) in expected.iter().zip(actual.iter()) {
            assert_eq!(e.hash, a.hash);
            assert_eq!(e.size, a.size);
            assert_eq!(e.offset, a.offset);
        }
    }

    #[test]
    fn test_stream_chunker_incremental_feed() {
        let config = ChunkConfig::new(64, 256, 512);

        // Feed data in small increments (simulating many small files)
        let mut chunker = StreamChunker::new(config.clone());
        let mut all_data = Vec::new();

        for i in 0..100 {
            let file_data = vec![(i % 256) as u8; 200]; // 200-byte "files"
            all_data.extend_from_slice(&file_data);
            chunker.feed(&file_data);
        }

        let chunks = chunker.finalize();

        // Verify all data is preserved
        let reassembled = ChunkEngine::reassemble_chunks(&chunks).unwrap();
        assert_eq!(all_data, reassembled);

        // Verify chunks respect bounds (all but last)
        for chunk in &chunks[..chunks.len().saturating_sub(1)] {
            assert!(chunk.size >= config.min_size, "chunk too small: {}", chunk.size);
            assert!(chunk.size <= config.max_size, "chunk too big: {}", chunk.size);
        }
    }

    #[test]
    fn test_stream_chunker_large_feeds() {
        let config = ChunkConfig::new(64, 256, 512);

        // Feed data in large blocks
        let mut chunker = StreamChunker::new(config.clone());
        let block = vec![7u8; 2048];
        chunker.feed(&block);
        chunker.feed(&block);

        let chunks = chunker.finalize();

        let reassembled = ChunkEngine::reassemble_chunks(&chunks).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&block);
        expected.extend_from_slice(&block);
        assert_eq!(expected, reassembled);

        // Should have multiple chunks
        assert!(chunks.len() > 1);
    }

    #[test]
    fn test_stream_chunker_empty() {
        let chunker = StreamChunker::new(ChunkConfig::default());
        let chunks = chunker.finalize();
        assert_eq!(chunks.len(), 0);
    }

    // ========================================================================
    // E1 — keyed naming (AC-E1.1) + keyed CDC (AC-E1.2/E1.3)
    // ========================================================================

    /// AC-E1.1 — keyed naming: same plaintext + same repo key → identical name
    /// (dedup preserved); different repo key → different name (oracle closed);
    /// and the keyed name is NOT the bare SHA-256 (the provider, who could
    /// compute SHA-256, cannot compute the name).
    #[test]
    fn e1_keyed_naming_is_deterministic_key_scoped_and_not_sha256() {
        let data = b"the quick brown fox jumps over the lazy dog, repeatedly".repeat(64);

        let a1 = ChunkEngine::new_keyed(ChunkConfig::e1_keyed(), keying_a());
        let a2 = ChunkEngine::new_keyed(ChunkConfig::e1_keyed(), keying_a());
        let b = ChunkEngine::new_keyed(ChunkConfig::e1_keyed(), keying_b());

        let name_a1 = a1.name(&data);
        let name_a2 = a2.name(&data);
        let name_b = b.name(&data);

        // Same repo key → identical name (per-repo dedup preserved).
        assert_eq!(name_a1, name_a2);
        // Different repo key → different name (confirmation-of-file oracle closed).
        assert_ne!(name_a1, name_b);
        // Keyed name is an HMAC, not the public SHA-256 the provider can compute.
        assert_ne!(name_a1, ChunkEngine::compute_hash(&data));
        // Still a 64-char hex string (storage-key / validate_chunk_hash compatible).
        assert_eq!(name_a1.len(), 64);
        assert!(name_a1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// AC-E1.2 — keyed boundaries: a different `boundary_key_repo` yields
    /// different cut points on identical input; the same key is deterministic.
    #[test]
    fn e1_keyed_cdc_boundaries_depend_on_boundary_key() {
        // ~512 KiB of high-entropy data so boundaries actually fire.
        let data = pseudo_random(512 * 1024, 0xC0FFEE);

        let a = ChunkEngine::new_keyed(ChunkConfig::e1_keyed(), keying_a());
        let a_again = ChunkEngine::new_keyed(ChunkConfig::e1_keyed(), keying_a());
        let b = ChunkEngine::new_keyed(ChunkConfig::e1_keyed(), keying_b());

        let cuts = |e: &ChunkEngine| -> Vec<u64> {
            e.chunk_data(&data).unwrap().iter().map(|c| c.offset).collect()
        };
        let cuts_a = cuts(&a);
        let cuts_a2 = cuts(&a_again);
        let cuts_b = cuts(&b);

        // Deterministic for a given key.
        assert_eq!(cuts_a, cuts_a2);
        // Multiple chunks were produced (the boundary fn fired).
        assert!(cuts_a.len() > 2, "expected several chunks, got {}", cuts_a.len());
        // Different boundary key → different cut points (provider cannot
        // reproduce boundaries without boundary_key_repo).
        assert_ne!(cuts_a, cuts_b, "different boundary keys must cut differently");
    }

    /// Keyed chunking still reassembles losslessly and respects size bounds.
    #[test]
    fn e1_keyed_cdc_reassembles_and_respects_bounds() {
        let data = pseudo_random(3 * 1024 * 1024, 0xBEEF);
        let config = ChunkConfig::e1_keyed();
        let engine = ChunkEngine::new_keyed(config.clone(), keying_a());

        let chunks = engine.chunk_data(&data).unwrap();
        assert!(chunks.len() > 1);
        let reassembled = ChunkEngine::reassemble_chunks(&chunks).unwrap();
        assert_eq!(data, reassembled);

        for chunk in &chunks[..chunks.len() - 1] {
            assert!(chunk.size >= config.min_size, "chunk too small: {}", chunk.size);
            assert!(chunk.size <= config.max_size, "chunk too big: {}", chunk.size);
        }
        // Keyed verify recomputes the HMAC name.
        assert!(engine.verify_all(&chunks));
    }

    /// Keyed `StreamChunker` matches keyed `ChunkEngine` (same key, same input).
    #[test]
    fn e1_keyed_stream_matches_engine() {
        let data = pseudo_random(2 * 1024 * 1024, 0xD00D);
        let config = ChunkConfig::e1_keyed();

        let engine = ChunkEngine::new_keyed(config.clone(), keying_a());
        let expected = engine.chunk_data(&data).unwrap();

        let mut chunker = StreamChunker::new_keyed(config, keying_a());
        chunker.feed(&data);
        let actual = chunker.finalize();

        assert_eq!(expected.len(), actual.len());
        for (e, a) in expected.iter().zip(actual.iter()) {
            assert_eq!(e.hash, a.hash);
            assert_eq!(e.size, a.size);
            assert_eq!(e.offset, a.offset);
        }
    }

    /// The Gear table is fully key-determined: deriving twice from the same key
    /// is identical; a different key gives a (overwhelmingly) different table.
    #[test]
    fn e1_gear_table_is_keyed_and_deterministic() {
        let t1 = derive_gear_table(&[0x11; 32]);
        let t2 = derive_gear_table(&[0x11; 32]);
        let t3 = derive_gear_table(&[0x12; 32]);
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
        // Unkeyed table differs from any per-repo table.
        assert_ne!(t1, derive_gear_table(UNKEYED_GEAR_KEY));
    }
}
