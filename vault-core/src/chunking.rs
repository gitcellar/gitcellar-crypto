//! Content-Defined Chunking (CDC) for efficient deduplication
//!
//! This module provides variable-size chunking using a rolling hash algorithm
//! inspired by FastCDC. Content-defined chunking enables deduplication by
//! producing consistent chunk boundaries regardless of insertions/deletions.
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
use sha2::{Digest, Sha256};
use tracing::{debug, info};

/// Configuration for the chunking algorithm
///
/// The default configuration produces chunks averaging 1MB in size,
/// which provides a good balance between deduplication efficiency
/// and overhead.
#[derive(Debug, Clone)]
#[repr(C)]
pub struct ChunkConfig {
    /// Minimum chunk size in bytes (default: 512KB)
    ///
    /// Chunks will never be smaller than this, except for the last
    /// chunk in a file which may be any size.
    pub min_size: usize,

    /// Average/target chunk size in bytes (default: 1MB)
    ///
    /// The rolling hash algorithm aims to produce chunks of this
    /// average size.
    pub avg_size: usize,

    /// Maximum chunk size in bytes (default: 2MB)
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

}

/// Represents a single chunk of data
///
/// A chunk contains the actual data along with metadata for
/// storage and verification.
#[derive(Debug, Clone)]
pub struct Chunk {
    /// Content-based hash (SHA256 of data)
    ///
    /// This hash serves as both an identifier and integrity check.
    /// Identical content will always produce the same hash, enabling
    /// deduplication.
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
    /// Content-based hash (SHA256)
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
/// The engine uses a rolling hash to find chunk boundaries that are
/// determined by the content itself, not fixed positions. This means
/// that if you insert data at the beginning of a file, only the first
/// chunk changes - the rest remain identical.
pub struct ChunkEngine {
    config: ChunkConfig,
}

impl ChunkEngine {
    /// Create a new chunking engine with the given configuration
    pub fn new(config: ChunkConfig) -> Self {
        Self { config }
    }

    /// Create a new chunking engine with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ChunkConfig::default())
    }

    /// Get the configuration
    pub fn config(&self) -> &ChunkConfig {
        &self.config
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

            let hash = Self::compute_hash(chunk_data);

            chunks.push(Chunk {
                hash: hash.clone(),
                data: chunk_data.to_vec(),
                size: chunk_data.len(),
                offset: offset as u64,
            });

            debug!(
                "Created chunk: {} bytes at offset {}, hash: {}",
                chunk_data.len(),
                offset,
                &hash[..16]
            );
            offset += chunk_size;
        }

        info!("Created {} chunks from {} bytes", chunks.len(), data.len());
        Ok(chunks)
    }

    /// Find chunk boundary using rolling hash (FastCDC-inspired)
    ///
    /// Uses a simple polynomial rolling hash to find content-defined
    /// boundaries. When the hash meets a certain condition (modulo check),
    /// we declare a chunk boundary.
    fn find_chunk_boundary(&self, data: &[u8]) -> usize {
        if data.len() <= self.config.min_size {
            return data.len();
        }

        let max_scan = std::cmp::min(data.len(), self.config.max_size);

        // Simple rolling hash for boundary detection
        // Uses polynomial rolling hash with base 31
        let mut hash: u32 = 0;
        const WINDOW_SIZE: usize = 48; // Rolling hash window

        for i in self.config.min_size..max_scan {
            if i >= WINDOW_SIZE {
                // Polynomial rolling hash: h = h * 31 + byte
                hash = hash.wrapping_mul(31).wrapping_add(data[i] as u32);

                // Check if hash meets boundary condition
                // Using modulo of avg_size creates chunks averaging that size
                if (hash % (self.config.avg_size as u32)) == 0 {
                    return i;
                }
            }
        }

        // If no boundary found, return max size
        max_scan
    }

    /// Compute SHA256 hash of data
    ///
    /// Returns lowercase hexadecimal string.
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

    /// Verify chunk integrity by recomputing hash
    ///
    /// # Arguments
    /// * `chunk` - The chunk to verify
    ///
    /// # Returns
    /// true if the chunk's hash matches its data
    pub fn verify_chunk(&self, chunk: &Chunk) -> bool {
        let computed_hash = Self::compute_hash(&chunk.data);
        computed_hash == chunk.hash
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
    buffer: Vec<u8>,
    offset: u64,
    chunks: Vec<Chunk>,
}

impl StreamChunker {
    /// Create a new stream chunker with the given configuration
    pub fn new(config: ChunkConfig) -> Self {
        Self {
            config,
            buffer: Vec::new(),
            offset: 0,
            chunks: Vec::new(),
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
            let hash = ChunkEngine::compute_hash(&self.buffer);
            let size = self.buffer.len();
            self.chunks.push(Chunk {
                hash,
                data: std::mem::take(&mut self.buffer),
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
            let hash = ChunkEngine::compute_hash(&chunk_data);
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

    /// Find the next chunk boundary in the buffer using the same
    /// rolling hash algorithm as `ChunkEngine::find_chunk_boundary()`
    fn find_boundary(&self) -> usize {
        let data = &self.buffer;
        if data.len() <= self.config.min_size {
            return data.len();
        }

        let max_scan = std::cmp::min(data.len(), self.config.max_size);

        let mut hash: u32 = 0;
        const WINDOW_SIZE: usize = 48;

        for i in self.config.min_size..max_scan {
            if i >= WINDOW_SIZE {
                hash = hash.wrapping_mul(31).wrapping_add(data[i] as u32);

                if (hash % (self.config.avg_size as u32)) == 0 {
                    return i;
                }
            }
        }

        max_scan
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ChunkConfig::default();
        assert_eq!(config.min_size, 512 * 1024);
        assert_eq!(config.avg_size, 1024 * 1024);
        assert_eq!(config.max_size, 2 * 1024 * 1024);
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
}
