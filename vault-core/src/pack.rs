//! Pack-into-blobs size-hiding for stored chunks (E1-PhaseB, AC-E1.4).
//!
//! ## Why packing exists
//!
//! GitCellar's pre-E1-PhaseB layout stored **one encrypted chunk per storage
//! object** (`repos/{repo}/chunks/{hmac}.gpg`). The storage backend — the
//! adversary in the zero-access model — sees every object's size, so the
//! per-chunk size sequence becomes a content/structure fingerprint that survives
//! encryption (E1 research §2/§4; eprint 2025/532 & 2025/558). Keyed naming
//! (AC-E1.1) and keyed CDC boundaries (AC-E1.2) — both already shipped in E1
//! Phase A — close the name-confirmation and boundary-reproduction oracles, but
//! **not** the size channel.
//!
//! This module **narrows** the size channel with the **restic 0.18.0 pack
//! model**: many encrypted chunks are concatenated into a larger **pack** blob
//! and assigned to packs at random, so a stored object's size no longer maps to
//! one chunk (AC-E1.4). It is the cheapest, highest-leverage size mitigation —
//! near zero storage overhead, unlike power-of-two/constant-size padding
//! (rejected for a storage-capped product; the optional
//! tight-multiplicative-ladder pack-size quantization is a documented higher-tier
//! add-on, not built here).
//!
//! ## What it does NOT close (be precise about this)
//!
//! Packing hides the **per-chunk** size sequence.
//! It does not close the size channel, and this module must not be described as
//! if it does — three residuals remain open by construction, and they are cheap
//! for the provider to read:
//!
//! 1. **Total ciphertext bytes leak exactly.** Packing adds *zero* padding — that
//!    is the near-zero-overhead property above, and `packing_adds_no_storage_overhead`
//!    pins it as an equality. So the sum of a push's pack sizes is exactly
//!    `sum(plaintext) + 41·n_chunks` (the per-chunk AEAD overhead,
//!    `encryption.rs`), from which total plaintext size follows closely.
//! 2. **The tail pack is a remainder, not "~target-sized".** [`pack_chunks`]
//!    seals the open pack only when the next chunk would overflow the target and
//!    flushes whatever is left at the end, so every batch ends with one
//!    non-uniform pack of size `total_batch_bytes mod ~target` — a finer read on
//!    the push size than any claim of uniformity would suggest.
//! 3. **A repo smaller than one target is a single pack**, whose size simply *is*
//!    that repo's ciphertext size. For the large population of small repos,
//!    packing hides the per-chunk split and nothing else; against a candidate set
//!    of known public repositories that is a usable confirmation channel.
//!
//! Closing (1) and (3) needs padding or size quantization — the documented
//! higher-tier add-on, deliberately not built here. The access-pattern residual
//! is likewise open and documented (AC-E1.7). Recorded because this crate is
//! published for third-party audit: an accurate residual list is worth more than
//! a confident summary, and overclaiming in crypto prose is a failure mode this
//! project has already shipped once (CG-1).
//!
//! ## What a pack is (and is not)
//!
//! A pack is an **opaque** concatenation of already-encrypted chunk blobs:
//!
//! ```text
//! pack object  =  chunk_blob_0 ‖ chunk_blob_1 ‖ … ‖ chunk_blob_{k-1}
//! each chunk_blob_i = [ver(1)][nonce(24)][ciphertext(n)][tag(16)]   (its own AEAD unit)
//! object key   =  repos/{repo_id}/packs/{pack_id}
//! ```
//!
//! The pack carries **no plaintext framing** the provider could read — no chunk
//! count, no offset table, no names. The map a reader needs
//! (`chunk_name → {pack_id, offset, length}`) lives in the repo's **encrypted**
//! manifest, never in the pack and never in plaintext at rest. The provider sees
//! opaque blobs, most of them near the target size — but see "What it does NOT
//! close" above: the sizes are neither uniform nor padded, and their sum is
//! exact.
//!
//! Each chunk blob is self-contained and already version-tagged (F6 byte inside
//! the blob), so packing is a pure **outer** layer: it never inspects, reframes,
//! or perturbs chunk bytes, and F6 per-chunk version dispatch is unchanged. The
//! published F2/E3 chunk test vector therefore still reproduces bit-for-bit.
//!
//! ## Reading back
//!
//! A reader fetches the whole pack (`StorageBackend::download`), then slices
//! `pack[offset .. offset+length]` with [`slice_chunk`] to recover the exact
//! encrypted-chunk blob, which decrypts normally. Whole-pack fetch (rather than
//! an HTTP range request) is deliberate: a range request would re-leak the
//! intra-pack offset/size to the backend, partly undoing AC-E1.4, and the
//! `StorageBackend` trait exposes no range API. One pack holds many of a read's
//! needed chunks, so a single fetch + client cache serves many slices — this is
//! the "batched fetch + client cache" access-pattern mitigation of DEC-CH-10 /
//! RT-1 (the access-pattern residual stays open and documented, AC-E1.7).
//!
//! ## Dedup
//!
//! Dedup is by `chunk_name` (the keyed HMAC). [`pack_chunks`] dedups **within a
//! batch** (a name packed once per call); cross-push dedup is the caller's job —
//! it skips chunks whose name is already located in the repo's existing manifest
//! before handing the *new* chunks here. Same plaintext + same repo key → same
//! name → dedup hit, even across packs and pushes.

use crate::error::{VaultError, VaultResult};
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Default target pack size (~4 MiB).
///
/// With E1's 16–256 KiB chunks this is ~16–256 chunks per pack — enough that an
/// individual chunk's size is hidden among many, while a pack stays small enough
/// for one `download` to be a reasonable read unit. A chunk is never split across
/// packs (it is an AEAD unit), so a chunk larger than the target gets its own
/// pack; the target is therefore a soft ceiling, not a hard frame size.
pub const DEFAULT_TARGET_PACK_SIZE: usize = 4 * 1024 * 1024;

/// Length, in bytes, of a `pack_id` once hex-encoded (32 random bytes → 64 hex).
pub const PACK_ID_HEX_LEN: usize = 64;

/// Where a single encrypted chunk lives inside a pack.
///
/// This is the per-chunk entry of the encrypted manifest. `length` is the size of
/// the **encrypted** chunk blob (`[ver][nonce][ct][tag]`), not the plaintext.
/// `u32` is ample: an E1 chunk maxes at 256 KiB + 41 B overhead, far below
/// `u32::MAX`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackLocation {
    /// The `pack_id` (random 256-bit hex) — the object key is
    /// `repos/{repo_id}/packs/{pack_id}`.
    pub pack_id: String,
    /// Byte offset of the chunk blob within the pack.
    pub offset: u64,
    /// Length of the chunk blob in bytes (encrypted size).
    pub length: u32,
}

/// A finished pack ready to upload under `repos/{repo_id}/packs/{pack_id}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuiltPack {
    /// Random 256-bit hex id; the storage object key.
    pub pack_id: String,
    /// The concatenated encrypted-chunk bytes.
    pub bytes: Vec<u8>,
}

impl BuiltPack {
    /// The on-storage object size (== `bytes.len()`).
    pub fn size(&self) -> usize {
        self.bytes.len()
    }
}

/// The result of packing a batch of encrypted chunks.
///
/// `packs` are the blobs to upload; `index` maps each (deduplicated) chunk name to
/// its [`PackLocation`] for the encrypted manifest. Every name in `index` resolves
/// into exactly one pack in `packs`.
#[derive(Clone, Debug, Default)]
pub struct PackSet {
    /// Finished packs to upload (one storage object each).
    pub packs: Vec<BuiltPack>,
    /// `chunk_name → PackLocation`, one entry per unique chunk in the batch.
    pub index: Vec<(String, PackLocation)>,
}

/// Generate a random 256-bit pack id as lowercase hex.
///
/// Not content-derived: a content hash would re-leak the very size/content
/// correlation packing exists to hide, and would also reintroduce a
/// confirmation oracle on pack contents. A random id leaks nothing.
pub fn random_pack_id<R: Rng + ?Sized>(rng: &mut R) -> String {
    let mut raw = [0u8; 32];
    rng.fill_bytes(&mut raw);
    let mut s = String::with_capacity(PACK_ID_HEX_LEN);
    for b in raw {
        // Two lowercase hex nibbles per byte.
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// Pack a batch of **new** encrypted chunks into blobs with random assignment.
///
/// `chunks` is `(chunk_name, encrypted_blob)` for chunks the caller has already
/// determined are new (not already stored — cross-push dedup is the caller's job).
/// The batch is shuffled with `rng` before sequential fill, so a chunk's
/// co-location with its stream neighbours is not a stable fingerprint (random
/// assignment, AC-E1.4). Within the batch, a repeated `chunk_name` is stored once
/// (intra-batch dedup), keeping `index` names unique.
///
/// Returns a [`PackSet`]: the packs to upload and the `chunk_name → PackLocation`
/// index for the encrypted manifest. A chunk is never split across packs; a chunk
/// larger than `target_pack_size` occupies its own pack.
///
/// `target_pack_size` of 0 is treated as 1 (each chunk its own pack) rather than
/// an error, so callers cannot accidentally produce empty packs.
pub fn pack_chunks<R: Rng + ?Sized>(
    chunks: Vec<(String, Vec<u8>)>,
    target_pack_size: usize,
    rng: &mut R,
) -> PackSet {
    let target = target_pack_size.max(1);

    // Random assignment: shuffle so adjacent stream chunks do not deterministically
    // co-locate in the same pack.
    let mut chunks = chunks;
    chunks.shuffle(rng);

    let mut packs: Vec<BuiltPack> = Vec::new();
    let mut index: Vec<(String, PackLocation)> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // Currently-open pack being filled.
    let mut cur_id: Option<String> = None;
    let mut cur_bytes: Vec<u8> = Vec::new();

    for (name, blob) in chunks {
        // Intra-batch dedup: a name is packed at most once per call.
        if !seen.insert(name.clone()) {
            continue;
        }

        // Seal the open pack before this chunk if appending it would overflow the
        // target AND the pack already holds something (never seal an empty pack —
        // an oversized chunk still needs a home).
        if !cur_bytes.is_empty() && cur_bytes.len() + blob.len() > target {
            packs.push(BuiltPack {
                pack_id: cur_id.take().expect("open pack has an id"),
                bytes: std::mem::take(&mut cur_bytes),
            });
        }

        // Open a fresh pack if none is currently open.
        let pack_id = cur_id.get_or_insert_with(|| random_pack_id(rng)).clone();

        let offset = cur_bytes.len() as u64;
        let length = blob.len() as u32;
        cur_bytes.extend_from_slice(&blob);

        index.push((name, PackLocation { pack_id, offset, length }));
    }

    // Flush the final open pack.
    if let Some(pack_id) = cur_id.take() {
        if !cur_bytes.is_empty() {
            packs.push(BuiltPack {
                pack_id,
                bytes: cur_bytes,
            });
        }
    }

    PackSet { packs, index }
}

/// Slice the encrypted-chunk blob out of a downloaded pack.
///
/// `pack_bytes` is the full pack object; `loc` is the chunk's manifest entry. The
/// returned slice is the exact `[ver][nonce][ct][tag]` blob to hand to the chunk
/// decryptor. Bounds are checked: a `loc` that runs past the end of the pack (a
/// corrupt or wrong-pack manifest) is an explicit error, never a panic or a
/// silent short read.
pub fn slice_chunk<'a>(pack_bytes: &'a [u8], loc: &PackLocation) -> VaultResult<&'a [u8]> {
    let start = usize::try_from(loc.offset)
        .map_err(|_| VaultError::Decryption(format!("pack offset {} overflows usize", loc.offset)))?;
    let end = start.checked_add(loc.length as usize).ok_or_else(|| {
        VaultError::Decryption(format!(
            "pack slice end overflows (offset {} + length {})",
            loc.offset, loc.length
        ))
    })?;
    if end > pack_bytes.len() {
        return Err(VaultError::Decryption(format!(
            "pack slice [{start}..{end}] out of bounds for pack of {} bytes \
             (pack_id {}): corrupt or mismatched manifest",
            pack_bytes.len(),
            loc.pack_id
        )));
    }
    Ok(&pack_bytes[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Build `n` distinct "encrypted" blobs of varying sizes. Bytes need not be
    /// real ciphertext for pack-layer tests — packing is byte-opaque.
    fn fake_chunks(n: usize, base_len: usize) -> Vec<(String, Vec<u8>)> {
        (0..n)
            .map(|i| {
                let len = base_len + (i % 7) * 13; // varied sizes
                let name = format!("{:064x}", i); // 64-hex, like an HMAC name
                let blob = vec![(i % 251) as u8; len];
                (name, blob)
            })
            .collect()
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xE1B_5126)
    }

    #[test]
    fn pack_id_is_64_lowercase_hex() {
        let id = random_pack_id(&mut rng());
        assert_eq!(id.len(), PACK_ID_HEX_LEN);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn pack_ids_are_random_not_content_derived() {
        // Same input, different RNG state → different pack ids (ids carry no
        // content correlation).
        let chunks = fake_chunks(20, 1000);
        let a = pack_chunks(chunks.clone(), 4096, &mut StdRng::seed_from_u64(1));
        let b = pack_chunks(chunks, 4096, &mut StdRng::seed_from_u64(2));
        let ids_a: HashSet<_> = a.packs.iter().map(|p| p.pack_id.clone()).collect();
        let ids_b: HashSet<_> = b.packs.iter().map(|p| p.pack_id.clone()).collect();
        assert!(ids_a.is_disjoint(&ids_b), "pack ids must not repeat across runs");
    }

    /// AC-E1.4 core: many small chunks collapse into far fewer packs, and no
    /// pack's size equals any single input chunk's size.
    #[test]
    fn many_chunks_pack_into_fewer_blobs_hiding_per_chunk_size() {
        let chunks = fake_chunks(100, 1000); // ~100 KiB total, ~1 KB each
        let single_chunk_sizes: HashSet<usize> = chunks.iter().map(|(_, b)| b.len()).collect();

        let ps = pack_chunks(chunks, 16 * 1024, &mut rng()); // 16 KiB target

        assert!(
            ps.packs.len() < 100,
            "100 small chunks must aggregate into fewer packs, got {}",
            ps.packs.len()
        );
        assert!(ps.packs.len() > 1, "should produce several packs at 16 KiB target");
        for p in &ps.packs {
            assert!(
                !single_chunk_sizes.contains(&p.size()),
                "a stored pack size ({}) must not equal a single chunk's size",
                p.size()
            );
        }
    }

    /// Round-trip: every chunk sliced back out of its pack equals the original
    /// encrypted blob. This is the property the read path relies on.
    #[test]
    fn pack_then_slice_round_trips_every_chunk() {
        let chunks = fake_chunks(64, 500);
        let original: std::collections::HashMap<String, Vec<u8>> =
            chunks.iter().cloned().collect();

        let ps = pack_chunks(chunks, 4096, &mut rng());
        let by_id: std::collections::HashMap<&str, &BuiltPack> =
            ps.packs.iter().map(|p| (p.pack_id.as_str(), p)).collect();

        // Every unique chunk has exactly one index entry.
        assert_eq!(ps.index.len(), original.len());

        for (name, loc) in &ps.index {
            let pack = by_id.get(loc.pack_id.as_str()).expect("index points at a real pack");
            let sliced = slice_chunk(&pack.bytes, loc).unwrap();
            assert_eq!(sliced, original[name].as_slice(), "chunk {name} did not round-trip");
        }
    }

    /// A chunk larger than the target gets its own pack and still round-trips
    /// (chunks are never split across packs).
    #[test]
    fn oversized_chunk_gets_its_own_pack() {
        let big = vec![7u8; 10_000];
        let chunks = vec![
            ("a".repeat(64), big.clone()),
            ("b".repeat(64), vec![1u8; 100]),
        ];
        let ps = pack_chunks(chunks, 4096, &mut rng());

        // The big chunk's pack holds exactly it.
        let big_loc = &ps.index.iter().find(|(n, _)| *n == "a".repeat(64)).unwrap().1;
        let by_id: std::collections::HashMap<&str, &BuiltPack> =
            ps.packs.iter().map(|p| (p.pack_id.as_str(), p)).collect();
        let big_pack = by_id[big_loc.pack_id.as_str()];
        assert_eq!(big_pack.size(), big.len(), "oversized chunk occupies its own pack");
        assert_eq!(slice_chunk(&big_pack.bytes, big_loc).unwrap(), big.as_slice());
    }

    /// Intra-batch dedup: a repeated chunk_name is packed once; the index has the
    /// name once.
    #[test]
    fn intra_batch_dedup_stores_a_name_once() {
        let name = "c".repeat(64);
        let chunks = vec![
            (name.clone(), vec![1u8; 50]),
            (name.clone(), vec![1u8; 50]),
            ("d".repeat(64), vec![2u8; 50]),
        ];
        let ps = pack_chunks(chunks, 4096, &mut rng());
        let count = ps.index.iter().filter(|(n, _)| *n == name).count();
        assert_eq!(count, 1, "duplicate name must be packed once");
        assert_eq!(ps.index.len(), 2);
    }

    #[test]
    fn empty_input_produces_no_packs() {
        let ps = pack_chunks(vec![], DEFAULT_TARGET_PACK_SIZE, &mut rng());
        assert!(ps.packs.is_empty());
        assert!(ps.index.is_empty());
    }

    #[test]
    fn slice_out_of_bounds_is_explicit_error_not_panic() {
        let pack = vec![0u8; 100];
        let bad = PackLocation { pack_id: "x".repeat(64), offset: 90, length: 50 };
        assert!(slice_chunk(&pack, &bad).is_err());
        let ok = PackLocation { pack_id: "x".repeat(64), offset: 90, length: 10 };
        assert!(slice_chunk(&pack, &ok).is_ok());
    }

    /// Total packed bytes equals the sum of unique chunk sizes — packing adds no
    /// per-chunk storage overhead (near-zero cost, the AC-E1.4 rationale).
    #[test]
    fn packing_adds_no_storage_overhead() {
        let chunks = fake_chunks(50, 800);
        let total_in: usize = chunks.iter().map(|(_, b)| b.len()).sum();
        let ps = pack_chunks(chunks, 4096, &mut rng());
        let total_out: usize = ps.packs.iter().map(|p| p.size()).sum();
        assert_eq!(total_in, total_out, "packs must hold exactly the chunk bytes, no padding");
    }

    /// All offsets/lengths within a pack are consistent: entries for a given pack
    /// tile it without gaps or overlaps when sorted by offset.
    #[test]
    fn pack_entries_tile_their_pack_contiguously() {
        let chunks = fake_chunks(40, 600);
        let ps = pack_chunks(chunks, 4096, &mut rng());

        for pack in &ps.packs {
            let mut locs: Vec<&PackLocation> = ps
                .index
                .iter()
                .map(|(_, l)| l)
                .filter(|l| l.pack_id == pack.pack_id)
                .collect();
            locs.sort_by_key(|l| l.offset);
            let mut expected = 0u64;
            for l in locs {
                assert_eq!(l.offset, expected, "entries must tile the pack with no gap");
                expected += l.length as u64;
            }
            assert_eq!(expected as usize, pack.size(), "entries must cover the whole pack");
        }
    }
}
