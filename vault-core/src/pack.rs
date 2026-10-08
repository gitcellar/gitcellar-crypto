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
//! This module **narrows** the size channel in two layers:
//!
//! 1. **Packing**, the **restic 0.18.0 pack model**: many encrypted chunks are
//!    concatenated into a larger **pack** blob and assigned to packs at random,
//!    so a stored object's size no longer maps to one chunk (AC-E1.4).
//! 2. **Padding**: every pack is padded with
//!    random filler to the smallest step of a geometric ladder at or above its
//!    content: a 256 KiB floor ([`PAD_LADDER_FLOOR`]), then x1.25 per step
//!    (256 KiB, 320 KiB, 400 KiB, 500 KiB, ...; [`PadLadder::DEFAULT`]).
//!    Packing alone did not help an incremental push: a push packs only the
//!    chunks new to it, so a one-chunk push stored one pack of exactly
//!    `plaintext + 41` bytes, the exact chunk length the eprint 2025/558
//!    attacks on secret-table Gear chunkers need. With the floor, every push
//!    whose new chunks total under 256 KiB stores the same object size.
//!
//! ## What padding costs, and how the storage quota counts it
//!
//! Padding is storage the user pays for. The floor costs at most 256 KiB per
//! pack, so at most 256 KiB for a push of under ~4 MiB of new chunks. Above the
//! floor the ladder rounds a pack up by less than 25%
//! (`padding_overhead_is_bounded_by_the_ladder` pins the bound). A pack
//! holding more than 3.64 MiB, up to the 4 MiB target, lands on the 4.55 MiB
//! step (4,768,370 bytes): about 14% over a pack filled exactly to the target.
//!
//! GitCellar's storage quota counts **stored object bytes**. A pack is stored
//! padded, so **padding counts against the quota in full**, exactly as the
//! per-chunk AEAD overhead does.
//!
//! ## What it does NOT close (be precise about this)
//!
//! Packing hides the **per-chunk** size sequence and padding coarsens what is
//! left. Together they do not close the size channel, and this module must
//! not be described as if they do. These residuals remain open by
//! construction:
//!
//! 1. **Total ciphertext bytes leak to ladder precision.** A pack's step
//!    bounds its content to within 25% (below the floor, to "under 256 KiB"),
//!    so a push's size, and a repository's growth, is readable in steps.
//! 2. **The tail pack is a remainder.** [`pack_chunks`] seals the open pack
//!    only when the next chunk would overflow the target and flushes whatever
//!    is left at the end, so every batch ends with one pack that is not
//!    target-sized; padding rounds it to a step, and the step still tracks the
//!    remainder.
//! 3. **A repo smaller than one target is a single pack**, whose step is that
//!    repo's ciphertext size to ladder precision. Against a candidate set of
//!    known public repositories that is a coarser, but still usable,
//!    confirmation channel.
//! 4. **Pack count and timing.** How many packs a push uploads, and when, is
//!    visible and is not padded.
//!
//! The shipped chunker is a secret-table Gear CDC, the class eprint 2025/558
//! analyses. Padding addresses the length observation that attack needs; the
//! provable successor is the reserved v5 AES-per-byte keyed chunker. The
//! access-pattern residual is likewise open and documented (AC-E1.7).
//! Recorded because this crate is published for third-party audit: an
//! accurate residual list is worth more than a confident summary, and
//! overclaiming in crypto prose is a failure mode this project has already
//! shipped once.
//!
//! ## What a pack is (and is not)
//!
//! A pack is an **opaque** concatenation of already-encrypted chunk blobs:
//!
//! ```text
//! pack object  =  chunk_blob_0 ‖ chunk_blob_1 ‖ … ‖ chunk_blob_{k-1} ‖ filler
//! each chunk_blob_i = [ver(1)][nonce(24)][ciphertext(n)][tag(16)]   (its own AEAD unit)
//! object key   =  repos/{repo_id}/packs/{pack_id}
//! ```
//!
//! The pack carries **no plaintext framing** the provider could read — no chunk
//! count, no offset table, no names. The map a reader needs
//! (`chunk_name → {pack_id, offset, length}`) lives in the repo's **encrypted**
//! manifest, never in the pack and never in plaintext at rest. The provider sees
//! opaque blobs whose sizes sit on ladder steps, but see "What it does NOT
//! close" above.
//!
//! `filler` is random bytes that bring the object to its ladder step. Nothing
//! marks where it starts: a reader addresses chunks by `{offset, length}` from
//! the encrypted manifest and never reads past the last blob, so the filler is
//! invisible to it and the read format is unchanged.
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

/// The smallest stored pack size (256 KiB): every pack whose content is at or
/// below it is padded to exactly this length, so a one-chunk incremental push
/// does not reveal its chunk's length.
pub const PAD_LADDER_FLOOR: usize = 256 * 1024;

/// A geometric ladder of allowed pack sizes: `floor`, then each step
/// `growth_num / growth_den` times the last (integer division, so a step is
/// never more than that ratio above the one before).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PadLadder {
    /// The first step; content at or below it is padded to it.
    pub floor: usize,
    /// Numerator of the per-step growth ratio.
    pub growth_num: usize,
    /// Denominator of the per-step growth ratio.
    pub growth_den: usize,
}

impl PadLadder {
    /// The production ladder: 256 KiB, then x1.25 per step.
    pub const DEFAULT: PadLadder =
        PadLadder { floor: PAD_LADDER_FLOOR, growth_num: 5, growth_den: 4 };

    /// The smallest ladder step at or above `len`.
    ///
    /// Every step after the floor is at most `growth_num / growth_den` times
    /// the one before, and the one before is below `len`, so for `len` above
    /// the floor the result is less than `len * growth_num / growth_den`.
    pub fn step_for(&self, len: usize) -> usize {
        let mut step = self.floor.max(1);
        while step < len {
            let next = (step as u128 * self.growth_num as u128 / self.growth_den.max(1) as u128)
                .min(usize::MAX as u128) as usize;
            // A ratio at or below 1 would never grow; move by one byte instead
            // so the loop always ends.
            step = if next > step { next } else { step + 1 };
        }
        step
    }
}

/// Pad a finished pack with random filler up to its ladder step.
///
/// The filler sits after the last chunk blob. Readers address chunks by
/// [`PackLocation`] and never read past the last blob, so filler changes no
/// read. It is random rather than zero so that it is indistinguishable from
/// the ciphertext before it.
pub fn pad_pack<R: Rng + ?Sized>(bytes: &mut Vec<u8>, ladder: &PadLadder, rng: &mut R) {
    let content = bytes.len();
    let step = ladder.step_for(content);
    if step > content {
        bytes.resize(step, 0);
        rng.fill_bytes(&mut bytes[content..]);
    }
}

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
/// larger than `target_pack_size` occupies its own pack. Every pack is padded
/// with random filler to its [`PadLadder::DEFAULT`] step ([`pad_pack`]), so a
/// pack's `bytes` are its chunk blobs followed by filler.
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
            let mut bytes = std::mem::take(&mut cur_bytes);
            pad_pack(&mut bytes, &PadLadder::DEFAULT, rng);
            packs.push(BuiltPack {
                pack_id: cur_id.take().expect("open pack has an id"),
                bytes,
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
            pad_pack(&mut cur_bytes, &PadLadder::DEFAULT, rng);
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

        // The big chunk's pack holds exactly it (plus filler to its step).
        let big_loc = &ps.index.iter().find(|(n, _)| *n == "a".repeat(64)).unwrap().1;
        let by_id: std::collections::HashMap<&str, &BuiltPack> =
            ps.packs.iter().map(|p| (p.pack_id.as_str(), p)).collect();
        let big_pack = by_id[big_loc.pack_id.as_str()];
        let entries_in_big_pack =
            ps.index.iter().filter(|(_, l)| l.pack_id == big_loc.pack_id).count();
        assert_eq!(entries_in_big_pack, 1, "oversized chunk occupies its own pack");
        assert_eq!(big_loc.offset, 0);
        assert_eq!(big_pack.size(), PadLadder::DEFAULT.step_for(big.len()));
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

    /// Padding is storage the user pays for, so its cost is pinned: a pack at
    /// or under the floor stores exactly the floor, and a pack above it stores
    /// less than 1.25x its content. (Replaces `packing_adds_no_storage_overhead`,
    /// which pinned zero overhead and is false by design once packs are padded.)
    #[test]
    fn padding_overhead_is_bounded_by_the_ladder() {
        let ladder = PadLadder::DEFAULT;

        // The ladder itself, across the range a pack can take: below the
        // floor, around it, and well past the 4 MiB target (oversized chunks).
        let mut probes: Vec<usize> = vec![0, 1, 41, PAD_LADDER_FLOOR - 1, PAD_LADDER_FLOOR];
        let mut len = PAD_LADDER_FLOOR + 1;
        while len < 64 * 1024 * 1024 {
            probes.extend([len - 1, len, len + 1]);
            len = len * 9 / 8 + 7;
        }
        for len in probes {
            let step = ladder.step_for(len);
            assert!(step >= len, "step {step} must hold content {len}");
            if len <= PAD_LADDER_FLOOR {
                assert_eq!(step, PAD_LADDER_FLOOR, "content {len} under the floor");
            } else {
                assert!(step * 4 < len * 5, "step {step} is 1.25x or more over content {len}");
            }
        }

        // And the packs `pack_chunks` actually builds, small and large.
        for (n, base, target) in [(50, 800, 4096), (300, 60_000, DEFAULT_TARGET_PACK_SIZE)] {
            let chunks = fake_chunks(n, base);
            let ps = pack_chunks(chunks, target, &mut rng());
            for pack in &ps.packs {
                let content: usize = ps
                    .index
                    .iter()
                    .filter(|(_, l)| l.pack_id == pack.pack_id)
                    .map(|(_, l)| l.length as usize)
                    .sum();
                assert_eq!(pack.size(), ladder.step_for(content), "pack sits on its ladder step");
            }
        }
    }

    /// Filler changes no read: every `PackLocation` still slices exactly its
    /// blob out of a padded pack, and the padding is really there.
    #[test]
    fn pack_slices_still_open_after_padding() {
        let mut chunks = fake_chunks(120, 30_000);
        chunks.push(("e".repeat(64), vec![9u8; 5_000_000])); // oversized, own pack
        let original: std::collections::HashMap<String, Vec<u8>> =
            chunks.iter().cloned().collect();

        let ps = pack_chunks(chunks, DEFAULT_TARGET_PACK_SIZE, &mut rng());
        let by_id: std::collections::HashMap<&str, &BuiltPack> =
            ps.packs.iter().map(|p| (p.pack_id.as_str(), p)).collect();
        assert_eq!(ps.index.len(), original.len());

        let mut padded_packs = 0;
        for pack in &ps.packs {
            let content_end = ps
                .index
                .iter()
                .filter(|(_, l)| l.pack_id == pack.pack_id)
                .map(|(_, l)| l.offset as usize + l.length as usize)
                .max()
                .expect("every pack holds a chunk");
            if pack.size() > content_end {
                padded_packs += 1;
            }
        }
        assert!(padded_packs > 0, "the packs must actually carry filler");

        for (name, loc) in &ps.index {
            let pack = by_id[loc.pack_id.as_str()];
            let sliced = slice_chunk(&pack.bytes, loc).unwrap();
            assert_eq!(sliced, original[name].as_slice(), "chunk {name} did not slice back exactly");
        }

        // A lone chunk under the floor is padded and still opens.
        let lone = vec![3u8; 777];
        let ps = pack_chunks(vec![("f".repeat(64), lone.clone())], DEFAULT_TARGET_PACK_SIZE, &mut rng());
        assert_eq!(ps.packs[0].size(), PAD_LADDER_FLOOR);
        assert_eq!(slice_chunk(&ps.packs[0].bytes, &ps.index[0].1).unwrap(), lone.as_slice());
    }

    /// An incremental push of one chunk must not reveal that
    /// chunk's exact length. Two one-chunk packs whose blobs differ by one byte,
    /// both under the ladder floor, store as objects of equal length.
    #[test]
    fn single_chunk_packs_of_different_lengths_are_indistinguishable() {
        let a = pack_chunks(vec![("a".repeat(64), vec![1u8; 5_000])], DEFAULT_TARGET_PACK_SIZE, &mut rng());
        let b = pack_chunks(vec![("b".repeat(64), vec![2u8; 5_001])], DEFAULT_TARGET_PACK_SIZE, &mut rng());
        assert_eq!(a.packs.len(), 1);
        assert_eq!(b.packs.len(), 1);
        assert_eq!(
            a.packs[0].size(),
            b.packs[0].size(),
            "one-chunk packs under the floor must not reveal the chunk length"
        );
    }

    /// All offsets/lengths within a pack are consistent: entries for a given pack
    /// tile it from offset 0 without gaps or overlaps when sorted by offset, and
    /// only filler follows the last one (the pack is its content's ladder step).
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
            assert_eq!(
                PadLadder::DEFAULT.step_for(expected as usize),
                pack.size(),
                "entries must cover the pack up to its filler"
            );
        }
    }
}
