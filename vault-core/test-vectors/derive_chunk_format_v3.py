"""Independent derivation of chunk-format-v3.json (2026-10).

Derives every published value from the inputs with no GitCellar code: HKDF-SHA256
from the standard library's hmac/hashlib (RFC 5869), HChaCha20 written out from
draft-irtf-cfrg-xchacha-03 section 2.2 (checked against its known-answer test), and
ChaCha20-Poly1305 from the `cryptography` package. The Rust test
`xchacha_published_test_vector_reproduces` (vault-core/src/encryption.rs)
reproduces the same bytes with GitCellar's engine, so two implementations agree.

    python derive_chunk_format_v3.py           # check the JSON beside this file
    python derive_chunk_format_v3.py --write   # (re)write it from the inputs below
"""

import hashlib
import hmac
import json
import os
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

HERE = os.path.dirname(os.path.abspath(__file__))
PATH = os.path.join(HERE, "chunk-format-v3.json")

# Inputs. Everything else in the JSON is derived from these.
FORMAT_VERSION = 3
CONTENT_KEY_INFO = "gitcellar/chunk-content/v1"
K_REPO_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
NONCE_HEX = "404142434445464748494a4b4c4d4e4f5051525354555657"
PLAINTEXT = "GitCellar chunk-format v3 published test vector"
REPO_UID = "5f0c9e7a2b1d4c3e8f6a0b9c7d2e1f30"
CHUNK_NAME = "9f2c4e8a1b3d5f70e6c2a4881d3b5f7092e4c6a8b0d2f4e6182a3c4d5e6f7081"
KEY_VERSION = 2
STREAM_OFFSET = 0


def hkdf_sha256(ikm, info, length=32):
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()  # absent salt = HashLen zeros
    t, okm, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def rotl(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = rotl(s[b] ^ s[c], 7)


def hchacha20(key, nonce16):
    s = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    s += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        quarter_round(s, 0, 4, 8, 12); quarter_round(s, 1, 5, 9, 13)
        quarter_round(s, 2, 6, 10, 14); quarter_round(s, 3, 7, 11, 15)
        quarter_round(s, 0, 5, 10, 15); quarter_round(s, 1, 6, 11, 12)
        quarter_round(s, 2, 7, 8, 13); quarter_round(s, 3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))


def xchacha20poly1305_seal(key, nonce24, plaintext, aad):
    subkey = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(subkey).encrypt(b"\x00" * 4 + nonce24[16:], plaintext, aad)


def derive():
    # HChaCha20 known-answer test, draft-irtf-cfrg-xchacha-03 section 2.2.1.
    kat = hchacha20(
        bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        bytes.fromhex("000000090000004a0000000031415927"),
    )
    assert kat.hex() == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc", "HChaCha20 KAT"

    plaintext = PLAINTEXT.encode()
    content_key = hkdf_sha256(bytes.fromhex(K_REPO_HEX), CONTENT_KEY_INFO.encode())
    cipher_aad = (
        bytes([FORMAT_VERSION])
        + REPO_UID.encode() + b"\x00"
        + CHUNK_NAME.encode() + b"\x00"
        + struct.pack("<I", KEY_VERSION)
        + struct.pack("<Q", STREAM_OFFSET)
        + struct.pack("<Q", len(plaintext))
    )
    nonce = bytes.fromhex(NONCE_HEX)
    chunk = bytes([FORMAT_VERSION]) + nonce + xchacha20poly1305_seal(content_key, nonce, plaintext, cipher_aad)
    assert len(chunk) == len(plaintext) + 41
    return {
        "_doc": (
            "Published deterministic test vector for GitCellar chunk-format v3 (XChaCha20-Poly1305, "
            "2026-10). A third party reproduces `chunk_hex` bit-for-bit from "
            "(content_key_hex, nonce_hex, plaintext_utf8, aad) with any XChaCha20-Poly1305 implementation, "
            "and reproduces content_key_hex from (k_repo_hex, content_key_info) with any HKDF-SHA256. The "
            "AEAD associated data is `aad.cipher_aad_hex` = format_version_byte(1) || repo_uid || 0x00 || "
            "chunk_name || 0x00 || key_version(u32 LE) || stream_offset(u64 LE) || size(u64 LE). repo_uid is "
            "the repository's immutable id (never its owner/name) and key_version is the repository key "
            "version that sealed the chunk; neither string field may contain 0x00. The AAD is NOT stored in "
            "the chunk; it only participates in the Poly1305 tag. Derived by derive_chunk_format_v3.py beside "
            "this file (independent of GitCellar code) and reproduced by vault-core's "
            "xchacha_published_test_vector_reproduces; never hand-edited."
        ),
        "format_version": FORMAT_VERSION,
        "cipher": "XChaCha20-Poly1305",
        "kdf": "HKDF-SHA256",
        "content_key_info": CONTENT_KEY_INFO,
        "chunk_layout": "[version_byte(1)] [XNonce(24)] [ciphertext(n)] [Poly1305 tag(16)]",
        "aad_layout": (
            "version_byte(1) || repo_uid || 0x00 || chunk_name || 0x00 || key_version(u32 LE) || "
            "stream_offset(u64 LE) || size(u64 LE)  (associated data only; not stored)"
        ),
        "k_repo_hex": K_REPO_HEX,
        "content_key_hex": content_key.hex(),
        "nonce_hex": NONCE_HEX,
        "plaintext_utf8": PLAINTEXT,
        "aad": {
            "repo_uid": REPO_UID,
            "chunk_name": CHUNK_NAME,
            "key_version": KEY_VERSION,
            "stream_offset": STREAM_OFFSET,
            "size": len(plaintext),
            "cipher_aad_hex": cipher_aad.hex(),
        },
        "chunk_hex": chunk.hex(),
    }


def main():
    derived = derive()
    if "--write" in sys.argv[1:]:
        with open(PATH, "w", encoding="utf-8", newline="\n") as f:
            json.dump(derived, f, indent=2)
            f.write("\n")
        print("wrote", PATH)
        return 0
    with open(PATH, encoding="utf-8") as f:
        published = json.load(f)
    if published != derived:
        for key in sorted(set(published) | set(derived)):
            if published.get(key) != derived.get(key):
                print("MISMATCH", key, published.get(key), "!=", derived.get(key))
        return 1
    print("chunk-format-v3.json re-derived independently: every value matches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
