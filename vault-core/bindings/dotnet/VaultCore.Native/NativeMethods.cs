using System;
using System.Runtime.InteropServices;

namespace VaultCore.Native;

/// <summary>
/// P/Invoke declarations for vault-core native library.
/// </summary>
internal static partial class NativeMethods
{
    private const string LibraryName = "vault_core";

    // ========================================================================
    // Buffer management
    // ========================================================================

    [StructLayout(LayoutKind.Sequential)]
    internal struct VaultBuffer
    {
        public IntPtr Data;
        public nuint Length;
        public nuint Capacity;
    }

    [LibraryImport(LibraryName)]
    internal static partial void vault_buffer_free(IntPtr buffer);

    // ========================================================================
    // Error handling
    // ========================================================================

    [LibraryImport(LibraryName)]
    internal static partial IntPtr vault_last_error();

    [LibraryImport(LibraryName)]
    internal static partial void vault_error_free(IntPtr error);

    // ========================================================================
    // Version
    // ========================================================================

    [LibraryImport(LibraryName)]
    internal static partial IntPtr vault_version();

    // ========================================================================
    // AES Encryption
    // ========================================================================

    [LibraryImport(LibraryName)]
    internal static partial IntPtr vault_aes_generate_key();

    [LibraryImport(LibraryName)]
    internal static partial IntPtr vault_aes_generate_salt();

    [LibraryImport(LibraryName)]
    internal static unsafe partial IntPtr vault_aes_derive_key(
        byte* passphrase,
        nuint passphraseLen,
        byte* salt,
        nuint saltLen);

    [LibraryImport(LibraryName)]
    internal static unsafe partial IntPtr vault_aes_create(byte* key, nuint keyLen);

    [LibraryImport(LibraryName)]
    internal static partial void vault_aes_free(IntPtr engine);

    [LibraryImport(LibraryName)]
    internal static unsafe partial IntPtr vault_aes_encrypt(
        IntPtr engine,
        byte* plaintext,
        nuint plaintextLen);

    [LibraryImport(LibraryName)]
    internal static unsafe partial IntPtr vault_aes_decrypt(
        IntPtr engine,
        byte* ciphertext,
        nuint ciphertextLen);

    // ========================================================================
    // Chunking
    // ========================================================================

    [StructLayout(LayoutKind.Sequential)]
    internal struct VaultChunkInfo
    {
        public IntPtr Hash;
        public nuint Size;
        public ulong Offset;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct VaultChunkList
    {
        public IntPtr Chunks;
        public nuint Count;
        public IntPtr Data;
    }

    [LibraryImport(LibraryName)]
    internal static partial IntPtr vault_chunker_create();

    [LibraryImport(LibraryName)]
    internal static partial IntPtr vault_chunker_create_custom(
        nuint minSize,
        nuint avgSize,
        nuint maxSize);

    [LibraryImport(LibraryName)]
    internal static partial void vault_chunker_free(IntPtr engine);

    [LibraryImport(LibraryName)]
    internal static unsafe partial IntPtr vault_chunker_chunk(
        IntPtr engine,
        byte* data,
        nuint dataLen);

    [LibraryImport(LibraryName)]
    internal static partial void vault_chunk_list_free(IntPtr list);

    [LibraryImport(LibraryName)]
    internal static unsafe partial IntPtr vault_compute_hash(byte* data, nuint dataLen);
}
