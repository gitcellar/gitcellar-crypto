using System;
using System.Runtime.InteropServices;

namespace VaultCore.Native;

/// <summary>
/// AES-256-GCM encryption engine.
/// </summary>
/// <remarks>
/// <para>
/// This class provides authenticated encryption using AES-256 in GCM mode.
/// Keys are 32 bytes (256 bits), and the output includes a 12-byte nonce
/// prepended to the ciphertext.
/// </para>
/// <para>
/// Thread-safe: instances can be used from multiple threads.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// // Generate a random key
/// var key = AesEngine.GenerateKey();
///
/// // Create engine
/// using var engine = new AesEngine(key);
///
/// // Encrypt
/// var encrypted = engine.Encrypt(Encoding.UTF8.GetBytes("secret"));
///
/// // Decrypt
/// var decrypted = engine.Decrypt(encrypted);
/// </code>
/// </example>
public sealed class AesEngine : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    /// <summary>
    /// Key size in bytes (32 bytes = 256 bits).
    /// </summary>
    public const int KeySize = 32;

    /// <summary>
    /// Salt size in bytes for key derivation.
    /// </summary>
    public const int SaltSize = 16;

    /// <summary>
    /// Creates a new AES encryption engine.
    /// </summary>
    /// <param name="key">32-byte encryption key.</param>
    /// <exception cref="ArgumentException">Key is not 32 bytes.</exception>
    /// <exception cref="VaultException">Failed to create engine.</exception>
    public AesEngine(byte[] key)
    {
        ArgumentNullException.ThrowIfNull(key);

        if (key.Length != KeySize)
        {
            throw new ArgumentException($"Key must be {KeySize} bytes, got {key.Length}", nameof(key));
        }

        unsafe
        {
            fixed (byte* keyPtr = key)
            {
                _handle = NativeMethods.vault_aes_create(keyPtr, (nuint)key.Length);
            }
        }

        if (_handle == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Create AES engine");
        }
    }

    /// <summary>
    /// Generates a random 256-bit encryption key.
    /// </summary>
    /// <returns>32-byte random key.</returns>
    public static byte[] GenerateKey()
    {
        var bufferPtr = NativeMethods.vault_aes_generate_key();
        if (bufferPtr == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Generate key");
        }

        try
        {
            return BufferToByteArray(bufferPtr);
        }
        finally
        {
            NativeMethods.vault_buffer_free(bufferPtr);
        }
    }

    /// <summary>
    /// Generates a random salt for key derivation.
    /// </summary>
    /// <returns>16-byte random salt.</returns>
    public static byte[] GenerateSalt()
    {
        var bufferPtr = NativeMethods.vault_aes_generate_salt();
        if (bufferPtr == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Generate salt");
        }

        try
        {
            return BufferToByteArray(bufferPtr);
        }
        finally
        {
            NativeMethods.vault_buffer_free(bufferPtr);
        }
    }

    /// <summary>
    /// Derives an encryption key from a passphrase using Argon2id.
    /// </summary>
    /// <param name="passphrase">User passphrase.</param>
    /// <param name="salt">16-byte salt (should be stored with encrypted data).</param>
    /// <returns>32-byte derived key.</returns>
    /// <exception cref="VaultException">Key derivation failed.</exception>
    /// <remarks>
    /// Uses Argon2id with OWASP-recommended parameters:
    /// - 64 MiB memory
    /// - 3 iterations
    /// - 4 parallel lanes
    /// </remarks>
    public static byte[] DeriveKey(byte[] passphrase, byte[] salt)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        ArgumentNullException.ThrowIfNull(salt);

        IntPtr bufferPtr;

        unsafe
        {
            fixed (byte* passphrasePtr = passphrase)
            fixed (byte* saltPtr = salt)
            {
                bufferPtr = NativeMethods.vault_aes_derive_key(
                    passphrasePtr,
                    (nuint)passphrase.Length,
                    saltPtr,
                    (nuint)salt.Length);
            }
        }

        if (bufferPtr == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Derive key");
        }

        try
        {
            return BufferToByteArray(bufferPtr);
        }
        finally
        {
            NativeMethods.vault_buffer_free(bufferPtr);
        }
    }

    /// <summary>
    /// Encrypts data using AES-256-GCM.
    /// </summary>
    /// <param name="plaintext">Data to encrypt.</param>
    /// <returns>Encrypted data (nonce + ciphertext + auth tag).</returns>
    /// <exception cref="VaultException">Encryption failed.</exception>
    public byte[] Encrypt(byte[] plaintext)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(plaintext);

        IntPtr bufferPtr;

        unsafe
        {
            fixed (byte* plaintextPtr = plaintext)
            {
                bufferPtr = NativeMethods.vault_aes_encrypt(
                    _handle,
                    plaintextPtr,
                    (nuint)plaintext.Length);
            }
        }

        if (bufferPtr == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Encrypt");
        }

        try
        {
            return BufferToByteArray(bufferPtr);
        }
        finally
        {
            NativeMethods.vault_buffer_free(bufferPtr);
        }
    }

    /// <summary>
    /// Encrypts data using AES-256-GCM (span version).
    /// </summary>
    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        ThrowIfDisposed();

        IntPtr bufferPtr;

        unsafe
        {
            fixed (byte* plaintextPtr = plaintext)
            {
                bufferPtr = NativeMethods.vault_aes_encrypt(
                    _handle,
                    plaintextPtr,
                    (nuint)plaintext.Length);
            }
        }

        if (bufferPtr == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Encrypt");
        }

        try
        {
            return BufferToByteArray(bufferPtr);
        }
        finally
        {
            NativeMethods.vault_buffer_free(bufferPtr);
        }
    }

    /// <summary>
    /// Decrypts data using AES-256-GCM.
    /// </summary>
    /// <param name="ciphertext">Encrypted data (nonce + ciphertext + auth tag).</param>
    /// <returns>Decrypted plaintext.</returns>
    /// <exception cref="VaultException">Decryption failed (e.g., tampered data).</exception>
    public byte[] Decrypt(byte[] ciphertext)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(ciphertext);

        IntPtr bufferPtr;

        unsafe
        {
            fixed (byte* ciphertextPtr = ciphertext)
            {
                bufferPtr = NativeMethods.vault_aes_decrypt(
                    _handle,
                    ciphertextPtr,
                    (nuint)ciphertext.Length);
            }
        }

        if (bufferPtr == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Decrypt");
        }

        try
        {
            return BufferToByteArray(bufferPtr);
        }
        finally
        {
            NativeMethods.vault_buffer_free(bufferPtr);
        }
    }

    /// <summary>
    /// Decrypts data using AES-256-GCM (span version).
    /// </summary>
    public byte[] Decrypt(ReadOnlySpan<byte> ciphertext)
    {
        ThrowIfDisposed();

        IntPtr bufferPtr;

        unsafe
        {
            fixed (byte* ciphertextPtr = ciphertext)
            {
                bufferPtr = NativeMethods.vault_aes_decrypt(
                    _handle,
                    ciphertextPtr,
                    (nuint)ciphertext.Length);
            }
        }

        if (bufferPtr == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Decrypt");
        }

        try
        {
            return BufferToByteArray(bufferPtr);
        }
        finally
        {
            NativeMethods.vault_buffer_free(bufferPtr);
        }
    }

    private static byte[] BufferToByteArray(IntPtr bufferPtr)
    {
        var buffer = Marshal.PtrToStructure<NativeMethods.VaultBuffer>(bufferPtr);
        var result = new byte[(int)buffer.Length];
        Marshal.Copy(buffer.Data, result, 0, (int)buffer.Length);
        return result;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    /// <summary>
    /// Releases the native encryption engine.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            if (_handle != IntPtr.Zero)
            {
                NativeMethods.vault_aes_free(_handle);
                _handle = IntPtr.Zero;
            }
            _disposed = true;
        }
    }
}
