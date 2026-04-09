using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace VaultCore.Native;

/// <summary>
/// Represents a chunk of data produced by content-defined chunking.
/// </summary>
public sealed class Chunk
{
    /// <summary>
    /// SHA256 hash of the chunk data (hex string).
    /// </summary>
    public required string Hash { get; init; }

    /// <summary>
    /// Chunk data.
    /// </summary>
    public required byte[] Data { get; init; }

    /// <summary>
    /// Size in bytes.
    /// </summary>
    public int Size => Data.Length;

    /// <summary>
    /// Offset in the original data.
    /// </summary>
    public required ulong Offset { get; init; }
}

/// <summary>
/// Content-defined chunking engine.
/// </summary>
/// <remarks>
/// <para>
/// Produces variable-size chunks based on content, enabling efficient
/// deduplication. Identical content produces identical chunks regardless
/// of its position in the file.
/// </para>
/// <para>
/// Thread-safe: instances can be used from multiple threads.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// using var chunker = new ChunkEngine();
/// var chunks = chunker.Chunk(fileData);
///
/// foreach (var chunk in chunks)
/// {
///     Console.WriteLine($"Chunk {chunk.Hash}: {chunk.Size} bytes at offset {chunk.Offset}");
/// }
/// </code>
/// </example>
public sealed class ChunkEngine : IDisposable
{
    private IntPtr _handle;
    private bool _disposed;

    /// <summary>
    /// Default minimum chunk size (512 KB).
    /// </summary>
    public const int DefaultMinSize = 512 * 1024;

    /// <summary>
    /// Default average chunk size (1 MB).
    /// </summary>
    public const int DefaultAvgSize = 1024 * 1024;

    /// <summary>
    /// Default maximum chunk size (2 MB).
    /// </summary>
    public const int DefaultMaxSize = 2 * 1024 * 1024;

    /// <summary>
    /// Creates a chunk engine with default configuration.
    /// </summary>
    /// <remarks>
    /// Default configuration:
    /// - Min: 512 KB
    /// - Avg: 1 MB
    /// - Max: 2 MB
    /// </remarks>
    public ChunkEngine()
    {
        _handle = NativeMethods.vault_chunker_create();
        if (_handle == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Create chunk engine");
        }
    }

    /// <summary>
    /// Creates a chunk engine with custom configuration.
    /// </summary>
    /// <param name="minSize">Minimum chunk size in bytes.</param>
    /// <param name="avgSize">Average/target chunk size in bytes.</param>
    /// <param name="maxSize">Maximum chunk size in bytes.</param>
    /// <exception cref="ArgumentException">Invalid size configuration.</exception>
    public ChunkEngine(int minSize, int avgSize, int maxSize)
    {
        if (minSize <= 0) throw new ArgumentException("minSize must be positive", nameof(minSize));
        if (avgSize < minSize) throw new ArgumentException("avgSize must be >= minSize", nameof(avgSize));
        if (maxSize < avgSize) throw new ArgumentException("maxSize must be >= avgSize", nameof(maxSize));

        _handle = NativeMethods.vault_chunker_create_custom(
            (nuint)minSize,
            (nuint)avgSize,
            (nuint)maxSize);

        if (_handle == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Create chunk engine");
        }
    }

    /// <summary>
    /// Creates a chunk engine optimized for small files (&lt;10 MB).
    /// </summary>
    public static ChunkEngine ForSmallFiles() => new(64 * 1024, 256 * 1024, 512 * 1024);

    /// <summary>
    /// Creates a chunk engine optimized for large files (&gt;100 MB).
    /// </summary>
    public static ChunkEngine ForLargeFiles() => new(1024 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024);

    /// <summary>
    /// Chunks data using content-defined chunking.
    /// </summary>
    /// <param name="data">Data to chunk.</param>
    /// <returns>List of chunks in order.</returns>
    /// <exception cref="VaultException">Chunking failed.</exception>
    public IReadOnlyList<Chunk> Chunk(byte[] data)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(data);

        if (data.Length == 0)
        {
            return Array.Empty<Chunk>();
        }

        IntPtr listPtr;

        unsafe
        {
            fixed (byte* dataPtr = data)
            {
                listPtr = NativeMethods.vault_chunker_chunk(_handle, dataPtr, (nuint)data.Length);
            }
        }

        if (listPtr == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Chunk data");
        }

        try
        {
            return ParseChunkList(listPtr);
        }
        finally
        {
            NativeMethods.vault_chunk_list_free(listPtr);
        }
    }

    /// <summary>
    /// Chunks data using content-defined chunking (span version).
    /// </summary>
    public IReadOnlyList<Chunk> Chunk(ReadOnlySpan<byte> data)
    {
        ThrowIfDisposed();

        if (data.Length == 0)
        {
            return Array.Empty<Chunk>();
        }

        IntPtr listPtr;

        unsafe
        {
            fixed (byte* dataPtr = data)
            {
                listPtr = NativeMethods.vault_chunker_chunk(_handle, dataPtr, (nuint)data.Length);
            }
        }

        if (listPtr == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Chunk data");
        }

        try
        {
            return ParseChunkList(listPtr);
        }
        finally
        {
            NativeMethods.vault_chunk_list_free(listPtr);
        }
    }

    /// <summary>
    /// Reassembles chunks back into original data.
    /// </summary>
    /// <param name="chunks">Chunks in order.</param>
    /// <returns>Reassembled data.</returns>
    public static byte[] Reassemble(IEnumerable<Chunk> chunks)
    {
        ArgumentNullException.ThrowIfNull(chunks);

        var totalSize = 0;
        foreach (var chunk in chunks)
        {
            totalSize += chunk.Size;
        }

        var result = new byte[totalSize];
        var offset = 0;

        foreach (var chunk in chunks)
        {
            Buffer.BlockCopy(chunk.Data, 0, result, offset, chunk.Size);
            offset += chunk.Size;
        }

        return result;
    }

    /// <summary>
    /// Computes SHA256 hash of data.
    /// </summary>
    /// <param name="data">Data to hash.</param>
    /// <returns>Lowercase hex string.</returns>
    public static string ComputeHash(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        IntPtr hashPtr;

        unsafe
        {
            fixed (byte* dataPtr = data)
            {
                hashPtr = NativeMethods.vault_compute_hash(dataPtr, (nuint)data.Length);
            }
        }

        if (hashPtr == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Compute hash");
        }

        try
        {
            return Marshal.PtrToStringAnsi(hashPtr) ?? "";
        }
        finally
        {
            NativeMethods.vault_error_free(hashPtr);
        }
    }

    /// <summary>
    /// Computes SHA256 hash of data (span version).
    /// </summary>
    public static string ComputeHash(ReadOnlySpan<byte> data)
    {
        IntPtr hashPtr;

        unsafe
        {
            fixed (byte* dataPtr = data)
            {
                hashPtr = NativeMethods.vault_compute_hash(dataPtr, (nuint)data.Length);
            }
        }

        if (hashPtr == IntPtr.Zero)
        {
            throw VaultException.FromLastError("Compute hash");
        }

        try
        {
            return Marshal.PtrToStringAnsi(hashPtr) ?? "";
        }
        finally
        {
            NativeMethods.vault_error_free(hashPtr);
        }
    }

    private static IReadOnlyList<Chunk> ParseChunkList(IntPtr listPtr)
    {
        var list = Marshal.PtrToStructure<NativeMethods.VaultChunkList>(listPtr);
        var chunks = new List<Chunk>((int)list.Count);

        for (nuint i = 0; i < list.Count; i++)
        {
            // Get chunk info
            var infoPtr = list.Chunks + (nint)i * Marshal.SizeOf<NativeMethods.VaultChunkInfo>();
            var info = Marshal.PtrToStructure<NativeMethods.VaultChunkInfo>(infoPtr);

            // Get chunk data buffer
            var bufferPtrPtr = list.Data + (nint)i * IntPtr.Size;
            var bufferPtr = Marshal.ReadIntPtr(bufferPtrPtr);
            var buffer = Marshal.PtrToStructure<NativeMethods.VaultBuffer>(bufferPtr);

            // Copy data
            var data = new byte[(int)buffer.Length];
            Marshal.Copy(buffer.Data, data, 0, (int)buffer.Length);

            chunks.Add(new Chunk
            {
                Hash = Marshal.PtrToStringAnsi(info.Hash) ?? "",
                Data = data,
                Offset = info.Offset
            });
        }

        return chunks;
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    /// <summary>
    /// Releases the native chunk engine.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed)
        {
            if (_handle != IntPtr.Zero)
            {
                NativeMethods.vault_chunker_free(_handle);
                _handle = IntPtr.Zero;
            }
            _disposed = true;
        }
    }
}
