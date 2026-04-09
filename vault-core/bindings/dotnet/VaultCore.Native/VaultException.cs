using System;
using System.Runtime.InteropServices;

namespace VaultCore.Native;

/// <summary>
/// Exception thrown when a vault-core operation fails.
/// </summary>
public class VaultException : Exception
{
    /// <summary>
    /// Creates a new VaultException with the specified message.
    /// </summary>
    public VaultException(string message) : base(message)
    {
    }

    /// <summary>
    /// Creates a new VaultException with the specified message and inner exception.
    /// </summary>
    public VaultException(string message, Exception innerException) : base(message, innerException)
    {
    }

    /// <summary>
    /// Gets the last error from the native library.
    /// </summary>
    internal static VaultException FromLastError(string operation)
    {
        var errorPtr = NativeMethods.vault_last_error();
        if (errorPtr == IntPtr.Zero)
        {
            return new VaultException($"{operation} failed (no error message)");
        }

        try
        {
            var message = Marshal.PtrToStringAnsi(errorPtr);
            return new VaultException($"{operation} failed: {message}");
        }
        finally
        {
            NativeMethods.vault_error_free(errorPtr);
        }
    }
}
