using System;
using System.Runtime.InteropServices;

namespace VaultCore.Native;

/// <summary>
/// Vault-core library information and utilities.
/// </summary>
public static class Vault
{
    private static string? _version;

    /// <summary>
    /// Gets the native library version.
    /// </summary>
    public static string Version
    {
        get
        {
            if (_version == null)
            {
                var versionPtr = NativeMethods.vault_version();
                _version = Marshal.PtrToStringAnsi(versionPtr) ?? "unknown";
            }
            return _version;
        }
    }

    /// <summary>
    /// Checks if the native library is loaded and functional.
    /// </summary>
    /// <returns>True if the library is available.</returns>
    public static bool IsAvailable()
    {
        try
        {
            _ = Version;
            return true;
        }
        catch
        {
            return false;
        }
    }
}
