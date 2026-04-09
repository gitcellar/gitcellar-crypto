//! FFI (Foreign Function Interface) exports for C/C#/other languages
//!
//! This module provides C-compatible functions that can be called from
//! other languages via P/Invoke (C#), ctypes (Python), etc.
//!
//! # Memory Management
//!
//! - All returned buffers must be freed using `vault_buffer_free()`
//! - Error messages are written to caller-provided buffers
//! - Opaque handles should be freed using their respective `*_free()` functions
//!
//! # Thread Safety
//!
//! All functions are thread-safe. Handles can be shared across threads.
//!
//! # Error Handling
//!
//! Functions return error codes:
//! - 0: Success
//! - Non-zero: Error (see `VaultErrorCode`)
//!
//! Call `vault_last_error()` to get the error message after a failure.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::ptr;
use std::slice;
use std::sync::Mutex;

use crate::chunking::{ChunkConfig, ChunkEngine};
use crate::encryption::{AesEncryptionEngine, EncryptionEngine};
use crate::error::VaultError;

// Thread-local error storage
thread_local! {
    static LAST_ERROR: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
}

fn set_last_error(msg: String) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = Some(msg);
    });
}

fn clear_last_error() {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = None;
    });
}

// ============================================================================
// Buffer type for returning byte arrays
// ============================================================================

/// Opaque buffer type for returning byte arrays to callers
#[repr(C)]
pub struct VaultBuffer {
    /// Pointer to data
    pub data: *mut c_uchar,
    /// Length in bytes
    pub len: usize,
    /// Capacity (for internal use)
    capacity: usize,
}

impl VaultBuffer {
    fn from_vec(v: Vec<u8>) -> *mut Self {
        let mut v = v;
        let buffer = Box::new(VaultBuffer {
            data: v.as_mut_ptr(),
            len: v.len(),
            capacity: v.capacity(),
        });
        std::mem::forget(v); // Prevent Vec from freeing the data
        Box::into_raw(buffer)
    }

    unsafe fn into_vec(ptr: *mut Self) -> Vec<u8> {
        if ptr.is_null() {
            return Vec::new();
        }
        let buffer = Box::from_raw(ptr);
        Vec::from_raw_parts(buffer.data, buffer.len, buffer.capacity)
    }
}

/// Free a buffer returned by vault functions
///
/// # Safety
/// The buffer must have been returned by a vault_* function.
#[no_mangle]
pub unsafe extern "C" fn vault_buffer_free(buffer: *mut VaultBuffer) {
    if !buffer.is_null() {
        let _ = VaultBuffer::into_vec(buffer); // Drop the Vec
    }
}

// ============================================================================
// Error handling
// ============================================================================

/// Get the last error message
///
/// Returns NULL if no error occurred.
/// The returned string is valid until the next vault_* call on this thread.
///
/// # Safety
/// The returned pointer is valid until the next vault call.
#[no_mangle]
pub extern "C" fn vault_last_error() -> *const c_char {
    LAST_ERROR.with(|e| {
        let borrowed = e.borrow();
        match &*borrowed {
            Some(msg) => {
                // Create a static-ish string for the error
                // This is a bit hacky but works for FFI
                CString::new(msg.as_str())
                    .map(|s| s.into_raw() as *const c_char)
                    .unwrap_or(ptr::null())
            }
            None => ptr::null(),
        }
    })
}

/// Free an error string returned by vault_last_error
///
/// # Safety
/// Must only be called with pointers returned by vault_last_error.
#[no_mangle]
pub unsafe extern "C" fn vault_error_free(error: *mut c_char) {
    if !error.is_null() {
        let _ = CString::from_raw(error);
    }
}

// ============================================================================
// AES Encryption
// ============================================================================

/// Opaque handle to an AES encryption engine
pub struct VaultAesEngine {
    inner: AesEncryptionEngine,
}

/// Generate a random 256-bit AES key
///
/// Returns a 32-byte buffer that must be freed with vault_buffer_free.
#[no_mangle]
pub extern "C" fn vault_aes_generate_key() -> *mut VaultBuffer {
    clear_last_error();
    let key = AesEncryptionEngine::generate_key();
    VaultBuffer::from_vec(key.to_vec())
}

/// Generate a random 16-byte salt for key derivation
///
/// Returns a 16-byte buffer that must be freed with vault_buffer_free.
#[no_mangle]
pub extern "C" fn vault_aes_generate_salt() -> *mut VaultBuffer {
    clear_last_error();
    let salt = AesEncryptionEngine::generate_salt();
    VaultBuffer::from_vec(salt.to_vec())
}

/// Derive an AES key from a passphrase
///
/// # Arguments
/// * `passphrase` - Passphrase bytes
/// * `passphrase_len` - Length of passphrase
/// * `salt` - 16-byte salt
/// * `salt_len` - Length of salt (must be 16)
///
/// # Returns
/// 32-byte key buffer, or NULL on error.
///
/// # Safety
/// Pointers must be valid for the specified lengths.
#[no_mangle]
pub unsafe extern "C" fn vault_aes_derive_key(
    passphrase: *const c_uchar,
    passphrase_len: usize,
    salt: *const c_uchar,
    salt_len: usize,
) -> *mut VaultBuffer {
    clear_last_error();

    if passphrase.is_null() || salt.is_null() {
        set_last_error("Null pointer argument".to_string());
        return ptr::null_mut();
    }

    let passphrase_slice = slice::from_raw_parts(passphrase, passphrase_len);
    let salt_slice = slice::from_raw_parts(salt, salt_len);

    match AesEncryptionEngine::derive_key(passphrase_slice, salt_slice) {
        Ok(key) => VaultBuffer::from_vec(key.to_vec()),
        Err(e) => {
            set_last_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Create an AES encryption engine
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `key_len` - Length of key (must be 32)
///
/// # Returns
/// Handle to encryption engine, or NULL on error.
///
/// # Safety
/// Key pointer must be valid for key_len bytes.
#[no_mangle]
pub unsafe extern "C" fn vault_aes_create(
    key: *const c_uchar,
    key_len: usize,
) -> *mut VaultAesEngine {
    clear_last_error();

    if key.is_null() {
        set_last_error("Null key pointer".to_string());
        return ptr::null_mut();
    }

    let key_slice = slice::from_raw_parts(key, key_len);

    match AesEncryptionEngine::new(key_slice) {
        Ok(engine) => Box::into_raw(Box::new(VaultAesEngine { inner: engine })),
        Err(e) => {
            set_last_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Free an AES encryption engine
///
/// # Safety
/// Handle must have been created by vault_aes_create.
#[no_mangle]
pub unsafe extern "C" fn vault_aes_free(engine: *mut VaultAesEngine) {
    if !engine.is_null() {
        let _ = Box::from_raw(engine);
    }
}

/// Encrypt data using AES-256-GCM
///
/// # Arguments
/// * `engine` - Encryption engine handle
/// * `plaintext` - Data to encrypt
/// * `plaintext_len` - Length of plaintext
///
/// # Returns
/// Buffer containing encrypted data (nonce + ciphertext), or NULL on error.
///
/// # Safety
/// All pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn vault_aes_encrypt(
    engine: *const VaultAesEngine,
    plaintext: *const c_uchar,
    plaintext_len: usize,
) -> *mut VaultBuffer {
    clear_last_error();

    if engine.is_null() || plaintext.is_null() {
        set_last_error("Null pointer argument".to_string());
        return ptr::null_mut();
    }

    let engine = &*engine;
    let plaintext_slice = slice::from_raw_parts(plaintext, plaintext_len);

    match engine.inner.encrypt(plaintext_slice) {
        Ok(encrypted) => VaultBuffer::from_vec(encrypted),
        Err(e) => {
            set_last_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Decrypt data using AES-256-GCM
///
/// # Arguments
/// * `engine` - Encryption engine handle
/// * `ciphertext` - Data to decrypt (nonce + ciphertext)
/// * `ciphertext_len` - Length of ciphertext
///
/// # Returns
/// Buffer containing decrypted data, or NULL on error.
///
/// # Safety
/// All pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn vault_aes_decrypt(
    engine: *const VaultAesEngine,
    ciphertext: *const c_uchar,
    ciphertext_len: usize,
) -> *mut VaultBuffer {
    clear_last_error();

    if engine.is_null() || ciphertext.is_null() {
        set_last_error("Null pointer argument".to_string());
        return ptr::null_mut();
    }

    let engine = &*engine;
    let ciphertext_slice = slice::from_raw_parts(ciphertext, ciphertext_len);

    match engine.inner.decrypt(ciphertext_slice) {
        Ok(decrypted) => VaultBuffer::from_vec(decrypted),
        Err(e) => {
            set_last_error(e.to_string());
            ptr::null_mut()
        }
    }
}

// ============================================================================
// Chunking
// ============================================================================

/// Opaque handle to a chunk engine
pub struct VaultChunkEngine {
    inner: ChunkEngine,
}

/// Chunk metadata returned by chunking operations
#[repr(C)]
pub struct VaultChunkInfo {
    /// SHA256 hash as null-terminated hex string
    pub hash: *mut c_char,
    /// Size in bytes
    pub size: usize,
    /// Offset in original data
    pub offset: u64,
}

/// Array of chunk info
#[repr(C)]
pub struct VaultChunkList {
    /// Pointer to array of chunk info
    pub chunks: *mut VaultChunkInfo,
    /// Number of chunks
    pub count: usize,
    /// Chunk data buffers (parallel array)
    pub data: *mut *mut VaultBuffer,
}

/// Create a chunk engine with default configuration
///
/// Returns handle to engine, or NULL on error.
#[no_mangle]
pub extern "C" fn vault_chunker_create() -> *mut VaultChunkEngine {
    clear_last_error();
    let engine = ChunkEngine::new(ChunkConfig::default());
    Box::into_raw(Box::new(VaultChunkEngine { inner: engine }))
}

/// Create a chunk engine with custom configuration
///
/// # Arguments
/// * `min_size` - Minimum chunk size in bytes
/// * `avg_size` - Average chunk size in bytes
/// * `max_size` - Maximum chunk size in bytes
///
/// Returns handle to engine, or NULL on error.
#[no_mangle]
pub extern "C" fn vault_chunker_create_custom(
    min_size: usize,
    avg_size: usize,
    max_size: usize,
) -> *mut VaultChunkEngine {
    clear_last_error();
    let config = ChunkConfig::new(min_size, avg_size, max_size);
    let engine = ChunkEngine::new(config);
    Box::into_raw(Box::new(VaultChunkEngine { inner: engine }))
}

/// Free a chunk engine
///
/// # Safety
/// Handle must have been created by vault_chunker_create*.
#[no_mangle]
pub unsafe extern "C" fn vault_chunker_free(engine: *mut VaultChunkEngine) {
    if !engine.is_null() {
        let _ = Box::from_raw(engine);
    }
}

/// Chunk data into content-defined chunks
///
/// # Arguments
/// * `engine` - Chunk engine handle
/// * `data` - Data to chunk
/// * `data_len` - Length of data
///
/// # Returns
/// Chunk list containing metadata and data buffers, or NULL on error.
/// Must be freed with vault_chunk_list_free.
///
/// # Safety
/// All pointers must be valid.
#[no_mangle]
pub unsafe extern "C" fn vault_chunker_chunk(
    engine: *const VaultChunkEngine,
    data: *const c_uchar,
    data_len: usize,
) -> *mut VaultChunkList {
    clear_last_error();

    if engine.is_null() || (data.is_null() && data_len > 0) {
        set_last_error("Null pointer argument".to_string());
        return ptr::null_mut();
    }

    let engine = &*engine;
    let data_slice = if data_len > 0 {
        slice::from_raw_parts(data, data_len)
    } else {
        &[]
    };

    match engine.inner.chunk_data(data_slice) {
        Ok(chunks) => {
            let count = chunks.len();

            // Allocate arrays
            let chunk_infos: Vec<VaultChunkInfo> = chunks
                .iter()
                .map(|c| {
                    let hash = CString::new(c.hash.clone()).unwrap().into_raw();
                    VaultChunkInfo {
                        hash,
                        size: c.size,
                        offset: c.offset,
                    }
                })
                .collect();

            let data_buffers: Vec<*mut VaultBuffer> = chunks
                .into_iter()
                .map(|c| VaultBuffer::from_vec(c.data))
                .collect();

            // Box the arrays
            let mut chunk_infos = chunk_infos.into_boxed_slice();
            let mut data_buffers = data_buffers.into_boxed_slice();

            let list = Box::new(VaultChunkList {
                chunks: chunk_infos.as_mut_ptr(),
                count,
                data: data_buffers.as_mut_ptr(),
            });

            // Prevent arrays from being freed
            std::mem::forget(chunk_infos);
            std::mem::forget(data_buffers);

            Box::into_raw(list)
        }
        Err(e) => {
            set_last_error(e.to_string());
            ptr::null_mut()
        }
    }
}

/// Free a chunk list
///
/// # Safety
/// Must have been returned by vault_chunker_chunk.
#[no_mangle]
pub unsafe extern "C" fn vault_chunk_list_free(list: *mut VaultChunkList) {
    if list.is_null() {
        return;
    }

    let list = Box::from_raw(list);

    // Free each chunk info's hash string
    for i in 0..list.count {
        let info = &*list.chunks.add(i);
        if !info.hash.is_null() {
            let _ = CString::from_raw(info.hash);
        }
    }

    // Free each data buffer
    for i in 0..list.count {
        let buffer = *list.data.add(i);
        vault_buffer_free(buffer);
    }

    // Free the arrays themselves
    let _ = Vec::from_raw_parts(list.chunks, list.count, list.count);
    let _ = Vec::from_raw_parts(list.data, list.count, list.count);
}

/// Compute SHA256 hash of data
///
/// Returns null-terminated hex string that must be freed with vault_error_free.
///
/// # Safety
/// Data pointer must be valid for data_len bytes.
#[no_mangle]
pub unsafe extern "C" fn vault_compute_hash(
    data: *const c_uchar,
    data_len: usize,
) -> *mut c_char {
    clear_last_error();

    if data.is_null() && data_len > 0 {
        set_last_error("Null pointer argument".to_string());
        return ptr::null_mut();
    }

    let data_slice = if data_len > 0 {
        slice::from_raw_parts(data, data_len)
    } else {
        &[]
    };

    let hash = ChunkEngine::compute_hash(data_slice);
    CString::new(hash).unwrap().into_raw()
}

// ============================================================================
// Version info
// ============================================================================

/// Get the library version string
///
/// Returns a null-terminated string. Do not free.
#[no_mangle]
pub extern "C" fn vault_version() -> *const c_char {
    static VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_roundtrip_ffi() {
        unsafe {
            // Generate key
            let key_buf = vault_aes_generate_key();
            assert!(!key_buf.is_null());

            let key_slice = slice::from_raw_parts((*key_buf).data, (*key_buf).len);

            // Create engine
            let engine = vault_aes_create(key_slice.as_ptr(), key_slice.len());
            assert!(!engine.is_null());

            // Encrypt
            let plaintext = b"Hello, FFI!";
            let encrypted = vault_aes_encrypt(engine, plaintext.as_ptr(), plaintext.len());
            assert!(!encrypted.is_null());

            // Decrypt
            let decrypted = vault_aes_decrypt(
                engine,
                (*encrypted).data,
                (*encrypted).len,
            );
            assert!(!decrypted.is_null());

            let decrypted_slice = slice::from_raw_parts((*decrypted).data, (*decrypted).len);
            assert_eq!(plaintext.to_vec(), decrypted_slice.to_vec());

            // Cleanup
            vault_buffer_free(decrypted);
            vault_buffer_free(encrypted);
            vault_aes_free(engine);
            vault_buffer_free(key_buf);
        }
    }

    #[test]
    fn test_chunker_ffi() {
        unsafe {
            let engine = vault_chunker_create();
            assert!(!engine.is_null());

            let data = vec![0u8; 1024];
            let list = vault_chunker_chunk(engine, data.as_ptr(), data.len());
            assert!(!list.is_null());
            assert!((*list).count > 0);

            vault_chunk_list_free(list);
            vault_chunker_free(engine);
        }
    }

    #[test]
    fn test_version() {
        let version = vault_version();
        assert!(!version.is_null());
    }
}
