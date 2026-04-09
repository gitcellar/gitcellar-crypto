//! In-memory credential store for testing
//!
//! This provides a simple in-memory implementation of the credential store
//! that can be used in tests without requiring OS keyring access.

use crate::error::Result;
use crate::credential_store::CredentialBackend;
use std::collections::HashMap;
use std::sync::RwLock;

/// In-memory credential store for testing
///
/// Thread-safe storage that keeps credentials in memory.
/// Useful for unit tests that don't need actual OS keyring access.
pub struct MemoryCredentialStore {
    data: RwLock<HashMap<String, String>>,
}

impl MemoryCredentialStore {
    /// Create a new empty memory store
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }

    /// Store a value
    pub fn store(&self, key: &str, value: &str) -> Result<()> {
        let mut data = self.data.write().unwrap();
        data.insert(key.to_string(), value.to_string());
        Ok(())
    }

    /// Retrieve a value
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        let data = self.data.read().unwrap();
        Ok(data.get(key).cloned())
    }

    /// Delete a value
    pub fn delete(&self, key: &str) -> Result<()> {
        let mut data = self.data.write().unwrap();
        data.remove(key);
        Ok(())
    }

    /// Check if a key exists
    pub fn contains(&self, key: &str) -> bool {
        let data = self.data.read().unwrap();
        data.contains_key(key)
    }

    /// Clear all stored credentials
    pub fn clear(&self) {
        let mut data = self.data.write().unwrap();
        data.clear();
    }

    /// Get the number of stored credentials
    pub fn len(&self) -> usize {
        let data = self.data.read().unwrap();
        data.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for MemoryCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialBackend for MemoryCredentialStore {
    fn store(&self, key: &str, value: &str) -> Result<()> {
        MemoryCredentialStore::store(self, key, value)
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        MemoryCredentialStore::get(self, key)
    }

    fn delete(&self, key: &str) -> Result<()> {
        MemoryCredentialStore::delete(self, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_retrieve() {
        let store = MemoryCredentialStore::new();

        store.store("key1", "value1").unwrap();
        store.store("key2", "value2").unwrap();

        assert_eq!(store.get("key1").unwrap(), Some("value1".to_string()));
        assert_eq!(store.get("key2").unwrap(), Some("value2".to_string()));
        assert_eq!(store.get("key3").unwrap(), None);
    }

    #[test]
    fn test_delete() {
        let store = MemoryCredentialStore::new();

        store.store("key", "value").unwrap();
        assert!(store.contains("key"));

        store.delete("key").unwrap();
        assert!(!store.contains("key"));
    }

    #[test]
    fn test_clear() {
        let store = MemoryCredentialStore::new();

        store.store("key1", "value1").unwrap();
        store.store("key2", "value2").unwrap();
        assert_eq!(store.len(), 2);

        store.clear();
        assert!(store.is_empty());
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(MemoryCredentialStore::new());
        let mut handles = vec![];

        // Spawn multiple threads that store and retrieve
        for i in 0..10 {
            let store_clone = Arc::clone(&store);
            let handle = thread::spawn(move || {
                let key = format!("key_{}", i);
                let value = format!("value_{}", i);
                store_clone.store(&key, &value).unwrap();
                assert_eq!(store_clone.get(&key).unwrap(), Some(value));
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(store.len(), 10);
    }
}
