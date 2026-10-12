//! OS keyring implementation using the keyring crate

use crate::error::{PasskeyError, Result};
use crate::credential_store::{CredentialBackend, CredentialStore};
use keyring::Entry;
use tracing::{debug, warn};

impl CredentialStore {
    /// Store a value in the credential store
    pub(crate) fn store(&self, key: &str, value: &str) -> Result<()> {
        let entry = Entry::new(&self.service_name, key)
            .map_err(|e| PasskeyError::CredentialStore(format!("Failed to create entry: {}", e)))?;

        entry
            .set_password(value)
            .map_err(|e| PasskeyError::CredentialStore(format!("Failed to set value: {}", e)))?;

        debug!("Stored credential '{}' in OS credential store", key);
        Ok(())
    }

    /// Retrieve a value from the credential store
    pub(crate) fn get(&self, key: &str) -> Result<Option<String>> {
        let entry = Entry::new(&self.service_name, key)
            .map_err(|e| PasskeyError::CredentialStore(format!("Failed to create entry: {}", e)))?;

        match entry.get_password() {
            Ok(value) => {
                debug!("Retrieved credential '{}' from OS credential store", key);
                Ok(Some(value))
            }
            Err(keyring::Error::NoEntry) => {
                debug!("Credential '{}' not found in OS credential store", key);
                Ok(None)
            }
            Err(keyring::Error::Ambiguous(_)) => {
                warn!("Multiple entries found for credential '{}', using first", key);
                Ok(None)
            }
            Err(e) => {
                warn!("Error accessing credential '{}': {}", key, e);
                Err(PasskeyError::CredentialStore(format!("Failed to retrieve '{}': {}", key, e)))
            }
        }
    }

    /// Delete a value from the credential store
    pub(crate) fn delete(&self, key: &str) -> Result<()> {
        let entry = Entry::new(&self.service_name, key)
            .map_err(|e| PasskeyError::CredentialStore(format!("Failed to create entry: {}", e)))?;

        match entry.delete_credential() {
            Ok(()) => {
                debug!("Deleted credential '{}' from OS credential store", key);
                Ok(())
            }
            Err(keyring::Error::NoEntry) => {
                // Not an error - credential wasn't there
                Ok(())
            }
            Err(e) => Err(PasskeyError::CredentialStore(format!("Failed to delete '{}': {}", key, e))),
        }
    }
}

impl CredentialBackend for CredentialStore {
    fn store(&self, key: &str, value: &str) -> Result<()> {
        CredentialStore::store(self, key, value)
    }

    fn get(&self, key: &str) -> Result<Option<String>> {
        CredentialStore::get(self, key)
    }

    fn delete(&self, key: &str) -> Result<()> {
        CredentialStore::delete(self, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests interact with the actual OS credential store.
    //
    // They used to skip on ANY store/get failure, and on a
    // store that "succeeded" but read back None. keyring v3 silently falls back
    // to an in-memory MOCK when no platform backend feature is enabled, which is
    // exactly the build-graph regression Cargo.toml's backend features exist to
    // prevent -- and these tests read it as "CI without a keyring". Now: the mock
    // is a failure, a backend-absent signal from keyring (NoStorageAccess /
    // PlatformFailure on the probe write) is the only skip, and once the probe
    // write succeeded every operation must work.

    const TEST_SERVICE: &str = "passkey-core-test";

    fn test_store() -> CredentialStore {
        CredentialStore::with_service_name(TEST_SERVICE)
    }

    /// `true` when a real OS backend is usable, `false` only on keyring's own
    /// backend-absent signal. Panics on the mock or any other failure.
    fn os_backend_available() -> bool {
        // On Linux (keyutils) Entry::new already touches the kernel keyring, and a
        // default-seccomp container refuses keyctl with EPERM -> PlatformFailure;
        // that is the same backend-absent signal as on the probe write below.
        let entry = match Entry::new(TEST_SERVICE, "backend_probe") {
            Ok(e) => e,
            Err(keyring::Error::NoStorageAccess(e)) | Err(keyring::Error::PlatformFailure(e)) => {
                eprintln!("Skipping: no usable OS keyring in this environment: {e}");
                return false;
            }
            Err(e) => panic!("keyring Entry::new failed for a reason that is not backend absence: {e}"),
        };
        assert!(
            entry
                .get_credential()
                .downcast_ref::<keyring::mock::MockCredential>()
                .is_none(),
            "keyring resolved to its in-memory MOCK store: no platform backend feature is enabled in this build graph, so credentials do not persist across processes"
        );
        match entry.set_password("probe") {
            Ok(()) => {
                let _ = entry.delete_credential();
                true
            }
            Err(keyring::Error::NoStorageAccess(e)) | Err(keyring::Error::PlatformFailure(e)) => {
                eprintln!("Skipping: no usable OS keyring in this environment: {e}");
                false
            }
            Err(e) => panic!("OS keyring probe write failed for a reason that is not backend absence: {e}"),
        }
    }

    #[test]
    fn test_store_and_retrieve() {
        if !os_backend_available() {
            return;
        }
        let store = test_store();
        let key = "test_key_passkey";
        let value = "test_value_12345";

        // Clean up first
        let _ = store.delete(key);

        store.store(key, value).expect("store on a working OS keyring");
        let retrieved = store
            .get(key)
            .expect("get on a working OS keyring")
            .expect("a stored credential must read back (None = the store did not persist)");
        assert_eq!(retrieved, value);

        // Clean up
        let _ = store.delete(key);
    }

    #[test]
    fn test_not_found() {
        if !os_backend_available() {
            return;
        }
        let store = test_store();
        let key = "nonexistent_credential_xyz123";

        // Make sure it doesn't exist
        let _ = store.delete(key);

        match store.get(key) {
            Ok(None) => {} // Expected: no credential, no error
            Ok(Some(_)) => {
                let _ = store.delete(key);
                panic!("Expected no credential for nonexistent key");
            }
            Err(e) => panic!("get of a missing key errored on a working OS keyring: {e:?}"),
        }
    }

    #[test]
    fn test_delete() {
        if !os_backend_available() {
            return;
        }
        let store = test_store();
        let key = "test_delete_key";

        store.store(key, "value").expect("store on a working OS keyring");

        // Delete
        store.delete(key).unwrap();

        // Should be gone
        let result = store.get(key);
        assert!(matches!(result, Ok(None)));
    }
}
