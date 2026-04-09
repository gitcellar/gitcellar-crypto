//! Challenge generation for authentication
//!
//! Provides cryptographically secure challenge nonces for
//! challenge-response authentication.

use rand::Rng;

/// Generate a random challenge nonce
///
/// Returns a 64-character hex string (32 bytes of entropy).
/// This should be used once and then discarded.
///
/// # Example
/// ```
/// use passkey_core::auth::generate_challenge;
/// let challenge = generate_challenge();
/// assert_eq!(challenge.len(), 64);
/// ```
pub fn generate_challenge() -> String {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    hex::encode(bytes)
}

/// Generate a challenge with timestamp
///
/// Returns a challenge that includes a timestamp prefix for expiration checking.
/// Format: `{unix_timestamp_hex}:{random_hex}`
///
/// # Example
/// ```
/// use passkey_core::auth::generate_timestamped_challenge;
/// let challenge = generate_timestamped_challenge();
/// assert!(challenge.contains(':'));
/// ```
pub fn generate_timestamped_challenge() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut rng = rand::thread_rng();
    let random_bytes: [u8; 24] = rng.gen();

    format!("{}:{}", hex::encode(timestamp.to_be_bytes()), hex::encode(random_bytes))
}

/// Check if a timestamped challenge has expired
///
/// # Arguments
/// * `challenge` - A challenge created by `generate_timestamped_challenge`
/// * `max_age_secs` - Maximum age in seconds before the challenge expires
///
/// # Returns
/// * `Ok(true)` - Challenge is still valid
/// * `Ok(false)` - Challenge has expired
/// * `Err(_)` - Challenge format is invalid
pub fn is_challenge_valid(challenge: &str, max_age_secs: u64) -> Result<bool, &'static str> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let parts: Vec<&str> = challenge.split(':').collect();
    if parts.len() != 2 {
        return Err("Invalid challenge format");
    }

    let timestamp_bytes = hex::decode(parts[0])
        .map_err(|_| "Invalid timestamp hex")?;

    if timestamp_bytes.len() != 8 {
        return Err("Invalid timestamp length");
    }

    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&timestamp_bytes);
    let challenge_time = u64::from_be_bytes(bytes);

    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(current_time.saturating_sub(challenge_time) <= max_age_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge_length() {
        let challenge = generate_challenge();
        assert_eq!(challenge.len(), 64);
    }

    #[test]
    fn test_generate_challenge_hex() {
        let challenge = generate_challenge();
        assert!(challenge.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_challenge_unique() {
        let c1 = generate_challenge();
        let c2 = generate_challenge();
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_timestamped_challenge_format() {
        let challenge = generate_timestamped_challenge();
        let parts: Vec<&str> = challenge.split(':').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 16); // 8 bytes = 16 hex chars
        assert_eq!(parts[1].len(), 48); // 24 bytes = 48 hex chars
    }

    #[test]
    fn test_challenge_validity_fresh() {
        let challenge = generate_timestamped_challenge();
        assert!(is_challenge_valid(&challenge, 300).unwrap()); // 5 minutes
    }

    #[test]
    fn test_challenge_validity_expired() {
        // Create a challenge with old timestamp
        let old_timestamp = 0u64; // Unix epoch
        let random_bytes: [u8; 24] = [0; 24];
        let old_challenge = format!("{}:{}", hex::encode(old_timestamp.to_be_bytes()), hex::encode(random_bytes));

        assert!(!is_challenge_valid(&old_challenge, 300).unwrap());
    }

    #[test]
    fn test_challenge_validity_invalid_format() {
        assert!(is_challenge_valid("invalid", 300).is_err());
        assert!(is_challenge_valid("too:many:parts", 300).is_err());
    }
}
