//! Challenge generation for authentication
//!
//! Provides cryptographically secure challenge nonces for
//! challenge-response authentication.

use rand::Rng;

use crate::error::PasskeyError;

/// What an authentication-challenge signature is for.
///
/// The purpose's domain tag is part of the signed bytes (see
/// [`challenge_signing_payload`]), so a signature made for one purpose never
/// verifies as another, and never as any other object the same key signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengePurpose {
    /// Challenge-response sign-in of a registered machine.
    Login,
    /// Proof of possession of a key being registered with a new account.
    RegistrationProof,
}

impl ChallengePurpose {
    /// Versioned domain tag signed in front of the challenge.
    pub fn domain(self) -> &'static str {
        match self {
            ChallengePurpose::Login => "gc-auth-login-v1",
            ChallengePurpose::RegistrationProof => "gc-auth-registration-pop-v1",
        }
    }
}

/// True for exactly the shape [`generate_challenge`] produces: 64 lowercase hex
/// characters. A client checks this before signing anything the server sent.
pub fn is_well_formed_challenge(challenge: &str) -> bool {
    challenge.len() == 64 && challenge.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The exact bytes an authentication-challenge signature covers:
/// `lp(purpose.domain()) ‖ lp(challenge)`, where `lp(s)` is
/// `<decimal byte length>:<s>\n` (the length-prefix encoding every signed
/// canonical in GitCellar uses).
///
/// The challenge comes from the server, which is untrusted. Signing it raw
/// would let a malicious server present *any* byte string (for example the
/// canonical of a key grant) as a "challenge" and receive the user's signature
/// over it. Two things prevent that here: the challenge must be a well-formed
/// nonce, and the signed bytes open with an auth-only domain tag that no other
/// signed object in the system starts with.
///
/// Returns [`PasskeyError::InvalidChallenge`] for anything that is not a
/// well-formed nonce. Signer and verifier must both build the payload here.
pub fn challenge_signing_payload(
    purpose: ChallengePurpose,
    challenge: &str,
) -> crate::error::Result<Vec<u8>> {
    if !is_well_formed_challenge(challenge) {
        return Err(PasskeyError::InvalidChallenge);
    }
    let mut out = Vec::with_capacity(96);
    for field in [purpose.domain(), challenge] {
        out.extend_from_slice(field.len().to_string().as_bytes());
        out.push(b':');
        out.extend_from_slice(field.as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

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
/// Not an authentication challenge: its `hex:hex` shape fails
/// [`is_well_formed_challenge`], so clients refuse to sign it.
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
    fn well_formed_challenge_accepts_only_generated_shape() {
        assert!(is_well_formed_challenge(&generate_challenge()));
        assert!(!is_well_formed_challenge(""));
        assert!(!is_well_formed_challenge(&"a".repeat(63)));
        assert!(!is_well_formed_challenge(&"a".repeat(65)));
        assert!(!is_well_formed_challenge(&"A".repeat(64)));
        assert!(!is_well_formed_challenge(&format!("{}g", "a".repeat(63))));
        // A signed-object canonical presented as a "challenge" is refused.
        assert!(!is_well_formed_challenge("11:gc-grant-v1\n9:alice/foo\n"));
    }

    #[test]
    fn signing_payload_is_domain_framed_and_purpose_separated() {
        let c = generate_challenge();
        let login = challenge_signing_payload(ChallengePurpose::Login, &c).unwrap();
        assert_eq!(login, format!("16:gc-auth-login-v1\n64:{c}\n").into_bytes());
        let pop = challenge_signing_payload(ChallengePurpose::RegistrationProof, &c).unwrap();
        assert_eq!(pop, format!("27:gc-auth-registration-pop-v1\n64:{c}\n").into_bytes());
        assert_ne!(login, pop);
        assert!(matches!(
            challenge_signing_payload(ChallengePurpose::Login, "11:gc-grant-v1\n"),
            Err(PasskeyError::InvalidChallenge)
        ));
    }

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
