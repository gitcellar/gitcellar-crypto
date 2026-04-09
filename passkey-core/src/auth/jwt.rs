//! JWT token generation and validation
//!
//! Provides JWT token handling for applications that use token-based auth
//! in addition to PassKey authentication.

use crate::error::{PasskeyError, Result};
use crate::paths::JwtConfig;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use uuid::Uuid;

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// User email
    pub email: String,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
}

/// Token pair returned after authentication
#[derive(Debug, Clone, Serialize)]
pub struct TokenPair {
    /// JWT access token
    pub access_token: String,
    /// Refresh token (opaque, base64-encoded)
    pub refresh_token: String,
    /// Access token expiry in seconds
    pub expires_in: i64,
}

/// Generate a new access token
///
/// # Arguments
/// * `user_id` - The user's UUID
/// * `email` - The user's email address
/// * `config` - JWT configuration with secret and expiry
pub fn generate_access_token(
    user_id: Uuid,
    email: &str,
    config: &JwtConfig,
) -> Result<String> {
    let now = Utc::now();
    let exp = now + Duration::seconds(config.access_token_expiry_secs);

    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        iat: now.timestamp(),
        exp: exp.timestamp(),
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.secret.as_bytes()),
    )
    .map_err(|e| PasskeyError::Other(format!("Failed to generate token: {}", e)))
}

/// Generate a random refresh token
///
/// Returns a base64-encoded random token.
pub fn generate_refresh_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

/// Hash a refresh token for secure storage
///
/// Use this when storing refresh tokens in a database.
pub fn hash_refresh_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Validate an access token and extract claims
///
/// # Arguments
/// * `token` - The JWT access token to validate
/// * `config` - JWT configuration with secret
///
/// # Returns
/// The decoded claims if valid
pub fn validate_access_token(token: &str, config: &JwtConfig) -> Result<Claims> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| {
        match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => PasskeyError::TokenExpired,
            _ => PasskeyError::InvalidToken,
        }
    })?;

    Ok(token_data.claims)
}

/// Generate a complete token pair for a user
///
/// # Arguments
/// * `user_id` - The user's UUID
/// * `email` - The user's email address
/// * `config` - JWT configuration
pub fn generate_token_pair(
    user_id: Uuid,
    email: &str,
    config: &JwtConfig,
) -> Result<TokenPair> {
    let access_token = generate_access_token(user_id, email, config)?;
    let refresh_token = generate_refresh_token();

    Ok(TokenPair {
        access_token,
        refresh_token,
        expires_in: config.access_token_expiry_secs,
    })
}

/// Check if a token is expired without full validation
///
/// This is a quick check that doesn't verify the signature.
/// Note: This performs basic JWT parsing without signature verification.
pub fn is_token_expired(token: &str) -> bool {
    // Decode the payload without verifying signature
    match decode_token_parts(token) {
        Some(claims) => {
            let now = Utc::now().timestamp();
            claims.exp < now
        }
        None => true, // Treat invalid tokens as expired
    }
}

/// Extract the subject (user ID) from a token without validation
///
/// WARNING: This does not verify the token signature!
/// Only use for logging or non-security-critical purposes.
pub fn extract_subject_unsafe(token: &str) -> Option<String> {
    decode_token_parts(token).map(|claims| claims.sub)
}

/// Decode token payload without verification (for non-security-critical purposes)
fn decode_token_parts(token: &str) -> Option<Claims> {
    use base64::Engine;

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Decode payload (second part)
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;

    serde_json::from_slice(&payload).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> JwtConfig {
        JwtConfig::new("test-secret-key", 3600, 86400 * 30)
    }

    #[test]
    fn test_generate_access_token() {
        let config = test_config();
        let user_id = Uuid::new_v4();

        let token = generate_access_token(user_id, "test@example.com", &config).unwrap();

        // Token should be a valid JWT format (header.payload.signature)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_validate_access_token() {
        let config = test_config();
        let user_id = Uuid::new_v4();
        let email = "test@example.com";

        let token = generate_access_token(user_id, email, &config).unwrap();
        let claims = validate_access_token(&token, &config).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
    }

    #[test]
    fn test_validate_invalid_token() {
        let config = test_config();

        let result = validate_access_token("invalid.token.here", &config);
        assert!(matches!(result, Err(PasskeyError::InvalidToken)));
    }

    #[test]
    fn test_validate_wrong_secret() {
        let config1 = test_config();
        let config2 = JwtConfig::new("different-secret", 3600, 86400);
        let user_id = Uuid::new_v4();

        let token = generate_access_token(user_id, "test@example.com", &config1).unwrap();

        // Validation with wrong secret should fail
        let result = validate_access_token(&token, &config2);
        assert!(matches!(result, Err(PasskeyError::InvalidToken)));
    }

    #[test]
    fn test_generate_refresh_token() {
        let token1 = generate_refresh_token();
        let token2 = generate_refresh_token();

        // Should be URL-safe base64
        assert!(!token1.contains('+'));
        assert!(!token1.contains('/'));

        // Should be unique
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_hash_refresh_token() {
        let token = generate_refresh_token();
        let hash = hash_refresh_token(&token);

        // Hash should be 64 hex chars (SHA256)
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Same token should produce same hash
        assert_eq!(hash, hash_refresh_token(&token));
    }

    #[test]
    fn test_generate_token_pair() {
        let config = test_config();
        let user_id = Uuid::new_v4();

        let pair = generate_token_pair(user_id, "test@example.com", &config).unwrap();

        assert!(!pair.access_token.is_empty());
        assert!(!pair.refresh_token.is_empty());
        assert_eq!(pair.expires_in, 3600);
    }

    #[test]
    fn test_is_token_expired() {
        let config = test_config();
        let user_id = Uuid::new_v4();

        // Fresh token should not be expired
        let token = generate_access_token(user_id, "test@example.com", &config).unwrap();
        assert!(!is_token_expired(&token));

        // Invalid token should be treated as expired
        assert!(is_token_expired("invalid"));
    }

    #[test]
    fn test_extract_subject_unsafe() {
        let config = test_config();
        let user_id = Uuid::new_v4();

        let token = generate_access_token(user_id, "test@example.com", &config).unwrap();
        let subject = extract_subject_unsafe(&token);

        assert_eq!(subject, Some(user_id.to_string()));
    }
}
