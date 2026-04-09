//! Authentication module for passkey-core
//!
//! Provides challenge-response authentication, signature verification,
//! machine ID derivation, and JWT token handling.
//!
//! # Authentication Model
//!
//! passkey-core uses Ed25519 keypairs for authentication:
//! 1. Server generates a random challenge
//! 2. Client signs the challenge with their private key
//! 3. Server verifies the signature with the client's public key
//!
//! This eliminates passwords entirely.

mod challenge;
mod machine_id;
mod verification;

#[cfg(feature = "jwt")]
pub mod jwt;

pub use challenge::*;
pub use machine_id::*;
pub use verification::*;

#[cfg(feature = "jwt")]
pub use jwt::{Claims, TokenPair, generate_access_token, generate_refresh_token,
              generate_token_pair, hash_refresh_token, validate_access_token};
