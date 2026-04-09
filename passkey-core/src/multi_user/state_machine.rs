//! Identity state machine
//!
//! Evaluates the current identity configuration and determines the state.
//! This is used by applications to decide what UI to show (onboarding, user selection, etc.)
//!
//! # Clean Slate Design
//!
//! All states use the multi-user directory structure (`users/{username}/identity/`).
//! There are no legacy/fallback paths.

use crate::multi_user::{get_active_user, list_users, user_has_identity};
use crate::paths::PasskeyConfig;

/// Identity state machine states
///
/// Represents all possible identity configuration states.
/// Applications use this to determine what UI/action is needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityState {
    /// No identity files exist - show onboarding
    NoIdentity,

    /// One user exists and is active, ready to go
    Ready {
        /// The active username
        username: String,
    },

    /// Multiple users exist, one is active
    ReadyMultiUser {
        /// The active username
        active_user: String,
        /// All available usernames
        users: Vec<String>,
    },

    /// Users exist but none is active - must select
    NeedsUserSelection {
        /// Available usernames to choose from
        users: Vec<String>,
    },

    /// Active user file points to non-existent user
    ActiveUserMissing {
        /// The claimed (non-existent) username
        claimed: String,
        /// Available usernames
        available: Vec<String>,
    },

    /// Identity files are corrupted or in an invalid state
    Corrupted {
        /// Description of what's wrong
        reason: String,
    },
}

impl IdentityState {
    /// Check if the state represents a ready/usable identity
    pub fn is_ready(&self) -> bool {
        matches!(self, IdentityState::Ready { .. } | IdentityState::ReadyMultiUser { .. })
    }

    /// Check if the state requires user action
    pub fn needs_action(&self) -> bool {
        matches!(
            self,
            IdentityState::NoIdentity
                | IdentityState::NeedsUserSelection { .. }
                | IdentityState::ActiveUserMissing { .. }
                | IdentityState::Corrupted { .. }
        )
    }

    /// Get the active username if in a ready state
    pub fn active_username(&self) -> Option<&str> {
        match self {
            IdentityState::Ready { username } => Some(username),
            IdentityState::ReadyMultiUser { active_user, .. } => Some(active_user),
            _ => None,
        }
    }

    /// Get all available users
    pub fn available_users(&self) -> Vec<&str> {
        match self {
            IdentityState::Ready { username } => vec![username.as_str()],
            IdentityState::ReadyMultiUser { users, .. } => users.iter().map(|s| s.as_str()).collect(),
            IdentityState::NeedsUserSelection { users } => users.iter().map(|s| s.as_str()).collect(),
            IdentityState::ActiveUserMissing { available, .. } => available.iter().map(|s| s.as_str()).collect(),
            _ => vec![],
        }
    }
}

/// Evaluate the current identity state
///
/// Examines the filesystem to determine the current state of identity configuration.
/// This is the primary entry point for applications to check identity status.
pub fn evaluate_state(config: &PasskeyConfig) -> IdentityState {
    // Get list of users
    let users = list_users(config);

    // Filter to users that actually have identity files
    let users_with_identity: Vec<String> = users
        .into_iter()
        .filter(|u| user_has_identity(config, u))
        .collect();

    if users_with_identity.is_empty() {
        return IdentityState::NoIdentity;
    }

    // Check active user
    let active_user = get_active_user(config);

    match active_user {
        None => {
            // No active user set
            if users_with_identity.len() == 1 {
                // Single user but not set as active - auto-select would be reasonable
                // but we return NeedsUserSelection to be explicit
                IdentityState::NeedsUserSelection {
                    users: users_with_identity,
                }
            } else {
                IdentityState::NeedsUserSelection {
                    users: users_with_identity,
                }
            }
        }
        Some(username) => {
            // Check if active user exists in our list
            if users_with_identity.contains(&username) {
                if users_with_identity.len() == 1 {
                    IdentityState::Ready { username }
                } else {
                    IdentityState::ReadyMultiUser {
                        active_user: username,
                        users: users_with_identity,
                    }
                }
            } else {
                // Active user file points to non-existent user
                IdentityState::ActiveUserMissing {
                    claimed: username,
                    available: users_with_identity,
                }
            }
        }
    }
}

/// Repair common identity state issues
///
/// Attempts to fix issues like:
/// - Single user not set as active
/// - Active user pointing to non-existent user
///
/// Returns the new state after repair.
pub fn repair_state(config: &PasskeyConfig) -> crate::error::Result<IdentityState> {
    use crate::multi_user::set_active_user;

    let state = evaluate_state(config);

    match &state {
        IdentityState::NeedsUserSelection { users } if users.len() == 1 => {
            // Single user but not active - set them as active
            set_active_user(config, &users[0])?;
            Ok(IdentityState::Ready {
                username: users[0].clone(),
            })
        }
        IdentityState::ActiveUserMissing { available, .. } if available.len() == 1 => {
            // Active user missing but only one available - set it
            set_active_user(config, &available[0])?;
            Ok(IdentityState::Ready {
                username: available[0].clone(),
            })
        }
        IdentityState::ActiveUserMissing { available, .. } if !available.is_empty() => {
            // Active user missing with multiple available - just return NeedsUserSelection
            Ok(IdentityState::NeedsUserSelection {
                users: available.clone(),
            })
        }
        // No repair needed or possible
        _ => Ok(state),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi_user::{create_user, set_active_user};
    use crate::Identity;
    use tempfile::TempDir;

    fn test_config(temp_dir: &TempDir) -> PasskeyConfig {
        PasskeyConfig::new("test")
            .with_config_dir(temp_dir.path().to_path_buf())
    }

    fn create_user_with_identity(config: &PasskeyConfig, username: &str) {
        create_user(config, username).unwrap();
        let identity = Identity::generate(&format!("{}@example.com", username)).unwrap();
        identity.save_for_user(config, username).unwrap();
    }

    #[test]
    fn test_no_identity() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        let state = evaluate_state(&config);
        assert_eq!(state, IdentityState::NoIdentity);
        assert!(!state.is_ready());
        assert!(state.needs_action());
    }

    #[test]
    fn test_single_user_ready() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        create_user_with_identity(&config, "alice");
        set_active_user(&config, "alice").unwrap();

        let state = evaluate_state(&config);
        assert!(matches!(&state, IdentityState::Ready { username } if username == "alice"));
        assert!(state.is_ready());
        assert!(!state.needs_action());
        assert_eq!(state.active_username(), Some("alice"));
    }

    #[test]
    fn test_multi_user_ready() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        create_user_with_identity(&config, "alice");
        create_user_with_identity(&config, "bob");
        set_active_user(&config, "alice").unwrap();

        let state = evaluate_state(&config);
        assert!(matches!(
            &state,
            IdentityState::ReadyMultiUser { active_user, users }
                if active_user == "alice" && users.len() == 2
        ));
        assert!(state.is_ready());
    }

    #[test]
    fn test_needs_user_selection() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        create_user_with_identity(&config, "alice");
        create_user_with_identity(&config, "bob");
        // No active user set

        let state = evaluate_state(&config);
        assert!(matches!(
            &state,
            IdentityState::NeedsUserSelection { users } if users.len() == 2
        ));
        assert!(!state.is_ready());
        assert!(state.needs_action());
    }

    #[test]
    fn test_active_user_missing() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        create_user_with_identity(&config, "alice");
        set_active_user(&config, "bob").unwrap(); // Bob doesn't exist

        let state = evaluate_state(&config);
        assert!(matches!(
            &state,
            IdentityState::ActiveUserMissing { claimed, available }
                if claimed == "bob" && available == &vec!["alice".to_string()]
        ));
    }

    #[test]
    fn test_repair_single_user() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        create_user_with_identity(&config, "alice");
        // No active user set

        let initial = evaluate_state(&config);
        assert!(matches!(initial, IdentityState::NeedsUserSelection { .. }));

        let repaired = repair_state(&config).unwrap();
        assert!(matches!(repaired, IdentityState::Ready { username } if username == "alice"));
    }

    #[test]
    fn test_repair_active_missing() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        create_user_with_identity(&config, "alice");
        set_active_user(&config, "nonexistent").unwrap();

        let initial = evaluate_state(&config);
        assert!(matches!(initial, IdentityState::ActiveUserMissing { .. }));

        let repaired = repair_state(&config).unwrap();
        assert!(matches!(repaired, IdentityState::Ready { username } if username == "alice"));
    }

    #[test]
    fn test_available_users() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        create_user_with_identity(&config, "alice");
        create_user_with_identity(&config, "bob");
        set_active_user(&config, "alice").unwrap();

        let state = evaluate_state(&config);
        let users = state.available_users();
        assert!(users.contains(&"alice"));
        assert!(users.contains(&"bob"));
    }

    #[test]
    fn test_users_without_identity_ignored() {
        let temp_dir = TempDir::new().unwrap();
        let config = test_config(&temp_dir);

        // Create alice with identity
        create_user_with_identity(&config, "alice");

        // Create bob without identity (just the directory)
        create_user(&config, "bob").unwrap();

        set_active_user(&config, "alice").unwrap();

        let state = evaluate_state(&config);
        // Should only see alice, not bob (no identity)
        let users = state.available_users();
        assert_eq!(users, vec!["alice"]);
    }
}
