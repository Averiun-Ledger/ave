use super::token::generate_api_key;

/// In-memory authentication store
///
/// Stores a single user's credentials and their active API key.
/// The API key persists across login attempts and is only reset on node restart.
pub struct AuthStore {
    username: String,
    password: String,
    active_key: Option<String>,
}

impl AuthStore {
    /// Creates a new AuthStore with the given credentials
    pub fn new(username: String, password: String) -> Self {
        Self {
            username,
            password,
            active_key: None,
        }
    }

    /// Validates credentials and returns the API key
    ///
    /// If credentials are valid:
    /// - Returns existing API key if one exists
    /// - Generates and stores a new API key if none exists
    ///
    /// If credentials are invalid, returns None
    pub fn login(&mut self, username: &str, password: &str) -> Option<String> {
        if username != self.username || password != self.password {
            return None;
        }

        // If there's already an active key, reuse it
        if let Some(ref key) = self.active_key {
            return Some(key.clone());
        }

        // Generate a new key and store it
        let new_key = generate_api_key();
        self.active_key = Some(new_key.clone());
        Some(new_key)
    }

    /// Validates that the provided API key matches the active key
    pub fn validate_key(&self, key: &str) -> bool {
        match &self.active_key {
            Some(active) => active == key,
            None => false,
        }
    }

    /// Returns the current active API key if one exists
    #[allow(dead_code)]
    pub fn get_active_key(&self) -> Option<&String> {
        self.active_key.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_success() {
        let mut store = AuthStore::new("admin".to_string(), "password".to_string());
        let key = store.login("admin", "password");
        assert!(key.is_some());
    }

    #[test]
    fn test_login_failure() {
        let mut store = AuthStore::new("admin".to_string(), "password".to_string());
        let key = store.login("admin", "wrongpassword");
        assert!(key.is_none());
    }

    #[test]
    fn test_login_reuses_key() {
        let mut store = AuthStore::new("admin".to_string(), "password".to_string());
        let key1 = store.login("admin", "password").unwrap();
        let key2 = store.login("admin", "password").unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_validate_key() {
        let mut store = AuthStore::new("admin".to_string(), "password".to_string());
        let key = store.login("admin", "password").unwrap();
        assert!(store.validate_key(&key));
        assert!(!store.validate_key("invalid_key"));
    }
}
