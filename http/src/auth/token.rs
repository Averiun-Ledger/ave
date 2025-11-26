use getrandom::fill;

/// Generates a unique API key in the format: ave_v1_<random_token>
///
/// The token is generated using cryptographically secure random bytes
/// and encoded in base64url format for URL safety.
pub fn generate_api_key() -> String {
    let mut bytes = [0u8; 32];
    fill(&mut bytes).expect("Failed to generate random bytes");

    // Use base64 URL-safe encoding (no padding)
    let token = base64_url_encode(&bytes);

    format!("ave_v1_{}", token)
}

/// Encodes bytes to base64 URL-safe format without padding
fn base64_url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::new();
    let mut i = 0;

    while i + 3 <= bytes.len() {
        let b1 = bytes[i];
        let b2 = bytes[i + 1];
        let b3 = bytes[i + 2];

        result.push(ALPHABET[(b1 >> 2) as usize] as char);
        result.push(ALPHABET[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
        result.push(ALPHABET[(((b2 & 0x0f) << 2) | (b3 >> 6)) as usize] as char);
        result.push(ALPHABET[(b3 & 0x3f) as usize] as char);

        i += 3;
    }

    // Handle remaining bytes
    match bytes.len() - i {
        1 => {
            let b1 = bytes[i];
            result.push(ALPHABET[(b1 >> 2) as usize] as char);
            result.push(ALPHABET[((b1 & 0x03) << 4) as usize] as char);
        }
        2 => {
            let b1 = bytes[i];
            let b2 = bytes[i + 1];
            result.push(ALPHABET[(b1 >> 2) as usize] as char);
            result.push(ALPHABET[(((b1 & 0x03) << 4) | (b2 >> 4)) as usize] as char);
            result.push(ALPHABET[((b2 & 0x0f) << 2) as usize] as char);
        }
        _ => {}
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key_format() {
        let key = generate_api_key();
        assert!(key.starts_with("ave_v1_"));
        // Should be approximately 50 characters (ave_v1_ + 43 chars base64)
        assert!(key.len() > 40 && key.len() < 60);
    }

    #[test]
    fn test_generate_api_key_uniqueness() {
        let key1 = generate_api_key();
        let key2 = generate_api_key();
        assert_ne!(key1, key2);
    }
}
