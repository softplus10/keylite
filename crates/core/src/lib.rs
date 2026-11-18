use serde::{Deserialize, Serialize};

pub const MAX_BLOB_BYTES: usize = 1024 * 1024;
pub const MAX_HISTORY: i64 = 5;

pub fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn etag(hash: &str) -> String {
    format!("\"blake3:{hash}\"")
}

pub fn matches_precondition(if_match: &str, head_hash: Option<&str>) -> bool {
    match head_hash {
        None => if_match.trim() == "*",
        Some(hash) => if_match.trim() == etag(hash),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Head {
    pub revision: i64,
    pub hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Revision {
    pub revision: i64,
    pub hash: String,
    pub size: i64,
    pub created_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_test_vector() {
        assert_eq!(digest(b""), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    }

    #[test]
    fn first_write_requires_star() {
        assert!(matches_precondition("*", None));
        assert!(!matches_precondition("\"something\"", None));
        let hash = digest(b"vault");
        assert!(matches_precondition(&etag(&hash), Some(&hash)));
        assert!(!matches_precondition("*", Some(&hash)));
    }
}
