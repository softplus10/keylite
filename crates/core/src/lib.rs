use serde::{Deserialize, Serialize};

pub const MAX_BLOB_BYTES: usize = 8 * 1024 * 1024;
pub const CHUNK_BYTES: usize = 512 * 1024;
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


// Account numbers are high-entropy bearer credentials, not public identifiers.
// Five groups of eight hexadecimal digits encode 160 bits of material.
// Two independently generated UUIDv4 values provide 152 random bits in this prefix.
pub fn generate_account_number(first: &str, second: &str) -> String {
    let hex = format!("{first}{second}").replace('-', "").to_ascii_uppercase();
    let chars: String = hex.chars().take(40).collect();
    (0..5).map(|i| chars[i * 8..(i + 1) * 8].to_owned())
        .collect::<Vec<_>>().join("-")
}

pub fn normalize_account_number(input: &str) -> Option<String> {
    let value: String = input.chars().filter(|c| *c != '-' && *c != ' ')
        .collect::<String>().to_ascii_uppercase();
    if value.len() != 40 || !value.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(value)
}

pub fn account_digest(normalized: &str) -> String {
    digest(format!("keylite-account-v1:{normalized}").as_bytes())
}

#[cfg(test)]
mod account_tests {
    use super::*;
    #[test]
    fn normalize_and_hash() {
        let a = generate_account_number(
            "ad9bd93f-9d3a-4b03-b25f-18bb45b3b87b",
            "bb8f884b-6b15-4691-b5c4-a6cf06b6d53a"
        );
        assert_eq!(a.replace('-', "").len(), 40);
        assert_eq!(normalize_account_number(&a).unwrap().len(), 40);
        assert!(normalize_account_number("not-an-account").is_none());
        assert_ne!(account_digest(&normalize_account_number(&a).unwrap()), digest(a.as_bytes()));
    }
}
