//! Serde helpers to serialize/deserialize byte arrays/vectors as 0x-prefixed hex strings.
//!
//! - `hex_vec`: for `Vec<u8>` of any length.
//! - `hex32`: for `[u8; 32]` with exact length enforcement.
//! - `hex48`: for `[u8; 48]` with exact length enforcement.
//!
//! These helpers ensure strict `0x` prefix and lowercase hex encoding.

use serde::{Deserialize, Deserializer, Serializer};
use thiserror::Error;

/// Errors that can occur during hex (de)serialization.
#[derive(Debug, Error)]
pub enum HexSerdeError {
    /// Input string must begin with `0x` prefix.
    #[error("missing 0x prefix")]
    MissingPrefix,

    /// Input contained non-hex characters or odd-length digits.
    #[error("invalid hex encoding: {0}")]
    InvalidHex(String),

    /// For fixed-size arrays: decoded byte length did not match the expected size.
    #[error("length mismatch: expected {expected} bytes, got {actual} bytes")]
    LengthMismatch { expected: usize, actual: usize },
}

fn strip_0x(s: &str) -> Result<&str, HexSerdeError> {
    if let Some(rest) = s.strip_prefix("0x") {
        Ok(rest)
    } else {
        Err(HexSerdeError::MissingPrefix)
    }
}

fn encode_lower_hex_prefixed(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    out.push_str(&hex::encode(bytes));
    out
}

/// Serde helpers for `Vec<u8>` as 0x-hex.
pub mod hex_vec {
    use super::*;

    /// Serialize a `Vec<u8>` as an `"0x..."` lowercase hex string.
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = encode_lower_hex_prefixed(bytes);
        serializer.serialize_str(&s)
    }

    /// Deserialize a `Vec<u8>` from an `"0x..."` lowercase hex string.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        let hex_part = strip_0x(&s).map_err(|e| serde::de::Error::custom(e.to_string()))?;
        let bytes = hex::decode(hex_part).map_err(|e| {
            serde::de::Error::custom(HexSerdeError::InvalidHex(e.to_string()).to_string())
        })?;
        Ok(bytes)
    }
}

/// Serde helpers for `[u8; 32]` as 0x-hex.
pub mod hex32 {
    use super::*;

    /// Serialize a `[u8; 32]` as an `"0x..."` lowercase hex string.
    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = encode_lower_hex_prefixed(bytes);
        serializer.serialize_str(&s)
    }

    /// Deserialize a `[u8; 32]` from an `"0x..."` lowercase hex string.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        let hex_part = strip_0x(&s).map_err(|e| serde::de::Error::custom(e.to_string()))?;
        let bytes = hex::decode(hex_part).map_err(|e| {
            serde::de::Error::custom(HexSerdeError::InvalidHex(e.to_string()).to_string())
        })?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(
                HexSerdeError::LengthMismatch {
                    expected: 32,
                    actual: bytes.len(),
                }
                .to_string(),
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Serde helpers for `[u8; 48]` as 0x-hex.
pub mod hex48 {
    use super::*;

    /// Serialize a `[u8; 48]` as an `"0x..."` lowercase hex string.
    pub fn serialize<S>(bytes: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = encode_lower_hex_prefixed(bytes);
        serializer.serialize_str(&s)
    }

    /// Deserialize a `[u8; 48]` from an `"0x..."` lowercase hex string.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        let hex_part = strip_0x(&s).map_err(|e| serde::de::Error::custom(e.to_string()))?;
        let bytes = hex::decode(hex_part).map_err(|e| {
            serde::de::Error::custom(HexSerdeError::InvalidHex(e.to_string()).to_string())
        })?;
        if bytes.len() != 48 {
            return Err(serde::de::Error::custom(
                HexSerdeError::LengthMismatch {
                    expected: 48,
                    actual: bytes.len(),
                }
                .to_string(),
            ));
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {

    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct VecWrap(#[serde(with = "crate::serde_hex::hex_vec")] Vec<u8>);

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Arr32Wrap(#[serde(with = "crate::serde_hex::hex32")] [u8; 32]);

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Arr48Wrap(#[serde(with = "crate::serde_hex::hex48")] [u8; 48]);

    #[test]
    fn vec_round_trip() {
        let v = VecWrap(vec![0x00, 0x01, 0xaa, 0xff]);
        let s = serde_json::to_string(&v).unwrap();
        // Newtype struct serializes as inner value (a JSON string)
        assert_eq!(s, "\"0x0001aaff\"");
        let back: VecWrap = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn arr32_round_trip() {
        let mut a = [0u8; 32];
        a[0] = 0xde;
        a[31] = 0xad;
        let w = Arr32Wrap(a);
        let s = serde_json::to_string(&w).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let s_hex = v.as_str().unwrap();
        assert!(s_hex.starts_with("0x"));
        assert_eq!(s_hex.len(), 2 + 64);
        let back: Arr32Wrap = serde_json::from_str(&s).unwrap();
        assert_eq!(back, w);
    }

    #[test]
    fn arr48_round_trip() {
        let mut a = [0u8; 48];
        a[0] = 0x12;
        a[47] = 0x34;
        let w = Arr48Wrap(a);
        let s = serde_json::to_string(&w).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let s_hex = v.as_str().unwrap();
        assert!(s_hex.starts_with("0x"));
        assert_eq!(s_hex.len(), 2 + 96);
        let back: Arr48Wrap = serde_json::from_str(&s).unwrap();
        assert_eq!(back, w);
    }

    #[test]
    fn vec_rejects_missing_prefix() {
        let s = "\"deadbeef\""; // no 0x
        let err = serde_json::from_str::<VecWrap>(s).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("missing 0x prefix"));
    }

    #[test]
    fn arr32_wrong_length_rejected() {
        // 31 bytes (62 hex chars) with 0x
        let s = format!("\"0x{}\"", "00".repeat(31));
        let err = serde_json::from_str::<Arr32Wrap>(&s).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("length mismatch"));
    }

    #[test]
    fn arr48_wrong_length_rejected() {
        // 49 bytes
        let s = format!("\"0x{}\"", "ff".repeat(49));
        let err = serde_json::from_str::<Arr48Wrap>(&s).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("length mismatch"));
    }

    #[test]
    fn invalid_hex_char_rejected() {
        let s = "\"0xzz\""; // invalid hex
        let err = serde_json::from_str::<VecWrap>(s).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid hex encoding"));
    }
}
