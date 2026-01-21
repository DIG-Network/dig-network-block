//! Emission type and its root calculation.
//!
//! This file defines the standardized `Emission` record used in L2 block bodies
//! and provides a `calculate_root()` method that returns the per-emission hash
//! (leaf) using the CAPITALIZED spec functions from `dig_l2_definition`.

use crate::dig_l2_definition as definitions;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Standardized reward distribution record used in every L2 block.
///
/// The `pubkey` is a BLS public key (48 bytes), and `weight` is the relative
/// share in the reward pool. JSON encodes `pubkey` as a `0x`-prefixed hex
/// string, and `weight` as a number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Emission {
    /// BLS public key (48 bytes), serialized as `0x` hex in JSON.
    #[serde(with = "crate::serde_hex::hex48")]
    pub pubkey: [u8; 48],
    /// Relative share of reward pool.
    pub weight: u64,
}

impl Emission {
    /// Computes the per-emission hash as defined by the spec using
    /// `COMPUTE_EMISSION_HASH`. This value can serve directly as a leaf for
    /// inclusion in the emissions Merkle tree.
    pub fn calculate_root(&self) -> definitions::Hash32 {
        definitions::COMPUTE_EMISSION_HASH(&self.pubkey, self.weight)
    }
}

/// Errors originating from `Emission`-level operations.
#[derive(Debug, Error)]
pub enum EmissionError {
    /// Placeholder for future validation errors (kept to satisfy file-level error requirement).
    #[error("emission error: {0}")]
    Generic(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emission_hash_matches_definition() {
        let e = Emission {
            pubkey: [7u8; 48],
            weight: 42,
        };
        let h1 = e.calculate_root();
        let h2 = definitions::COMPUTE_EMISSION_HASH(&e.pubkey, e.weight);
        assert_eq!(h1, h2);
    }

    #[test]
    fn emission_json_round_trip() {
        let e = Emission {
            pubkey: [0x11u8; 48],
            weight: 9,
        };
        let s = serde_json::to_string(&e).unwrap();
        // Ensure pubkey serialized to string with 0x
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        let pk_str = v.get("pubkey").and_then(|x| x.as_str()).unwrap();
        assert!(pk_str.starts_with("0x"));
        assert_eq!(pk_str.len(), 2 + 48 * 2);
        let back: Emission = serde_json::from_str(&s).unwrap();
        assert_eq!(back, e);
    }
}
