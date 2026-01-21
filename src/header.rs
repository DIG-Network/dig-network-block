//! L2 block header: metadata and commitments to the body.
//!
//! The header owns calculation of its `HEADER_ROOT`, which is a Merkle root of
//! individually domain-separated header fields. This allows proving single
//! fields against the overall `BLOCK_ROOT` without revealing the entire header.

use crate::dig_l2_definition as definitions;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Header for an L2 block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2BlockHeader {
    /// Block version; must match network consensus version.
    pub version: u32,
    /// Network ID (32 bytes), serialized as `0x` hex.
    #[serde(with = "crate::serde_hex::hex32")]
    pub network_id: [u8; 32],
    /// Epoch number.
    pub epoch: u64,
    /// Previous block root (32 bytes), serialized as `0x` hex.
    #[serde(with = "crate::serde_hex::hex32")]
    pub prev_block_root: [u8; 32],
    /// Body root (32 bytes), serialized as `0x` hex.
    #[serde(with = "crate::serde_hex::hex32")]
    pub body_root: [u8; 32],
    /// Count of data items (bytes) in the body.
    pub data_count: u32,
    /// Count of emissions in the body.
    pub emissions_count: u32,
    /// Proposer public key (48 bytes), serialized as `0x` hex.
    #[serde(with = "crate::serde_hex::hex48")]
    pub proposer_pubkey: [u8; 48],
}

impl L2BlockHeader {
    /// Calculates the `HEADER_ROOT` using the spec function.
    pub fn calculate_root(&self) -> definitions::Hash32 {
        definitions::COMPUTE_HEADER_ROOT(
            self.version,
            &self.network_id,
            self.epoch,
            &self.prev_block_root,
            &self.body_root,
            self.data_count,
            self.emissions_count,
            &self.proposer_pubkey,
        )
    }

    /// Validates that the header version matches the expected consensus version.
    pub fn validate_version(&self, expected_version: u32) -> Result<(), HeaderError> {
        if self.version != expected_version {
            return Err(HeaderError::VersionMismatch {
                expected: expected_version,
                found: self.version,
            });
        }
        Ok(())
    }

    /// Validates that `data_count` and `emissions_count` match the provided body lengths.
    pub fn validate_counts(&self, data_len: usize, emissions_len: usize) -> Result<(), HeaderError> {
        if self.data_count as usize != data_len {
            return Err(HeaderError::CountMismatch {
                field: "data_count",
                expected: self.data_count as usize,
                actual: data_len,
            });
        }
        if self.emissions_count as usize != emissions_len {
            return Err(HeaderError::CountMismatch {
                field: "emissions_count",
                expected: self.emissions_count as usize,
                actual: emissions_len,
            });
        }
        Ok(())
    }
}

/// Errors that can be emitted by header-level validation or operations.
#[derive(Debug, Error)]
pub enum HeaderError {
    /// Header version does not match expected network consensus version.
    #[error("version mismatch: expected {expected}, found {found}")]
    VersionMismatch { expected: u32, found: u32 },

    /// A header item count did not match the body lengths.
    #[error("{field} mismatch: header has {expected}, body has {actual}")]
    CountMismatch { field: &'static str, expected: usize, actual: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> L2BlockHeader {
        L2BlockHeader {
            version: 1,
            network_id: [1u8; 32],
            epoch: 10,
            prev_block_root: [2u8; 32],
            body_root: [3u8; 32],
            data_count: 2,
            emissions_count: 1,
            proposer_pubkey: [9u8; 48],
        }
    }

    #[test]
    fn header_root_changes_when_field_changes() {
        let mut h1 = sample_header();
        let mut h2 = sample_header();
        assert_eq!(h1.calculate_root(), h2.calculate_root());
        h2.data_count = 3;
        assert_ne!(h1.calculate_root(), h2.calculate_root());
    }

    #[test]
    fn version_validation() {
        let h = sample_header();
        assert!(h.validate_version(1).is_ok());
        let e = h.validate_version(2).unwrap_err();
        match e {
            HeaderError::VersionMismatch { expected, found } => {
                assert_eq!(expected, 2);
                assert_eq!(found, 1);
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn counts_validation() {
        let h = sample_header();
        assert!(h.validate_counts(2, 1).is_ok());
        let e = h.validate_counts(1, 1).unwrap_err();
        match e {
            HeaderError::CountMismatch { field, expected, actual } => {
                assert_eq!(field, "data_count");
                assert_eq!(expected, 2);
                assert_eq!(actual, 1);
            }
            _ => panic!("unexpected error variant"),
        }
    }
}
