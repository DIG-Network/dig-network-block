//! L2 block body: application data and standardized emissions.
//!
//! The body owns calculation of its `BODY_ROOT` by composing the two subroots:
//! - `DATA_ROOT`: Merkle root of per-byte data item hashes.
//! - `EMISSIONS_ROOT`: Merkle root of per-emission hashes.
//!
//! Both collections are sorted by their hash for determinism (sorting is done on
//! a local copy so `calculate_*` methods do not mutate the body).

use crate::dig_l2_definition as definitions;
use crate::emission::Emission;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Body of an L2 block: application data bytes and reward emissions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2BlockBody {
    /// Application-specific data bytes. Serialized as `0x`-prefixed hex string.
    #[serde(with = "crate::serde_hex::hex_vec")]
    pub data: Vec<u8>,
    /// Reward distribution records.
    pub emissions: Vec<Emission>,
}

impl L2BlockBody {
    /// Computes the `DATA_ROOT` as the Merkle root of `COMPUTE_DATA_HASH(byte)`
    /// for each `byte` in `self.data`, sorted by hash ascending for determinism.
    pub fn calculate_data_root(&self) -> definitions::Hash32 {
        let mut leaves: Vec<definitions::Hash32> = self
            .data
            .iter()
            .map(|b| definitions::COMPUTE_DATA_HASH(*b))
            .collect();
        leaves.sort_unstable();
        definitions::MERKLE_ROOT(&leaves)
    }

    /// Computes the `EMISSIONS_ROOT` as the Merkle root of each emission's
    /// per-item hash, sorted by hash ascending for determinism.
    pub fn calculate_emissions_root(&self) -> definitions::Hash32 {
        let mut leaves: Vec<definitions::Hash32> = self
            .emissions
            .iter()
            .map(|e| e.calculate_root())
            .collect();
        leaves.sort_unstable();
        definitions::MERKLE_ROOT(&leaves)
    }

    /// Computes the overall `BODY_ROOT` from the two subroots.
    pub fn calculate_root(&self) -> definitions::Hash32 {
        let d = self.calculate_data_root();
        let e = self.calculate_emissions_root();
        definitions::COMPUTE_BODY_ROOT(&d, &e)
    }
}

/// Errors that can be returned by body-level operations.
#[derive(Debug, Error)]
pub enum BodyError {
    /// Placeholder for future validation errors.
    #[error("body error: {0}")]
    Generic(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emission::Emission;

    #[test]
    fn data_root_does_not_depend_on_input_order() {
        let b1 = L2BlockBody { data: vec![3, 1, 2], emissions: vec![] };
        let b2 = L2BlockBody { data: vec![2, 3, 1], emissions: vec![] };
        assert_eq!(b1.calculate_data_root(), b2.calculate_data_root());
    }

    #[test]
    fn emissions_root_does_not_depend_on_input_order() {
        let e1 = Emission { pubkey: [1u8; 48], weight: 5 };
        let e2 = Emission { pubkey: [2u8; 48], weight: 5 };
        let e3 = Emission { pubkey: [3u8; 48], weight: 6 };
        let b1 = L2BlockBody { data: vec![], emissions: vec![e1.clone(), e2.clone(), e3.clone()] };
        let b2 = L2BlockBody { data: vec![], emissions: vec![e3, e1, e2] };
        assert_eq!(b1.calculate_emissions_root(), b2.calculate_emissions_root());
    }

    #[test]
    fn body_root_changes_when_subroots_change() {
        let e = Emission { pubkey: [9u8; 48], weight: 1 };
        let b1 = L2BlockBody { data: vec![1, 2], emissions: vec![e.clone()] };
        let b2 = L2BlockBody { data: vec![1], emissions: vec![e] };
        assert_ne!(b1.calculate_root(), b2.calculate_root());
    }
}
