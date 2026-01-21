//! L2 block: header and body, with delegated root calculation.
//!
//! `L2Block::calculate_root()` defers to `header.calculate_root()` and
//! `body.calculate_root()` and then composes them via `COMPUTE_BLOCK_ROOT`.
//!
//! Construction via `from_parts` enforces invariants between header and body
//! (counts and body_root) and can surface `HeaderError`/`BodyError` via
//! transparent composition.

use crate::dig_l2_definition as definitions;
use crate::{body::L2BlockBody, header::L2BlockHeader};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Full L2 block containing a header and a body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2Block {
    pub header: L2BlockHeader,
    pub body: L2BlockBody,
}

impl L2Block {
    /// Calculates the `BLOCK_ROOT` by composing the `HEADER_ROOT` and `BODY_ROOT`.
    pub fn calculate_root(&self) -> definitions::Hash32 {
        let header_root = self.header.calculate_root();
        let body_root = self.body.calculate_root();
        definitions::COMPUTE_BLOCK_ROOT(&header_root, &body_root)
    }

    /// Validates consistency between `header` and `body` and returns a block if valid.
    ///
    /// Checks:
    /// - `data_count` and `emissions_count` match body lengths.
    /// - `header.body_root` equals `body.calculate_root()`.
    /// - If `expected_version` is provided, header version matches it.
    pub fn from_parts(
        header: L2BlockHeader,
        body: L2BlockBody,
        expected_version: Option<u32>,
    ) -> Result<Self, BlockError> {
        if let Some(v) = expected_version {
            header.validate_version(v)?;
        }
        // Compare roots first so that a mutated body triggers BodyRootMismatch
        // which is typically the more informative error than counts mismatch.
        let calc_body_root = body.calculate_root();
        if header.body_root != calc_body_root {
            return Err(BlockError::BodyRootMismatch {
                header_body_root: header.body_root,
                calculated: calc_body_root,
            });
        }
        // Then validate counts for completeness.
        header.validate_counts(body.data.len(), body.emissions.len())?;
        Ok(L2Block { header, body })
    }
}

/// Errors that can be returned by `L2Block` construction/validation.
#[derive(Debug, Error)]
pub enum BlockError {
    /// Propagate header-level validation errors transparently.
    #[error(transparent)]
    Header(#[from] crate::header::HeaderError),

    /// Propagate body-level errors transparently (not currently used, reserved for future checks).
    #[error(transparent)]
    Body(#[from] crate::body::BodyError),

    /// The header's `body_root` does not match the calculated body root.
    #[error("body_root mismatch: header {header_body_root:?} != calculated {calculated:?}")]
    BodyRootMismatch { header_body_root: [u8; 32], calculated: [u8; 32] },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emission::Emission;

    fn make_body() -> L2BlockBody {
        L2BlockBody { data: vec![1, 2, 3], emissions: vec![Emission { pubkey: [5u8; 48], weight: 10 }] }
    }

    fn make_header_for_body(body: &L2BlockBody) -> L2BlockHeader {
        let body_root = body.calculate_root();
        L2BlockHeader {
            version: 1,
            network_id: [0xabu8; 32],
            epoch: 7,
            prev_block_root: [0u8; 32],
            body_root,
            data_count: body.data.len() as u32,
            emissions_count: body.emissions.len() as u32,
            proposer_pubkey: [9u8; 48],
        }
    }

    #[test]
    fn block_root_composition_matches_definitions() {
        let body = make_body();
        let header = make_header_for_body(&body);
        let block = L2Block::from_parts(header, body, Some(1)).unwrap();
        let h_root = block.header.calculate_root();
        let b_root = block.body.calculate_root();
        let expect = definitions::COMPUTE_BLOCK_ROOT(&h_root, &b_root);
        assert_eq!(block.calculate_root(), expect);
    }

    #[test]
    fn from_parts_rejects_mismatched_counts() {
        let body = make_body();
        let mut header = make_header_for_body(&body);
        header.data_count += 1; // wrong
        let err = L2Block::from_parts(header, body, Some(1)).unwrap_err();
        match err {
            BlockError::Header(crate::header::HeaderError::CountMismatch { .. }) => {}
            _ => panic!("unexpected error type"),
        }
    }

    #[test]
    fn from_parts_rejects_body_root_mismatch() {
        let mut body = make_body();
        let mut header = make_header_for_body(&body);
        // change body so root no longer matches header
        body.data.push(4);
        let err = L2Block::from_parts(header, body, Some(1)).unwrap_err();
        match err {
            BlockError::BodyRootMismatch { .. } => {}
            _ => panic!("unexpected error type"),
        }
    }
}
