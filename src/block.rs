//! L2 block: header and body, with delegated root calculation.
//!
//! `L2Block::calculate_root()` defers to `header.calculate_root()` and
//! `body.calculate_root()` and then composes them via `COMPUTE_BLOCK_ROOT`.
//!
//! Construction via `new` enforces invariants between header and body
//! (counts and body_root) and can surface `HeaderError`/`BodyError` via
//! transparent composition.

use crate::dig_l2_definition as definitions;
use crate::{body::L2BlockBody, emission::Emission, header::L2BlockHeader};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Full L2 block containing a header and a body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigL2Block {
    pub header: L2BlockHeader,
    pub body: L2BlockBody,
}

impl DigL2Block {
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
    pub fn new (
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
        Ok(DigL2Block { header, body })
    }

    /// Build a block from raw inputs, constructing required consensus emissions
    /// and composing header/body deterministically.
    ///
    /// Steps:
    /// - Validates the provided `ConsensusEmissionConfig` against the attester list.
    /// - Uses `BUILD_CONSENSUS_EMISSIONS` to create mandatory emissions (proposer + attesters).
    /// - Appends any `extra_emissions` provided by the caller.
    /// - Assembles the body from `data` and all emissions, computes `body_root`.
    /// - Fills header counts and `body_root`, leaving other header fields as provided.
    pub fn build(
        version: u32,
        network_id: [u8; 32],
        epoch: u64,
        prev_block_root: [u8; 32],
        proposer_pubkey: [u8; 48],
        data: Vec<u8>,
        extra_emissions: Vec<Emission>,
        attester_pubkeys: &[[u8; 48]],
        cfg: &crate::emission_config::ConsensusEmissionConfig,
    ) -> Result<Self, BlockError> {
        // Validate config with respect to the number of attesters
        cfg.validate_for_attesters(attester_pubkeys.len())?;

        // Build consensus emissions tuples then convert to Emission
        let tuples = definitions::BUILD_CONSENSUS_EMISSIONS(
            proposer_pubkey,
            attester_pubkeys,
            cfg.proposer_reward_share,
            cfg.attester_reward_share,
        )?;
        let mut emissions: Vec<Emission> = tuples
            .into_iter()
            .map(|(pk, w)| Emission { pubkey: pk, weight: w })
            .collect();
        emissions.extend(extra_emissions.into_iter());

        let body = L2BlockBody { data, emissions };
        let body_root = body.calculate_root();

        let header = L2BlockHeader {
            version,
            network_id,
            epoch,
            prev_block_root,
            body_root,
            data_count: body.data.len() as u32,
            emissions_count: body.emissions.len() as u32,
            proposer_pubkey,
        };

        Ok(DigL2Block { header, body })
    }
}

/// Errors that can be returned by `DigL2Block` construction/validation.
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

    /// Propagate definition-level errors (e.g., invalid attester share policy).
    #[error(transparent)]
    Definitions(#[from] crate::dig_l2_definition::DefinitionError),

    /// Propagate configuration errors.
    #[error(transparent)]
    Config(#[from] crate::emission_config::EmissionConfigError),
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
        let block = DigL2Block::new(header, body, Some(1)).unwrap();
        let h_root = block.header.calculate_root();
        let b_root = block.body.calculate_root();
        let expect = definitions::COMPUTE_BLOCK_ROOT(&h_root, &b_root);
        assert_eq!(block.calculate_root(), expect);
    }

    #[test]
    fn new_rejects_mismatched_counts() {
        let body = make_body();
        let mut header = make_header_for_body(&body);
        header.data_count += 1; // wrong
        let err = DigL2Block::new(header, body, Some(1)).unwrap_err();
        match err {
            BlockError::Header(crate::header::HeaderError::CountMismatch { .. }) => {}
            _ => panic!("unexpected error type"),
        }
    }

    #[test]
    fn new_rejects_body_root_mismatch() {
        let mut body = make_body();
        let mut header = make_header_for_body(&body);
        // change body so root no longer matches header
        body.data.push(4);
        let err = DigL2Block::new(header, body, Some(1)).unwrap_err();
        match err {
            BlockError::BodyRootMismatch { .. } => {}
            _ => panic!("unexpected error type"),
        }
    }

    #[test]
    fn build_block_with_attesters_and_extras() {
        let data = vec![1u8, 2, 3, 4];
        let extra = vec![Emission { pubkey: [0x33u8; 48], weight: 7 }];
        let attesters = vec![[0x11u8; 48], [0x22u8; 48], [0x44u8; 48]];
        let cfg = crate::emission_config::ConsensusEmissionConfig::new(12, 90);
        let block = DigL2Block::build(
            1,
            [9u8; 32],
            123,
            [8u8; 32],
            [7u8; 48],
            data,
            extra,
            &attesters,
            &cfg,
        )
        .unwrap();

        // Counts should reflect body lengths
        assert_eq!(block.header.data_count as usize, block.body.data.len());
        assert_eq!(block.header.emissions_count as usize, block.body.emissions.len());

        // Roots should be consistent
        let expect_body_root = block.body.calculate_root();
        assert_eq!(block.header.body_root, expect_body_root);

        // JSON round-trip of whole block
        let s = serde_json::to_string(&block).unwrap();
        let back: DigL2Block = serde_json::from_str(&s).unwrap();
        assert_eq!(block, back);
    }

    #[test]
    fn build_block_zero_attesters_policy() {
        let cfg = crate::emission_config::ConsensusEmissionConfig::new(12, 0);
        let b = DigL2Block::build(
            1,
            [0u8; 32],
            0,
            [0u8; 32],
            [1u8; 48],
            vec![],
            vec![],
            &[],
            &cfg,
        )
        .unwrap();
        assert_eq!(b.body.emissions.len(), 1); // proposer only

        // Now invalid: non-zero attester share but no attesters
        let cfg_bad = crate::emission_config::ConsensusEmissionConfig::new(12, 1);
        let err = DigL2Block::build(
            1,
            [0u8; 32],
            0,
            [0u8; 32],
            [1u8; 48],
            vec![],
            vec![],
            &[],
            &cfg_bad,
        )
        .unwrap_err();
        match err {
            BlockError::Config(crate::emission_config::EmissionConfigError::NonZeroAttesterShareWithNoAttesters) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
