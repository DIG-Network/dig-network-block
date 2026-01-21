//! Consensus emission configuration.
//!
//! This module defines `ConsensusEmissionConfig`, which controls how proposer
//! and attester reward weights are assigned when building required consensus
//! emissions for a block.
//!
//! Validation helpers ensure obvious configuration mistakes are surfaced (e.g.,
//! non-zero attester share with zero attesters).

use thiserror::Error;

/// Configuration for consensus emissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusEmissionConfig {
    /// Fixed proposer share (e.g., 12 for 12.5%).
    pub proposer_reward_share: u64,
    /// Total attester share that will be equally split among attesters using
    /// integer division; remainder (if any) is undistributed.
    pub attester_reward_share: u64,
}

impl ConsensusEmissionConfig {
    /// Create a new config.
    pub fn new(proposer_reward_share: u64, attester_reward_share: u64) -> Self {
        Self {
            proposer_reward_share,
            attester_reward_share,
        }
    }

    /// Validate the config against a given number of attesters.
    ///
    /// Policy: if there are zero attesters, `attester_reward_share` must be 0;
    /// otherwise the split would be undefined.
    pub fn validate_for_attesters(&self, attesters_len: usize) -> Result<(), EmissionConfigError> {
        if attesters_len == 0 && self.attester_reward_share > 0 {
            return Err(EmissionConfigError::NonZeroAttesterShareWithNoAttesters);
        }
        Ok(())
    }
}

/// Errors that can be produced by configuration validation.
#[derive(Debug, Error)]
pub enum EmissionConfigError {
    /// `attester_reward_share > 0` while there are zero attesters.
    #[error("non-zero attester share configured but no attesters provided")]
    NonZeroAttesterShareWithNoAttesters,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_zero_attesters_policy() {
        let cfg = ConsensusEmissionConfig::new(12, 0);
        assert!(cfg.validate_for_attesters(0).is_ok());

        let cfg_bad = ConsensusEmissionConfig::new(12, 1);
        let err = cfg_bad.validate_for_attesters(0).unwrap_err();
        match err {
            EmissionConfigError::NonZeroAttesterShareWithNoAttesters => {}
        }
    }

    #[test]
    fn validate_with_attesters_ok() {
        let cfg = ConsensusEmissionConfig::new(12, 88);
        assert!(cfg.validate_for_attesters(3).is_ok());
    }
}
