//! CAPITALIZED spec functions and hashing domains for the L2 block.
//!
//! This module centralizes the specification-defined functions so they can be
//! imported and used by the concrete types (`header`, `body`, `block`, etc.).
//!
//! Contents:
//! - Domain constants used for SHA-256 domain separation
//! - `COMPUTE_DATA_HASH`
//! - `COMPUTE_EMISSION_HASH`
//! - `MERKLE_ROOT`
//! - `COMPUTE_BODY_ROOT`
//! - `COMPUTE_HEADER_ROOT`
//! - `COMPUTE_BLOCK_ROOT`
//! - `BUILD_CONSENSUS_EMISSIONS` (returns simple tuples for later conversion)
//!
//! All functions are deterministic and documented. Merkle construction uses
//! classic odd-leaf duplication and distinct leaf/node domains.

#![allow(non_snake_case)]

use crate::header::L2BlockHeader;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// 32-byte hash type used across the spec.
pub type Hash32 = [u8; 32];

/// Domain separation for individual header fields.
pub const HEADER_FIELD_DOMAIN: &[u8] = b"dig:l2:header_field:";
/// Domain separation for the block root composition.
pub const BLOCK_ROOT_DOMAIN: &[u8] = b"dig:l2:block_root:";
/// Domain separation for application data items (single byte per spec here).
pub const DATA_HASH_DOMAIN: &[u8] = b"dig:l2:data:";
/// Domain separation for standardized emissions.
pub const EMISSION_HASH_DOMAIN: &[u8] = b"dig:l2:emission:";
/// Domain separation for Merkle leaf nodes.
pub const MERKLE_LEAF_DOMAIN: &[u8] = b"dig:l2:merkle:leaf:";
/// Domain separation for Merkle internal nodes.
pub const MERKLE_NODE_DOMAIN: &[u8] = b"dig:l2:merkle:node:";
/// Domain for the empty Merkle root.
pub const MERKLE_EMPTY_DOMAIN: &[u8] = b"dig:l2:merkle:empty:";

/// Errors for definition-level functions.
#[derive(Debug, Error)]
pub enum DefinitionError {
    /// Attempted to assign non-zero attester share with zero attesters; division is undefined.
    #[error("attester_reward_share is non-zero but no attesters provided")]
    NoAttestersForNonZeroShare,
}

fn sha256_concat(parts: &[&[u8]]) -> Hash32 {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update(p);
    }
    hasher.finalize().into()
}

/// Compute the hash for a single data item (a single byte for this chain).
///
/// Per spec: `SHA256(DATA_HASH_DOMAIN || item.data)`.
pub fn COMPUTE_DATA_HASH(data_byte: u8) -> Hash32 {
    let b = [data_byte];
    sha256_concat(&[DATA_HASH_DOMAIN, &b])
}

/// Compute the hash for a single emission.
///
/// Per spec: `SHA256(EMISSION_HASH_DOMAIN || emission.pubkey || emission.weight_le)`.
pub fn COMPUTE_EMISSION_HASH(pubkey: &[u8; 48], weight: u64) -> Hash32 {
    let w = weight.to_le_bytes();
    sha256_concat(&[EMISSION_HASH_DOMAIN, pubkey, &w])
}

/// Compute a Merkle root from a slice of leaves.
///
/// - Leaves are first converted to domain-separated leaf nodes: `H = SHA256(MERKLE_LEAF_DOMAIN || leaf)`
/// - Internal nodes are `SHA256(MERKLE_NODE_DOMAIN || left || right)`
/// - Odd number of nodes duplicates the last one to make a pair.
/// - Empty slice returns `SHA256(MERKLE_EMPTY_DOMAIN)`.
pub fn MERKLE_ROOT(leaves: &[Hash32]) -> Hash32 {
    if leaves.is_empty() {
        return sha256_concat(&[MERKLE_EMPTY_DOMAIN]);
    }

    let mut level: Vec<Hash32> = leaves
        .iter()
        .map(|leaf| sha256_concat(&[MERKLE_LEAF_DOMAIN, leaf]))
        .collect();

    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = *level.last().unwrap();
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let combined = sha256_concat(&[MERKLE_NODE_DOMAIN, &pair[0], &pair[1]]);
            next.push(combined);
        }
        level = next;
    }
    level[0]
}

/// Compute the body root from the two subroots `DATA_ROOT` and `EMISSIONS_ROOT`.
///
/// Implemented as a 2-leaf Merkle root of `[data_root, emissions_root]`.
pub fn COMPUTE_BODY_ROOT(data_root: &Hash32, emissions_root: &Hash32) -> Hash32 {
    MERKLE_ROOT(&[*data_root, *emissions_root])
}

/// Compute the header root from individual header fields, allowing proofs of each field.
///
/// Instead of taking a header struct (to avoid module coupling), we accept individual fields.
/// The field label is included literally to avoid positional ambiguity.
pub fn COMPUTE_HEADER_ROOT(args: &L2BlockHeader) -> Hash32 {
    let v_bytes = args.version.to_le_bytes();
    let e_bytes = args.epoch.to_le_bytes();
    let dc_bytes = args.data_count.to_le_bytes();
    let ec_bytes = args.emissions_count.to_le_bytes();

    let leaves: [Hash32; 8] = [
        sha256_concat(&[HEADER_FIELD_DOMAIN, b"version", &v_bytes]),
        sha256_concat(&[HEADER_FIELD_DOMAIN, b"network_id", &args.network_id]),
        sha256_concat(&[HEADER_FIELD_DOMAIN, b"epoch", &e_bytes]),
        sha256_concat(&[
            HEADER_FIELD_DOMAIN,
            b"prev_block_root",
            &args.prev_block_root,
        ]),
        sha256_concat(&[HEADER_FIELD_DOMAIN, b"body_root", &args.body_root]),
        sha256_concat(&[HEADER_FIELD_DOMAIN, b"data_count", &dc_bytes]),
        sha256_concat(&[HEADER_FIELD_DOMAIN, b"emissions_count", &ec_bytes]),
        sha256_concat(&[
            HEADER_FIELD_DOMAIN,
            b"proposer_pubkey",
            &args.proposer_pubkey,
        ]),
    ];
    MERKLE_ROOT(&leaves)
}

/// Compute the block root from `HEADER_ROOT` and `BODY_ROOT`.
///
/// Per spec: `SHA256(BLOCK_ROOT_DOMAIN || header_root || body_root)`.
pub fn COMPUTE_BLOCK_ROOT(header_root: &Hash32, body_root: &Hash32) -> Hash32 {
    sha256_concat(&[BLOCK_ROOT_DOMAIN, header_root, body_root])
}

/// Simple emission tuple returned by `BUILD_CONSENSUS_EMISSIONS`.
/// Concrete `Emission` types can convert from this tuple.
pub type EmissionTuple = ([u8; 48], u64);

/// Build the required consensus emissions: one proposer record plus attester records.
///
/// - `proposer_reward_share` is a fixed weight (e.g., 12 for 12.5%).
/// - `attester_reward_share` is split equally among attesters using integer division; remainder is undistributed.
/// - If `attester_reward_share > 0` while `attester_pubkeys` is empty, returns an error.
pub fn BUILD_CONSENSUS_EMISSIONS(
    proposer_pubkey: [u8; 48],
    attester_pubkeys: &[[u8; 48]],
    proposer_reward_share: u64,
    attester_reward_share: u64,
) -> Result<Vec<EmissionTuple>, DefinitionError> {
    let mut out = Vec::with_capacity(1 + attester_pubkeys.len());
    out.push((proposer_pubkey, proposer_reward_share));

    if attester_pubkeys.is_empty() {
        if attester_reward_share > 0 {
            return Err(DefinitionError::NoAttestersForNonZeroShare);
        }
        return Ok(out);
    }

    let per_attester = attester_reward_share / (attester_pubkeys.len() as u64);
    for pk in attester_pubkeys {
        out.push((*pk, per_attester));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h32(x: u8) -> Hash32 {
        // helper deterministic array for testing merkle behavior
        let mut a = [0u8; 32];
        a[0] = x;
        a
    }

    #[test]
    fn data_hash_changes_with_value() {
        let h1 = COMPUTE_DATA_HASH(0);
        let h2 = COMPUTE_DATA_HASH(1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn emission_hash_domain_separated() {
        let pk = [1u8; 48];
        let h1 = COMPUTE_EMISSION_HASH(&pk, 10);
        let h2 = sha256_concat(&[DATA_HASH_DOMAIN, &pk, &10u64.to_le_bytes()]);
        assert_ne!(h1, h2); // different domain
    }

    #[test]
    fn merkle_root_empty() {
        let r = MERKLE_ROOT(&[]);
        let expect = sha256_concat(&[MERKLE_EMPTY_DOMAIN]);
        assert_eq!(r, expect);
    }

    #[test]
    fn merkle_root_single() {
        let leaf = h32(7);
        let r = MERKLE_ROOT(&[leaf]);
        // When single, result is SHA(leaf_domain || leaf), not just the leaf
        assert_eq!(r, sha256_concat(&[MERKLE_LEAF_DOMAIN, &leaf]));
    }

    #[test]
    fn merkle_root_odd_duplication() {
        let leaves = [h32(1), h32(2), h32(3)];
        let r = MERKLE_ROOT(&leaves);
        // Basic sanity: changing last element changes root
        let r2 = MERKLE_ROOT(&[h32(1), h32(2), h32(4)]);
        assert_ne!(r, r2);
    }

    #[test]
    fn body_root_is_merkle_of_two() {
        let d = h32(0x11);
        let e = h32(0x22);
        let r = COMPUTE_BODY_ROOT(&d, &e);
        let r2 = MERKLE_ROOT(&[d, e]);
        assert_eq!(r, r2);
    }

    #[test]
    fn header_root_field_permutation_changes_root() {
        let network_id = [2u8; 32];
        let prev = [3u8; 32];
        let body = [4u8; 32];
        let proposer = [5u8; 48];
        let r1_header = L2BlockHeader {
            version: 1,
            network_id,
            epoch: 2,
            prev_block_root: prev,
            body_root: body,
            data_count: 3,
            emissions_count: 4,
            proposer_pubkey: proposer,
        };
        let r2_header = L2BlockHeader {
            version: 1,
            network_id,
            epoch: 2,
            prev_block_root: prev,
            body_root: body,
            data_count: 4,
            emissions_count: 3,
            proposer_pubkey: proposer,
        };
        let r1 = COMPUTE_HEADER_ROOT(&r1_header);
        let r2 = COMPUTE_HEADER_ROOT(&r2_header);
        assert_ne!(r1, r2);
    }

    #[test]
    fn block_root_composition() {
        let header_root = h32(0xaa);
        let body_root = h32(0xbb);
        let r = COMPUTE_BLOCK_ROOT(&header_root, &body_root);
        let expect = sha256_concat(&[BLOCK_ROOT_DOMAIN, &header_root, &body_root]);
        assert_eq!(r, expect);
    }

    #[test]
    fn build_consensus_emissions_basic() {
        let proposer = [7u8; 48];
        let attesters = vec![[1u8; 48], [2u8; 48], [3u8; 48]];
        let v = BUILD_CONSENSUS_EMISSIONS(proposer, &attesters, 12, 88).unwrap();
        assert_eq!(v.len(), 1 + attesters.len());
        assert_eq!(v[0], (proposer, 12));
        // 88 / 3 = 29 per attester
        assert_eq!(v[1].1, 29);
        assert_eq!(v[2].1, 29);
        assert_eq!(v[3].1, 29);
    }

    #[test]
    fn build_consensus_emissions_zero_attesters_policy() {
        let proposer = [9u8; 48];
        let v = BUILD_CONSENSUS_EMISSIONS(proposer, &[], 12, 0).unwrap();
        assert_eq!(v.len(), 1);

        let err = BUILD_CONSENSUS_EMISSIONS(proposer, &[], 12, 1).unwrap_err();
        match err {
            DefinitionError::NoAttestersForNonZeroShare => {}
        }
    }
}
