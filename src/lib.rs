//! dig-network-block crate library entry point.
//!
//! This crate provides primitives for defining and hashing an L2 block structure.
//!
//! Current modules implemented:
//! - `serde_hex`: Serde helpers to encode/decode byte arrays and vectors as 0x-prefixed hex.
//! - `dig_l2_definition`: CAPITALIZED spec functions (hash domains, Merkle, roots, consensus emissions tuples).
//! - `emission`, `body`, `header`, `block`: core L2 types each with `calculate_root()`.

pub mod serde_hex;
pub mod dig_l2_definition;
pub mod emission;
pub mod body;
pub mod header;
pub mod block;
