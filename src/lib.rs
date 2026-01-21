//! dig-network-block crate library entry point.
//!
//! This crate provides primitives for defining and hashing an L2 block structure.
//!
//! Current modules implemented:
//! - `serde_hex`: Serde helpers to encode/decode byte arrays and vectors as 0x-prefixed hex.
//! - `dig_l2_definition`: CAPITALIZED spec functions (hash domains, Merkle, roots, consensus emissions tuples).
//! - `emission`, `body`, `header`, `block`: core L2 types each with `calculate_root()`.
//!
//! # Example
//!
//! The following example shows how to create a DIG L2 block, compute and print
//! its root hash, serialize it to JSON, restore it back from JSON, compute the
//! root again, print it, and assert that both roots are equal.
//!
//! ```rust
//! use dig_network_block::block::DigL2Block;
//! use dig_network_block::emission_config::ConsensusEmissionConfig;
//!
//! // 1) Create a DIG block
//! let version = 1u32;
//! let network_id = [1u8; 32];
//! let epoch = 42u64;
//! let prev_block_root = [0u8; 32];
//! let proposer_pubkey = [9u8; 48];
//! let data = vec![1u8, 2, 3, 4, 5];
//! let extra_emissions = vec![]; // none for this example
//! let attesters: Vec<[u8; 48]> = vec![]; // no attesters
//! let cfg = ConsensusEmissionConfig::new(12, 0); // zero attester share since there are no attesters
//! let block = DigL2Block::build(
//!     version,
//!     network_id,
//!     epoch,
//!     prev_block_root,
//!     proposer_pubkey,
//!     data,
//!     extra_emissions,
//!     &attesters,
//!     &cfg,
//! ).unwrap();
//!
//! // 2) Take its root hash and print it
//! let root1 = block.calculate_root();
//! println!("root1: {:?}", root1); // prints the 32-byte hash as a byte array
//!
//! // 3) Serialize the block and print the JSON
//! let json = serde_json::to_string_pretty(&block).unwrap(); // requires serde_json
//! println!("json: {}", json);
//!
//! // 4) Use the JSON to re-instantiate a new block from the original
//! let block2: DigL2Block = serde_json::from_str(&json).unwrap();
//!
//! // 5) Take the root hash of the re-instantiated block, print it
//! let root2 = block2.calculate_root();
//! println!("root2: {:?}", root2);
//!
//! // 6) Assert the original hash equals the new one
//! assert_eq!(root1, root2);
//! ```

pub mod serde_hex;
pub mod dig_l2_definition;
pub mod emission;
pub mod body;
pub mod header;
pub mod block;
pub mod emission_config;

