dig-network-block
=================

Primitives for the DIG L2 block structure: strongly typed header/body models, deterministic hashing (roots), and consensus emission tuples. The crate focuses on reproducible root computation that matches the DIG L2 spec and offers convenient Serde helpers for JSON workflows.

- Crate: dig-network-block
- Docs: https://docs.rs/dig-network-block
- License: MIT OR Apache-2.0

Features
--------
- Typed models for the L2 block: header, body, and the composed block.
- Deterministic root hashing for data, emissions, header, body, and block.
- Consensus emission tuple construction consistent with the DIG L2 definition.
- serde support and a serde_hex module to encode/decode byte arrays as 0x‑prefixed hex in JSON.

Getting started
---------------
See the crate-level documentation for a full code example that:
1. Builds a DIG L2 block from inputs
2. Computes and prints its root hash
3. Serializes to JSON and back using serde/serde_json
4. Verifies the root remains the same after round-trip

Modules overview
----------------
- serde_hex: Serde helpers for 0x‑prefixed hex encoding/decoding of byte arrays.
- dig_l2_definition: Spec-level (capitalized) functions for hashing, Merkle root computation, and emission tuple building.
- emission, body, header, block: Core L2 types, each with calculate_root() where applicable.
- emission_config: Configuration helpers for proposer/attester reward shares.

Development
-----------
- Build: cargo build
- Test: cargo test
- Format: cargo fmt --all
- Lints: cargo clippy --all-targets --all-features -- -D warnings

Continuous integration
----------------------
GitHub Actions workflow at .github/workflows/ci.yml builds and tests the crate on pushes and pull requests.

License
-------
- MIT license

Contribution
------------
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, shall be licensed under the MIT license without any additional terms or conditions.
