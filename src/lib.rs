//! The parts of proofmark, as a library so that integration tests and the
//! fuzz harness can reach them.
//!
//! This is not a stable API. The crate is published as a binary, and any of
//! these modules may change shape in any release. See
//! `docs/adr/0006-library-target-for-tests-not-an-api.md`.

pub mod aws_chunked;
pub mod checksum;
pub mod fake;
pub mod http;
pub mod ledger;
pub mod rng;
pub mod s3;
pub mod safety;
pub mod session;
pub mod sigv4;
pub mod time;
