//! proofmark: probes an S3-compatible endpoint and reports, feature by
//! feature, whether it behaves the way S3 clients expect.
//!
//! Nothing is implemented yet, so the binary only prints its name and
//! version. The design is in `docs/design.md` and the milestones are in
//! `docs/roadmap.md`.

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let line = concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION"));
    match writeln!(std::io::stdout().lock(), "{line}") {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
