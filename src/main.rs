//! proofmark: probes an S3-compatible endpoint and reports, feature by
//! feature, whether it behaves the way S3 clients expect.
//!
//! The commands are in `src/cli.rs`; the design is in `docs/design.md`.

use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args = std::env::args_os().skip(1).collect();
    let code = proofmark::cli::main(args, &mut io::stdout(), &mut io::stderr());
    ExitCode::from(code)
}
