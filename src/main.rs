//! proofmark: probes an S3-compatible endpoint and reports, feature by
//! feature, whether it behaves the way S3 clients expect.
//!
//! The commands are in `src/cli.rs`; the design is in `docs/design.md`.

use std::io::{self, Write};
use std::process::ExitCode;

fn main() -> ExitCode {
    // A panic message could carry text from a response, so a panic prints
    // only where the bug is, never its message.
    std::panic::set_hook(Box::new(|info| {
        let place = info
            .location()
            .map_or_else(String::new, |l| format!(" at {}:{}", l.file(), l.line()));
        let _ = writeln!(
            io::stderr(),
            "proofmark: internal error{place}; please report it"
        );
    }));
    let args = std::env::args_os().skip(1).collect();
    let code = proofmark::cli::main(args, &mut io::stdout(), &mut io::stderr());
    ExitCode::from(code)
}
