# 0006: A library target for tests and fuzzing, not a public API

Status: accepted, 2026-11-25

## Context

The design says proofmark is one binary crate with no stable Rust API in 0.1. M1 builds the client, the signer, the checksums and the fake server before any command uses them, and they need tests from outside the module that owns them:

- The signer is checked against the aws-c-auth vectors and the S3 examples through its public surface, the way a probe will call it.
- A signed `PUT` and `GET` go through the real client to the real fake on a loopback socket.
- The response parser is fuzzed by a harness that drives it as a black box.

In a binary-only crate, code that `main` does not reach yet is dead code, and with warnings as errors it does not compile without `#[expect(dead_code)]` on every module. Integration tests in `tests/` cannot reach into a binary at all. A future cargo-fuzz target, if CI ever gains one on Linux, needs a library to link against too.

The options considered:

1. Keep a binary only. Put every test inside its module, and mark each module `#[expect(dead_code)]` until a command uses it.
2. Add `src/lib.rs` that declares the modules, keep `src/main.rs` as the binary, and say plainly that the library is not an API.
3. Split into a workspace with an internal library crate and a binary crate.

## Decision

Option 2. `src/lib.rs` declares the modules as `pub`. The crate stays `publish = false`, the library's documentation says it is not a stable API, and any module may change shape in any release. From M2, when the commands arrive, the binary uses the library like any other caller.

## Consequences

- Integration tests and the fuzz harness use exactly what the binary will use. No test-only back doors.
- Every public item needs documentation (`missing_docs`), which costs some writing and keeps the internals readable.
- `cargo doc` produces library documentation that looks like an API. Its first line says it is not one. If the project is ever published to crates.io, the library is either hidden or made a real API; that decision comes with publishing, which is separate already.
- The design's "a library crate if anyone asks for one" in the post-release list still means a stable, documented, versioned API. This ADR does not promise one.
