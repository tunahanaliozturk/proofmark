# 0007: ring for TLS, SHA-256 and HMAC; MD5 and the CRCs written here

Status: accepted, 2026-11-25

## Context

The design planned seven crates for cryptography and checksums: `rustls` with the `ring` provider for TLS, plus `sha2`, `hmac`, `md-5` and `crc` for the hashes. The roadmap asked M1 to settle `ring` against `aws-lc-rs`, rustls's default provider, because `ring`'s last release (0.17.14) is from 2025-03-11.

What was found on 2026-11-25:

- `ring` builds on all three CI systems and locally on Windows with the GNU toolchain, needing only a C compiler. `aws-lc-rs` also needs CMake and NASM on Windows.
- The RustSec database marks `ring` versions before 0.17 as unmaintained (RUSTSEC-2025-0010) and lists 0.17 as unaffected. The only open-ended advisory against 0.17 (RUSTSEC-2025-0009) is fixed in 0.17.12. rustls 0.23.46 still ships a `ring` provider.
- `ring` already contains SHA-256 and HMAC-SHA256, the only primitives SigV4 needs.
- MD5 (for `Content-MD5` and ETags) and the three CRCs are not security primitives here. Each is a few dozen lines with published test vectors: RFC 1321's suite for MD5, and the check value for `"123456789"` from the CRC catalogue for each CRC.

The options considered:

1. The plan as written: `ring` for TLS, and `sha2`, `hmac`, `md-5` and `crc` beside it.
2. `aws-lc-rs` for TLS, the hashes from crates as planned.
3. `ring` for TLS and for SHA-256 and HMAC; MD5 and the CRCs written here and pinned to their vectors.

## Decision

Option 3. `ring` stays the rustls provider. `checksum::sha256` and the SigV4 HMAC use `ring::digest` and `ring::hmac`. `checksum::md5`, `crc32`, `crc32c` and `crc64nvme` are written in `src/checksum.rs`.

## Consequences

- Four fewer direct dependencies, and their transitive ones (`digest`, `block-buffer`, `crypto-common`, `crc-catalog` and others).
- MD5 and the CRCs are code to own. The tests pin MD5 to the RFC 1321 suite and the padding edge lengths, each CRC to its catalogue check value, and CRC32C to the trailer checksum in the S3 streaming example. A mutation of one polynomial bit fails two of those tests.
- If `ring` stops being maintained or loses its rustls provider, the move is to `aws-lc-rs`, and SHA-256 and HMAC move with it; they are used only in `src/checksum.rs` and `src/sigv4.rs`.
- The minimum Rust version no longer comes from `sha2`. It stays 1.88, now because of let chains and `slice::as_chunks`.
