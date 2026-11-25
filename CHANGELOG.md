# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

A change to what a probe expects is listed under its own heading, **Expectation changes**, with the citation that justifies it. Reports carry the expectations version, so results from before and after the change can be told apart.

## Unreleased

### Added

- The wire and signing layer (M1): an HTTP/1.1 client with TLS, a SigV4 signer for headers, presigned URLs and signed chunks, the `aws-chunked` encoder and decoder, CRC32, CRC32C, CRC64NVME, MD5 and SHA-256, and the fake S3 server's skeleton. No commands use them yet.
- Repository scaffold, design document, roadmap and decision records.

### Fixed

Found by review in the M1 code before any release:

- The canonical URI keeps an escaped `/` (`%2F`) escaped, and an empty path is `/`.
- `Debug` output of requests and signatures hides the session token, the `Authorization` header and the presigned signature and credential.
- Presigned S3 requests are always signed over `UNSIGNED-PAYLOAD`, and presigning again replaces the old `X-Amz-*` parameters instead of signing them twice.
- The HTTP client treats `101 Switching Protocols` as an error, checks the head and line limits on complete heads and lines, refuses chunk-size lines with no hex digit, and refuses NUL in the method, path and headers.
- The exchange deadline now covers the name lookup and every socket read and write under TLS.
- The client builds its TLS configuration only from trusted roots and takes no caller-built rustls configuration.
- The fake server listens on loopback addresses only.
