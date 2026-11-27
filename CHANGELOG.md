# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

A change to what a probe expects is listed under its own heading, **Expectation changes**, with the citation that justifies it. Reports carry the expectations version, so results from before and after the change can be told apart.

## Unreleased

### Added

- Safety, runner and reports (M2): the commands `run`, `list`, `explain`, `cleanup` and `fake`, with the exit codes from the design; the write ledger and cleanup from it; bucket naming and the empty-bucket check; the probe registry, statuses and the runner; terminal, JSON, JUnit and Markdown output; and the 14 `basic` probes, each with the faults in the fake that it catches.
- The wire and signing layer (M1): an HTTP/1.1 client with TLS, a SigV4 signer for headers, presigned URLs and signed chunks, the `aws-chunked` encoder and decoder, CRC32, CRC32C, CRC64NVME, MD5 and SHA-256, and the fake S3 server's skeleton. No commands use them yet.
- Repository scaffold, design document, roadmap and decision records.

### Expectation changes

Expectations version 1, the first. The 14 `basic` probes and their evidence:

- `basic.put-get`, `basic.range`: GetObject reference, "Description" and "URI Request Parameters" (read 2026-11-25).
- `basic.etag-is-md5`, `basic.content-md5-mismatch`: "Checking object integrity for data uploads", sections "Using Content-MD5 and the ETag to verify uploaded objects" and "Using Content-MD5 when uploading objects".
- `basic.head`: HeadObject reference, "Description".
- `basic.user-metadata`: "Working with object metadata", "User-defined metadata".
- `basic.zero-byte`: "Organizing objects in the Amazon S3 console by using folders", which says the console creates 0-byte objects.
- `basic.overwrite`, `basic.expect-continue`: PutObject reference, "Description" and "Examples".
- `basic.missing-key`, `basic.missing-bucket`, `basic.range-unsatisfiable`, `basic.bad-signature`: "Error responses", "List of error codes".
- `basic.delete-missing`: basis observed. The DeleteObject reference does not say what a missing key gets; DeleteObjects, "Description", says a missing key is confirmed as deleted, and the single call is taken to behave the same. A store answering `404` is reported as `difference`, not `violation`.

### Fixed

Found by review in the M1 code before any release:

- The canonical URI keeps an escaped `/` (`%2F`) escaped, and an empty path is `/`.
- `Debug` output of requests and signatures hides the session token, the `Authorization` header and the presigned signature and credential.
- Presigned S3 requests are always signed over `UNSIGNED-PAYLOAD`, and presigning again replaces the old `X-Amz-*` parameters instead of signing them twice.
- The HTTP client treats `101 Switching Protocols` as an error, checks the head and line limits on complete heads and lines, refuses chunk-size lines with no hex digit, and refuses NUL in the method, path and headers.
- The exchange deadline now covers the name lookup and every socket read and write under TLS.
- The client builds its TLS configuration only from trusted roots and takes no caller-built rustls configuration.
- The fake server listens on loopback addresses only.
