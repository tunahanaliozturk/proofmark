# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows [Semantic Versioning](https://semver.org/).

A change to what a probe expects is listed under its own heading, **Expectation changes**, with the citation that justifies it. Reports carry the expectations version, so results from before and after the change can be told apart.

## Unreleased

### Added

- Safety, runner and reports (M2): the commands `run`, `list`, `explain`, `cleanup` and `fake`, with the exit codes from the design; the write ledger and cleanup from it; bucket naming and the empty-bucket check; the probe registry, statuses and the runner; terminal, JSON, JUnit and Markdown output; and the 14 `basic` probes, each with the faults in the fake that it catches.
- The wire and signing layer (M1): an HTTP/1.1 client with TLS, a SigV4 signer for headers, presigned URLs and signed chunks, the `aws-chunked` encoder and decoder, CRC32, CRC32C, CRC64NVME, MD5 and SHA-256, and the fake S3 server's skeleton. The M2 commands use them.
- Repository scaffold, design document, roadmap and decision records.

### Expectation changes

Expectations version 1, the first. The 14 `basic` probes and their evidence:

- `basic.put-get`, `basic.range`: GetObject reference, "Description" and "URI Request Parameters" (read 2026-11-25).
- `basic.etag-is-md5`, `basic.content-md5-mismatch`: "Checking object integrity for data uploads", sections "Using Content-MD5 and the ETag to verify uploaded objects" and "Using Content-MD5 when uploading objects". The same page says objects encrypted with SSE-KMS or a customer key get an ETag that is not the MD5; `basic.etag-is-md5` and `basic.zero-byte` report such an object as `inconclusive`.
- `basic.head`: HeadObject reference, "Description". The expectation names the status, the length and the ETag; the client never sees a body on a HEAD response, so the probe does not claim to check for one.
- `basic.user-metadata`: "Working with object metadata", "User-defined metadata".
- `basic.zero-byte`: "Organizing objects in the Amazon S3 console by using folders", which says the console creates 0-byte objects.
- `basic.overwrite`, `basic.expect-continue`: PutObject reference, "Description" and "Examples".
- `basic.missing-key`, `basic.missing-bucket`, `basic.range-unsatisfiable`, `basic.bad-signature`: "Error responses", "List of error codes".
- `basic.delete-missing`: basis observed. The DeleteObject reference does not say what a missing key gets; DeleteObjects, "Description", says a missing key is confirmed as deleted, and the single call is taken to behave the same. A store answering `404` is reported as `difference`, not `violation`. The probe writes its key and deletes it before the judged `DELETE`, so that it never deletes a key it did not create.

### Fixed

Found by review in the M2 code before any release:

- Cleanup trusts a ledger only where it names proofmark's own buckets (`proofmark-<run id>-*`, or the bucket given with the new `cleanup --bucket`) and keys (under `proofmark-<run id>/`, now also in a run's own bucket), for the endpoint it was written for, read once. Anything else is refused with exit 2 before a request is sent.
- No probe deletes a key, or writes over one, that this run did not create; `basic.delete-missing` no longer deletes a key it never wrote.
- Cleanup and the probes record their deletes in the ledger, so a later cleanup does not delete a key someone wrote since. A write the store refused (3xx, 4xx) no longer makes cleanup delete that key; a `CreateBucket` answered with a 5xx no longer drops the bucket from cleanup.
- Output is scrubbed as the last step, of the access key id too, and of each secret's percent-encoded and base64 forms. A signature echoed into a preflight error code was printed. Version ids go into the ledger unscrubbed, since cleanup sends them back.
- An existing bucket is used only when both listings answer with a whole, empty listing of the right kind and versioning was never turned on; a `501` or an incomplete listing no longer counts as empty.
- A flag given a value (`--use-existing-bucket=false`) is a usage error instead of turning the flag on. `--timeout` is limited to a day; a huge value overflowed the clock.
- A failed bucket creation that leaves cleanup work exits 5, not 4. A report path that is the kept ledger is refused instead of overwriting it. A run whose stdout or report file could not be written exits 2 instead of 0.
- `basic.put-get`, `basic.head` and `basic.range` read `Content-Length` and `Content-Range` as numbers; `basic.missing-bucket` checks with `HeadBucket` that its bucket is missing; `basic.bad-signature` keeps the session token on the wrong-secret request.
- A probe that got a `501` stays `unsupported` when a later request of it gets no response.

Found by review in the M1 code before any release:

- The canonical URI keeps an escaped `/` (`%2F`) escaped, and an empty path is `/`.
- `Debug` output of requests and signatures hides the session token, the `Authorization` header and the presigned signature and credential.
- Presigned S3 requests are always signed over `UNSIGNED-PAYLOAD`, and presigning again replaces the old `X-Amz-*` parameters instead of signing them twice.
- The HTTP client treats `101 Switching Protocols` as an error, checks the head and line limits on complete heads and lines, refuses chunk-size lines with no hex digit, and refuses NUL in the method, path and headers.
- The exchange deadline now covers the name lookup and every socket read and write under TLS.
- The client builds its TLS configuration only from trusted roots and takes no caller-built rustls configuration.
- The fake server listens on loopback addresses only.
