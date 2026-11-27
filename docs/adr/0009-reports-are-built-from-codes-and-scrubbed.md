# 0009: Output is built from codes and counts, and scrubbed of every secret used

Status: accepted, 2026-11-25

## Context

The design says credentials, `Authorization` headers, signatures and tokens never appear in output, and M1 made `Debug` of requests, signatures and credentials hide them. M2 adds five ways for text to leave a run: the terminal output, the JSON, JUnit and Markdown reports, and `--verbose`. It also adds the ledger file.

Hiding header values by name is not enough, because a store can echo what it received. AWS itself does: a `SignatureDoesNotMatch` error carries `SignatureProvided`, `StringToSign` and `CanonicalRequest`, and the canonical request contains the session token when one is signed. The fake now does the same, so that the tests see that shape. A report that quoted an error body, or a header the store chose to fill with what it was sent, would leak.

The options considered:

1. Redact by header and parameter name only, as M1 does for `Debug`.
2. Never copy response bodies or free text into output, and redact by name.
3. Option 2, and also replace every secret the run used, wherever it appears, in every string that leaves the run.

## Decision

Option 3.

- Judges build details from status codes, XML error codes and counts. An error code is accepted only if it is letters, digits and dots, so a store cannot smuggle text through it. No response body is copied anywhere.
- `--verbose` prints request and response heads with the values of `Authorization`, `X-Amz-Security-Token`, `X-Amz-Signature` and `X-Amz-Credential` redacted by name, and never prints bodies.
- `Remote` keeps the secret key, the session token and the signature of every request it sends, including the deliberately wrong one from `basic.bad-signature`. Every detail, target, request id, leftover and log line passes through `Remote::scrub`, which replaces each of them.

## Consequences

- `a_planted_secret_appears_in_no_output` (`tests/cli.rs`) runs the binary with a planted session token, `--verbose` and all three report files, keeps the ledger by leaving a foreign object behind, collects every signature the fake received, and searches every output for each of them. Turning off both the name redaction in the log and the scrubbing makes it fail.
- Scrubbing is a second line, not the only one; the first is never copying bodies or free text. A failure of one is hidden by the other in the output, so each has its own check: the unit tests on `error_code` for the first, and the planted-secret test with name redaction off for the second.
- Replacing strings costs a scan per secret per output string. A run sends at most a few hundred requests, so this is small.
