# 0005: An in-process fake S3 server with switchable faults is the test bed

Status: accepted, 2026-11-22

## Context

A probe makes a claim: "this store enforces `If-None-Match`". To trust the claim, the probe itself must be tested, and a test of a checker has two halves. It must pass when the store is right, and it must fail when the store is wrong in the way the probe is there to catch. A probe that passes against everything tests nothing.

The options considered:

1. Test probes against real stores in containers. Slow, Linux only in CI, and a real store is right or wrong in whatever ways its current version happens to be. There is no way to ask MinIO to ignore `If-None-Match` on demand.
2. Test probes against recorded responses. Cheap, but a recording cannot answer a request it has not seen, and the race probes depend on timing.
3. Write a small S3 server in this repository, in memory, with faults that can be switched on one at a time.

## Decision

Option 3. `proofmark::fake` is an S3 server that runs inside the test process on a loopback port. It implements the subset of S3 that the probes use, verifies SigV4 signatures with the same signer, and keeps everything in memory.

Its correct behaviour is the reference as proofmark understands it ([ADR 0003](0003-expectations-carry-their-evidence.md)). Each fault is one named, documented way of being wrong, taken from real reports where there is one, for example:

- `IgnoreIfNoneMatch`: accepts the header and overwrites anyway.
- `RacyIfNoneMatch`: checks for the key, waits, then writes, without a lock.
- `IgnoreGetIfMatch`: serves a stale `If-Match` read with `200` ([Garage issue #804](https://git.deuxfleurs.fr/Deuxfleurs/garage/issues/804)).
- `StoreChunkFraming`: stores the `aws-chunked` body as received, framing and trailer included.
- `IgnoreChecksum`: accepts a wrong `x-amz-checksum-*` value.
- `RejectChecksumAlgorithmHeader`: refuses a request carrying `x-amz-checksum-algorithm: CRC32` as not implemented, which is the error R2 users saw in January 2025 ([R2 incident](https://www.cloudflarestatus.com/incidents/t5nrjmpxc1cj)).
- `ListSkipsAtPageBoundary`: drops the first key of every page after the first.
- `IgnoreRetention`: accepts a retention date and allows the delete.

Every probe declares the faults it catches. A test runs every probe against the correct fake (it must pass) and against each of its faults (it must not pass, and must report the expected status). A second test checks that every fault is caught by at least one probe and every probe catches at least one fault.

The fake also ships as `proofmark fake`, so users can see what a run looks like without any store, and so the SDK request shapes can be captured from real SDKs pointed at it (M4).

## Consequences

- Every probe is tested on every CI platform, Windows included, in seconds and without Docker.
- The race probes get a race that is guaranteed to exist: `RacyIfNoneMatch` holds the window open long enough that the probe must see it.
- The fake is a second S3 implementation to maintain. It stays small because it only needs the behaviour probes exercise, with one global lock and no persistence.
- The fake and the probes can share a misunderstanding of S3. The mutation test cannot catch that. Real stores in the matrix and user disputes are the check (ADR 0003).
- The fault list doubles as documentation: `proofmark explain <probe>` names the faults a probe catches, which tells a user what a pass does and does not mean.
