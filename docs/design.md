# proofmark design

This document is the contract for the build. Code that disagrees with it is a bug in one of the two, and the fix says which.

Facts in this document were checked on 2026-11-22 unless a date says otherwise. Anything that could not be checked is under [Open questions](#open-questions).

## The problem and who has it

An "S3-compatible" store speaks the S3 API, but how much of the API it honours, and how, varies. The gaps that hurt are the ones that do not produce an error:

- A conditional write (`If-None-Match: *`, `If-Match: <etag>`) that the store accepts and does not enforce. Software that uses it as a lock, such as table-format commits and some backup tools, overwrites data and never finds out. The [NVIDIA storage runbook](https://docs.omniverse.nvidia.com/ovstorage/ovstorage-guide/latest/runbooks/s3-compatibility.html) (updated 2026-11-18) calls this the most dangerous gap and says to validate it deliberately.
- An upload whose checksum the store ignores, or whose `aws-chunked` framing the store saves as part of the object.
- A retention date that is stored and not enforced.

Others break loudly, but only after a client upgrade. In January 2025 the AWS SDKs began sending CRC checksums by default ([AWS SDK reference, "Data Integrity Protections for Amazon S3"](https://docs.aws.amazon.com/sdkref/latest/guide/feature-dataintegrity.html)). Cloudflare R2 answered with errors such as `Header 'x-amz-checksum-algorithm' with value 'CRC32' not implemented` from 17 January until a fix on 3 February 2025 ([R2 incident](https://www.cloudflarestatus.com/incidents/t5nrjmpxc1cj)), and other stores were hit too ([xuanwo.io, 2025-02-20](https://xuanwo.io/links/2025/02/aws_s3_sdk_breaks_its_compatible_services/)).

### Who has it

1. **Operators moving between self-hosted stores.** MinIO stopped publishing Docker images in October 2025 and ended active development of its community edition in December 2025 ([Linuxiac](https://linuxiac.com/minio-ends-active-development/)). Its users are choosing between Garage, SeaweedFS, RustFS, Ceph RGW, Apache Ozone and others. They need to know, before the move, whether the clients they run (restic, Loki, Mimir, an Iceberg or Delta writer, an application on a current AWS SDK) will keep working. This is the primary user.
2. **Developers of S3-compatible stores** who want a feature-level gate in CI that fails on a regression and says which rule broke.
3. **Developers of tools that support "any S3-compatible endpoint"**, who want to tell their users which stores are safe for which feature.

### What they use today

| Tool | State on 2026-11-22 | Gap for this user |
| --- | --- | --- |
| [`ceph/s3-tests`](https://github.com/ceph/s3-tests) | Archived on 2026-10-12. The README says the tests moved into [`ceph/ceph`](https://github.com/ceph/ceph/tree/main/src/test/rgw/s3-tests) (`src/test/rgw/s3-tests`) and will not be maintained in the old repository. | Python, tox and boto3. Results are per test, not per feature. Written around Ceph. Ozone's correction to its conditional-write tests ([#735](https://github.com/ceph/s3-tests/pull/735), opened 2026-04-14) is still open in the archived repository. |
| [`minio/mint`](https://github.com/minio/mint) | Archived; last push 2026-01-08. | A container of many SDK test runners, aimed at MinIO. |
| [`go-faster/s3t`](https://github.com/go-faster/s3t) | Active (push 2026-10-26), MIT, Go, 0 stars. | A single-binary Go port of `s3-tests`. Solves the deployment problem, keeps upstream's tests, expectations and per-test results by design ("upstream is right"). |
| [`tamnd/s3-compat`](https://github.com/tamnd/s3-compat) | Last push 2026-06-10, no licence, 0 stars. | A Go test harness and compose file for five stores. The README lists only configuration and client packages; the feature tests are "to be added". |
| [versitygw tests](https://github.com/versity/versitygw/tree/main/tests) | Active, Apache-2.0. | Shell tests (BATS) that need the AWS CLI, s3cmd and mc installed. Since 2026-08-10 it also has a Go test of 32-way `If-Match` and `If-None-Match` races, run against versitygw itself. |
| [block/buzz conformance probe](https://github.com/block/buzz/blob/main/docs/git-on-object-storage.md) | Active, Apache-2.0. | An application's own admission gate for conditional-write atomicity, built into that application. |
| Vendor compatibility tables | Various. | Not reproducible, go out of date, written by the party being judged. |

So the race probe is not a new idea: versitygw and buzz both have one. What is missing is a tool an operator can download and run against any store in a minute, that reports per feature with the evidence for each expectation, that separates "refuses" from "ignores", that knows which features a given client needs, and that cannot damage data in the bucket it is pointed at.

### Why Rust

Go would also give a single static binary, and two of the closest tools are written in Go. Rust is chosen because it is the language this project's author works in, and because the testing approach (a deterministic in-process fake with switchable faults, [ADR 0005](adr/0005-in-process-fake-as-the-test-bed.md)) is one the author has used before. Neither is a reason a user should care about. The user gets a single binary either way.

## Goals

1. A single binary, no runtime, that probes an endpoint with about 80 probes and reports per feature.
2. Each probe's expectation cites its evidence, and each result says whether the store broke documented behaviour, differs from observed AWS behaviour, refused honestly, or could not be judged ([ADR 0003](adr/0003-expectations-carry-their-evidence.md)).
3. Silent acceptance is called out above everything else.
4. Profiles that select the probes a known client depends on.
5. Never delete, overwrite or lock data proofmark did not write ([ADR 0004](adr/0004-only-touch-what-it-wrote.md)).
6. Every probe is shown to pass against a correct fake and to fail against the fault it exists to catch ([ADR 0005](adr/0005-in-process-fake-as-the-test-bed.md)).
7. Output a terminal matrix, JSON, JUnit and Markdown.
8. A CI job in this repository that runs proofmark against pinned container images of open stores and publishes the matrix.
9. Windows, macOS and Linux as equal platforms for the binary.

## Non-goals

- Performance or load testing. The race probes send a few dozen concurrent requests, no more.
- IAM, bucket policies, ACLs, STS, server-side encryption (SSE-S3, SSE-KMS, SSE-C).
- Lifecycle rules executing over time, replication, S3 Select, static website hosting, event notifications, inventory, analytics.
- Browser POST uploads, SigV4a, anonymous access, HTTP/2.
- Durability and fault tolerance of the store: crashes, disk loss, node loss, multi-node consistency.
- Grading stores with a single score. A percentage hides which rule broke; the report lists findings.
- Being a general S3 client or a library. There is no stable Rust API in 0.1; the crate is a binary.

## The user's view

### Install

A release binary per platform from GitHub releases, or `cargo install` once the crate is published (publishing needs a separate decision; `publish = false` until then).

### Credentials

From the environment only: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and, if set, `AWS_SESSION_TOKEN`. Not from the command line, where they would show in the process list, and not from `~/.aws` in 0.1.

### Commands

```
proofmark run      --endpoint URL [options]      run probes against an endpoint
proofmark list     [--profile P] [--feature F]   show the probes and their expectations, no network
proofmark explain  PROBE                         one probe: requests, expectation, citation, faults it catches
proofmark cleanup  --endpoint URL --ledger FILE [--bucket NAME]  remove what an interrupted run left behind
proofmark fake     [--listen ADDR] [--fault F]   run the fake S3 server, for trying proofmark out and for capturing SDK requests
proofmark report   --input FILE... [options]     render, merge or compare JSON reports
```

`run` options:

| Option | Meaning | Default |
| --- | --- | --- |
| `--endpoint URL` | `http://` or `https://`, with port. | required |
| `--region NAME` | Signing region. Some stores need their own (Garage uses `garage`). | `us-east-1` |
| `--profile NAME` | Select probes by client profile. Repeatable. | none |
| `--feature NAME` | Select probes by feature. Repeatable. | none |
| `--probe ID` | Select single probes. Repeatable. | none |
| | With no selection, every probe runs except opt-in ones. | |
| `--addressing path\|virtual` | Addressing style for all probes except the addressing probes, which always try both. | `path` |
| `--bucket NAME` with `--use-existing-bucket` | Work in an existing, empty bucket instead of creating buckets ([ADR 0004](adr/0004-only-touch-what-it-wrote.md)). | create own |
| `--ledger PATH` | Where the write ledger goes. | `./proofmark-ledger-<run id>.jsonl` |
| `--report FORMAT=PATH` | Also write `json`, `junit` or `markdown` to a file. Repeatable. The terminal matrix always goes to stdout. | none |
| `--fail-on LIST` | Statuses that make the exit code 1. | `violation,difference,unsupported,inconclusive` |
| `--race-writers N` | Concurrent writers in a race probe. At most 64. | 8 |
| `--race-rounds N` | Rounds per race probe. | 20 |
| `--lock-seconds N` | Retention used by Object Lock probes. | 10 |
| `--allow-compliance-lock` | Run the compliance-mode probe, which leaves an object that cannot be deleted until its retention expires. | off |
| `--ca-file PATH` | Extra trusted CA certificates (PEM), for stores with a private CA. | none |
| `--timeout SECONDS` | Per request. | 30 |
| `--seed N` | Seed for payloads and key names, printed in every report so a run can be repeated. | random |
| `--verbose` | Print every exchange, with secrets redacted. | off |

There is no option to skip TLS verification. A store with a self-signed certificate needs `--ca-file`.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every selected probe ended with a status not listed in `--fail-on`, and cleanup finished. |
| 1 | At least one probe ended with a status listed in `--fail-on`. |
| 2 | Usage error: unknown option, a value given to a flag, missing credentials, unknown probe, profile or feature. Also a run whose output or a requested report file could not be written, unless it already failed for another reason. |
| 3 | Safety refusal: the existing bucket cannot be shown to be empty and never versioned ([ADR 0012](adr/0012-an-existing-bucket-must-be-shown-empty-and-unversioned.md)), a bucket name is taken, or `--bucket` was given without `--use-existing-bucket`. Nothing was written. |
| 4 | Could not start: endpoint unreachable, TLS failure, or the preflight request was rejected (bad credentials, wrong region, clock skew over 15 minutes). |
| 5 | Cleanup incomplete: something proofmark wrote is still there. The ledger is kept and its path printed. This wins over every other code once something may have been written, because the user has to act. |

`cleanup` exits 0 when nothing the ledger names is left (the ledger file is then removed), 5 if anything is left, 2 for a ledger it cannot read, one written for another endpoint, or one that names anything proofmark does not write, and 4 if no delete got any response. `--bucket NAME` names the existing bucket a run used; without it only proofmark's own buckets are accepted. How cleanup reads a ledger that a crash left untidy is in [ADR 0008](adr/0008-what-cleanup-infers-from-the-ledger.md), and which ledgers it trusts in [ADR 0011](adr/0011-a-ledger-names-only-what-proofmark-writes.md). `report --baseline` exits 1 when the results differ from the baseline.

### Statuses

`pass`, `violation`, `difference`, `unsupported`, `inconclusive`, `skipped`. The first five are defined in [ADR 0003](adr/0003-expectations-carry-their-evidence.md). `skipped` means the probe was not run: not selected, needs an opt-in flag, needs a bucket configuration the existing bucket lacks, or depends on a probe that did not pass (the reason is printed). A `violation` or `difference` where the store returned success and ignored part of the request is also marked `silent`.

### Examples

The outputs below are illustrations of the format, not results from any store.

```
$ proofmark list --feature conditional
id                                 basis       expectation
cond.put-if-none-match-new         documented  PUT with If-None-Match: * on a new key succeeds with 200
cond.put-if-none-match-exists      documented  PUT with If-None-Match: * on an existing key fails with 412
cond.put-if-none-match-race        documented  of N concurrent PUTs with If-None-Match: *, exactly one succeeds
...
```

```
$ proofmark explain cond.put-if-none-match-race
cond.put-if-none-match-race  (feature: conditional, profiles: table-commit)

Requests, per round, on a fresh key:
  N writers, each with its own connection, send at the same moment:
  PUT /<bucket>/<key>  If-None-Match: *  body: 1 KiB unique to the writer
  then one GET /<bucket>/<key>

Expected: exactly one writer gets 200; every other writer gets 412 (or 409); the
GET returns the winner's body.
Basis: documented. Amazon S3 User Guide, "How to prevent object overwrites with
conditional writes", section "Conditional write behavior": "If multiple conditional
writes or copies occur for the same object name, the first write operation to finish
succeeds." https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html
(read 2026-11-22)

A round counts only if all N requests were in flight at the same time. A pass means no
lost update in the contended rounds that ran. It does not prove there is none.

Catches: IgnoreIfNoneMatch, RacyIfNoneMatch
```

```
$ proofmark run --endpoint http://127.0.0.1:9000 --profile table-commit --report json=out.json
proofmark 0.1.0  endpoint http://127.0.0.1:9000  region us-east-1  seed 8121907
buckets created: proofmark-k3x9q2-main
ledger: ./proofmark-ledger-k3x9q2.jsonl

feature       probes  pass  violation  difference  unsupported  inconclusive  skipped
basic              4     4          0           0            0             0        0
listing            2     2          0           0            0             0        0
multipart          1     1          0           0            0             0        0
conditional        8     5          2           0            1             0        0

findings
  violation  silent  cond.put-if-none-match-race
      3 of 20 contended rounds had 2 or more winners (8 writers per round)
      expected: exactly one 200; basis: documented (conditional-writes.html, "Conditional write behavior")
  violation          cond.put-if-match-missing
      PUT with If-Match on a missing key returned 200 and created the object; expected 404
  unsupported        cond.copy-if-none-match
      501 NotImplemented

cleanup: 1 bucket, 214 object versions removed, nothing left
result: 2 violations, 1 unsupported (exit 1)
```

JSON report, abridged:

```json
{
  "schema_version": 1,
  "proofmark_version": "0.1.0",
  "expectations_version": 1,
  "endpoint": "http://127.0.0.1:9000",
  "region": "us-east-1",
  "seed": 8121907,
  "started": "2026-12-01T10:00:00Z",
  "selection": { "profiles": ["table-commit"], "features": [], "probes": [] },
  "results": [
    {
      "id": "cond.put-if-none-match-race",
      "feature": "conditional",
      "status": "violation",
      "silent": true,
      "basis": "documented",
      "citation": {
        "url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html",
        "section": "Conditional write behavior",
        "read": "2026-11-22"
      },
      "detail": "3 of 20 contended rounds had 2 or more winners",
      "exchanges": [
        { "method": "PUT", "target": "/proofmark-k3x9q2-main/cond/race-01", "status": 200, "request_id": "..." }
      ]
    }
  ],
  "cleanup": { "complete": true, "left": [] }
}
```

The Markdown report is a table with one row per probe and, from `report --input a.json --input b.json --format markdown`, one column per store. That is the format the store matrix is published in.

## Probe catalogue

The planned probes, by feature. Ids are stable once released; renaming one is an expectation change. The count will move during the build; probes that cannot be cited are dropped rather than guessed. Citations below name the page; the section is recorded with each probe.

**basic** (14), from the [GetObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html), PutObject, HeadObject and DeleteObject references and the [error responses](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/ErrorResponses.html) page:
`basic.put-get` (bytes and length round trip), `basic.etag-is-md5` (single-part ETag is the quoted MD5, per [checking object integrity](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html)), `basic.head` (headers and no body), `basic.user-metadata`, `basic.zero-byte`, `basic.overwrite`, `basic.missing-key` (404 `NoSuchKey`, XML error body), `basic.missing-bucket` (404 `NoSuchBucket`), `basic.delete-missing` (204), `basic.range` (206 and `Content-Range`, including a suffix range), `basic.range-unsatisfiable` (416 `InvalidRange`), `basic.content-md5-mismatch` (400 `BadDigest`), `basic.bad-signature` (403 `SignatureDoesNotMatch`), `basic.expect-continue` (an upload with `Expect: 100-continue` completes).

**addressing** (2), from [virtual hosting](https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html):
`addr.path-style`, `addr.virtual-host` (connects to the endpoint's address with `Host: <bucket>.<endpoint host>`, so no DNS set-up is needed, and checks both styles see the same object). A store that needs a configured domain for virtual hosting gets `unsupported` with that hint.

**listing** (9), from [ListObjectsV2](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html) and [object keys](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html):
`list.v2-basic` (including `KeyCount`, an empty prefix and `max-keys=0`), `list.pagination` (`max-keys=2` with continuation tokens returns every key exactly once and in order), `list.start-after`, `list.delimiter`, `list.prefix-delimiter`, `list.order-utf8` (keys in UTF-8 binary order), `list.unusual-keys` (space, `+`, `%`, `?`, `#`, non-ASCII in two Unicode normal forms as two keys, `a//b`, trailing `/`, `./` and `../` segments, a 1,024-byte key: each round-trips and lists once, byte for byte), `list.encoding-type-url`, `list.read-after-write` (a new key lists at once and a deleted one is gone, per the [strong consistency model](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel)).

**multipart** (8), from the [multipart upload overview](https://docs.aws.amazon.com/AmazonS3/latest/userguide/mpuoverview.html) and [quotas](https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html):
`mpu.basic` (a 5 MiB part and a 1-byte part complete to their concatenation), `mpu.etag` (MD5 of the concatenated part digests, then `-2`), `mpu.part-too-small` (`EntityTooSmall`), `mpu.abort` (after abort the upload is gone from `ListMultipartUploads` and `UploadPart` answers `NoSuchUpload`), `mpu.part-order` (`InvalidPartOrder`), `mpu.wrong-part-etag` (`InvalidPart`), `mpu.list-parts`, `mpu.part-replace` (re-uploading a part number replaces it).

**checksums** (16), from [checking object integrity for uploads](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html), [SigV4 streaming](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming.html) and [streaming with trailers](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming-trailers.html):
`sum.crc32`, `sum.crc32c`, `sum.crc64nvme`, `sum.sha256` (a correct `x-amz-checksum-*` header is accepted and returned on `GET` with `x-amz-checksum-mode: ENABLED`), `sum.crc32-wrong`, `sum.crc64nvme-wrong`, `sum.sha256-wrong` (400 `BadDigest`; acceptance is a silent violation), `sum.trailer-crc32` (the default SDK shape: `Content-Encoding: aws-chunked`, `x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER`, `x-amz-trailer: x-amz-checksum-crc32`, `x-amz-decoded-content-length`; the stored object equals the decoded data, not the framing), `sum.trailer-crc64nvme`, `sum.trailer-wrong`, `sum.signed-streaming` (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD` with chunk signatures), `sum.unsigned-payload` (`UNSIGNED-PAYLOAD` accepted), `sum.algorithm-header` (`x-amz-sdk-checksum-algorithm` on `PutObject` and `x-amz-checksum-algorithm` on `CreateMultipartUpload` are accepted when the matching checksum is sent, the request that R2 refused in January 2025), `sum.content-sha256-mismatch` (`XAmzContentSHA256Mismatch`), `sum.mpu-full-object-crc64nvme` (full-object checksum type on completion), `sum.mpu-composite-crc32` (composite value with the `-N` suffix).

**conditional** (14), from [conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html), [conditional requests](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-requests.html), GetObject and [CopyObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CopyObject.html):
`cond.put-if-none-match-new` (200), `cond.put-if-none-match-exists` (412), `cond.put-if-none-match-race`, `cond.put-if-match` (200 on the current ETag), `cond.put-if-match-stale` (412), `cond.put-if-match-race`, `cond.put-if-match-missing` (fails and creates nothing), `cond.mpu-complete-if-none-match` (a key written during the upload makes the completion fail with 412, the documented scenario), `cond.copy-if-none-match` (412), `cond.delete-marker` (in a versioned bucket, `If-None-Match: *` succeeds when the current version is a delete marker), `cond.get-if-match-stale` (412; [Garage #804](https://git.deuxfleurs.fr/Deuxfleurs/garage/issues/804)), `cond.get-if-none-match` (304), `cond.get-dates` (`If-Modified-Since` 304, `If-Unmodified-Since` 412), `cond.copy-source-if-match` (412).

**versioning** (4), from [versioning workflows](https://docs.aws.amazon.com/AmazonS3/latest/userguide/versioning-workflows.html):
`ver.ids` (two writes, two version ids, the old one still readable), `ver.list-versions` (`IsLatest` correct), `ver.delete-marker` (404 with `x-amz-delete-marker: true`), `ver.delete-version` (deleting by version id removes that version only).

**object lock** (5), from [Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) and PutObjectRetention:
`lock.governance-blocks-delete` (403), `lock.governance-bypass` (delete with `x-amz-bypass-governance-retention: true` succeeds), `lock.legal-hold`, `lock.expiry` (after the retain-until date, by the server's clock, the delete succeeds), `lock.compliance` (opt-in: the bypass header does not help).

**presigned** (4), from [sharing objects with presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ShareObjectPreSignedURL.html) and [query string authentication](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-query-string-auth.html):
`presign.get`, `presign.put`, `presign.expired` (403), `presign.tampered` (403).

**copy** (4), from CopyObject:
`copy.metadata-copy` (default directive keeps metadata and content type), `copy.metadata-replace`, `copy.self-without-replace` (400 `InvalidRequest`), `copy.encoded-source` (a source key with reserved characters, URL-encoded).

That is 80 probes.

### Profiles

A profile is a named list of probe ids plus the evidence for why that client needs them. The evidence for a client profile is a link to the client's source at a commit, recorded when the profile is written (M6). Planned profiles:

| Profile | For | Evidence |
| --- | --- | --- |
| `sdk-2025` | Any application on an AWS SDK released since early 2025 with default settings. | The [SDK default algorithm table](https://docs.aws.amazon.com/sdkref/latest/guide/feature-dataintegrity.html): CRC32 for most SDKs, CRC64NVME for the AWS CLI v2 and the C++ SDK. Request shapes captured from the AWS CLI v2 and boto3 (M4). |
| `table-commit` | Writers that commit with conditional writes (Iceberg, Delta, Hudi and similar). | Which writers use which conditional operation is checked in their sources at M6. |
| `restic` | restic's S3 backend. | restic and minio-go sources at M6. |
| `loki-mimir` | Grafana Loki and Mimir object storage. | Their object storage client sources at M6. |
| `immutable-backup` | Backup software that relies on Object Lock. | Object Lock and versioning documentation. |

## Architecture

One binary crate, with a library target that tests and the fuzz harness use and that is not an API ([ADR 0006](adr/0006-library-target-for-tests-not-an-api.md)). No async runtime ([ADR 0002](adr/0002-own-http1-client-on-blocking-sockets.md)).

```
cli ──> config ──> preflight ──> plan ──> runner ──> report ──> exit code
                      │                    │  ▲
                      │                    ▼  │
                      └──────────> session: signer, http, ledger, clock offset
                                           │
                                           ▼
                                   endpoint (real store, or fake on loopback)
```

### Modules

| Module | Does | Pure or I/O |
| --- | --- | --- |
| `cli` | Parses arguments by hand ([ADR 0010](adr/0010-arguments-parsed-by-hand.md)) and validates them into an immutable `RunConfig`: endpoint, region, selection, limits. Help text is written by hand. | Pure, plus reading the environment |
| `run` | One run: preflight, safety set-up, the probes, cleanup, the report. Also the `cleanup` command. | I/O |
| `sigv4` | Canonical request, string to sign, signing key, `Authorization` header, presigned query, chunk and trailer signatures. Takes the time as an argument. | Pure |
| `checksum` | CRC32, CRC32C, CRC64NVME, SHA-256, MD5, composite multipart values, base64, hex. | Pure |
| `aws_chunked` | The `aws-chunked` encoder and decoder, signed and unsigned, with trailers. | Pure |
| `time` | UTC timestamps in the SigV4, HTTP-date and ISO 8601 forms. | Pure |
| `rng` | The seeded SplitMix64 source for payloads and key names. | Pure |
| `s3` | Paths, and response parsers (XML error codes and listings, with roxmltree). Knows the S3 shapes, not the network. Requests are built as a `session::Call`. | Pure |
| `http` | Writes a `Request` to a socket and reads a `Response`. TCP or TLS. Handles `100 Continue`, chunked bodies, `HEAD`, connection close, timeouts. | I/O |
| `session` | Ties one run together: config, credentials, signer, the clock offset to the server, the ledger, the seeded random source, the run's buckets. Sends requests and records exchanges. | I/O |
| `ledger` | Appends write intents and results to the JSON-lines ledger and flushes; reads it back for cleanup. | I/O |
| `safety` | Bucket naming, the empty-bucket check, cleanup from the ledger. | I/O, with pure decision functions |
| `probe` | The `Probe` type, the registry of all probes, each probe's `run` and `judge`. | `run` does I/O, `judge` is pure |
| `profile` | The profile table. | Pure |
| `report` | `Report` and the four renderers; merge and baseline comparison. | Pure, plus writing files |
| `fake` | The in-process S3 server and its faults ([ADR 0005](adr/0005-in-process-fake-as-the-test-bed.md)). | I/O on loopback |

### Main types

Sketches, not final signatures.

```rust
pub struct Request {            // what goes on the wire, exactly
    method: Method,
    target: Target,             // bucket, key, query pairs; rendered per Addressing
    headers: Vec<(HeaderName, String)>,   // in send order, nothing added later
    body: Vec<u8>,
}

pub struct Response {
    status: u16,
    headers: Vec<(String, String)>,       // in received order, duplicates kept
    body: Vec<u8>,
}

pub struct Probe {
    id: ProbeId,                // "cond.put-if-none-match-race"
    feature: Feature,
    title: &'static str,
    expectation: Expectation,
    needs: Needs,               // bucket kind (plain, versioned, locked), opt-in flags
    catches: &'static [Fault],  // at least one
    run: fn(&mut Session) -> Result<Observation, ProbeError>,
    judge: fn(&Observation) -> Judgement,
}

pub struct Expectation { statement: &'static str, basis: Basis }
pub enum Basis { Documented(Citation), Observed(Citation) }
pub struct Citation { url: &'static str, section: &'static str, read: &'static str }

pub enum Judgement { Matches, Deviates { detail: String, silent: bool }, Unsupported, Inconclusive { reason: String } }
pub enum Status { Pass, Violation, Difference, Unsupported, Inconclusive, Skipped }
```

`Status` is computed from the `Judgement` and the `Basis` by one pure function, the table in ADR 0003. `Observation` holds the exchanges a probe made and anything it measured (for races: per writer, the status, the send and receive instants, and the final body).

### Data flow of a run

1. **Parse and validate** the command line into a `RunConfig`. Errors exit 2.
2. **Preflight.** Connect, send one signed `ListBuckets` (or, with `--use-existing-bucket`, a `HeadBucket`). Read the server's `Date` header and compute the clock offset. Fail with exit 4 on connection, TLS, authentication or a skew over 15 minutes. If the error body names a different region, say so.
3. **Plan.** Select probes, drop those whose needs cannot be met (with the reason), and order them so that probes sharing a bucket kind run together.
4. **Safety set-up** ([ADR 0004](adr/0004-only-touch-what-it-wrote.md)). Create the buckets the plan needs, or check the existing bucket is empty. Exit 3 on refusal.
5. **Run.** Each probe gets fresh keys under its own prefix. `run` performs the requests through the session (every write goes through the ledger first); `judge` decides; the runner turns that into a status. A probe that errors or times out is `inconclusive`, never `pass`.
6. **Clean up** from the ledger, waiting for any compliance retention to expire.
7. **Report** to the terminal and to every `--report` file, then exit with the code from the table above.

## The hard parts

### What is the right answer

There is no AWS budget. The answer is in [ADR 0003](adr/0003-expectations-carry-their-evidence.md): every expectation carries a citation, the status separates documented from observed behaviour, and corrections go through pull requests with evidence. Two more rules:

- When every store in the matrix fails the same probe, the probe is reviewed before any store is blamed. The matrix report marks such rows.
- Behaviour the documentation leaves open is not probed, or is probed only for what it does state. For example, AWS says a concurrent conditional write may also get `409 Conflict` ([conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html#conditional-error-response)), so the race probe accepts 409 as well as 412 from the losers.

### Not destroying data

[ADR 0004](adr/0004-only-touch-what-it-wrote.md), and it is built first (M2), before any probe that writes more than one object. The ledger is written before each request, so a crash between request and response still leaves a record.

### Races are probabilistic

A race probe cannot make a store race. It can only make it likely, and say how often it managed to.

- Each writer opens its connection and finishes the TLS handshake first, then waits on a barrier, so the requests leave within microseconds of each other.
- A round counts as **contended** only if every writer's request was in flight at the same moment: the latest send time is before the earliest response time.
- The judgement is over contended rounds only. Two or more winners in any contended round, or a final body that is not the sole winner's, is a silent violation. Zero contended rounds is `inconclusive`, never `pass`.
- The report says how many contended rounds ran. The wording of a pass is "no lost update in K contended rounds", as in the block/buzz design, which notes that a finite probe "cannot prove a universal axiom" ([buzz, "Conformance"](https://github.com/block/buzz/blob/main/docs/git-on-object-storage.md)).

The fake's `RacyIfNoneMatch` fault widens the window between its existence check and its write so that a correct probe must catch it in every run of the test, not most runs.

### Time

Object Lock and presigned URL expiry depend on the server's clock, not the client's. proofmark measures the offset from the `Date` header in preflight and computes retain-until dates and waits in server time. The `RetainUntilDate` in the [PutObjectRetention reference](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectRetention.html) is a timestamp with no documented minimum, so the lock probes use a retention of `--lock-seconds` (10 by default) and wait for it. Whether stores accept a retention that short is part of what is found out. SigV4 itself fails if the clocks differ by more than 15 minutes; preflight reports that plainly instead of letting every probe fail with `RequestTimeTooSkewed`.

### Matching what SDKs actually send

The value of the `sdk-2025` profile depends on sending what SDKs send. The documentation describes the format ([trailing checksums](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html#trailing-checksums)) but not each SDK's exact headers. At M4, `proofmark fake --record DIR` saves the request heads it receives; the AWS CLI v2 and boto3 (free, installed locally) are pointed at it, and the captured heads are checked in as fixtures with the tool versions. A test checks that the probes' request shapes carry the same header names and encodings. When SDKs change, a contributor re-records.

### Citations rot

On 2026-11-22, `https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html` and the other SigV4 pages under `/API/` redirected to the API index, while the same pages under `/developerguide/` answered. Citations keep the section title next to the URL, and a weekly scheduled workflow checks that every cited URL answers `200`. It is not part of the pull request checks, so documentation moves do not block unrelated work.

### HTTP details stores get wrong

Interim `100 Continue`, chunked responses, `HEAD` with a `Content-Length` and no body, keys that need careful percent-encoding in both the path and the canonical request. The client handles each, and each has a fake-server test. Other interim responses (`102`, `103`) are skipped; `101 Switching Protocols` is an error, because the client speaks only HTTP/1.1. In the canonical request an escaped `/` inside a key (`%2F`) stays escaped, since S3 treats it as part of the key, and presigned S3 URLs are always signed over `UNSIGNED-PAYLOAD`. The response parser is fuzzed with arbitrary bytes from M1: a hostile or broken endpoint must not make proofmark panic or hang.

### Store-specific set-up

Regions that are not AWS regions, virtual hosting that needs a configured domain, Object Lock that must be enabled when the bucket is created. The CI store configurations live in `stores/` with a README per store, so a user can see what was set and why. proofmark reports a missing configuration as `unsupported` with a hint, not as a violation.

### Keeping up with many vendors

The store matrix runs on pinned images (tag and digest) and compares results to a checked-in baseline per store. Updating a store is a one-line change to its image pin plus the new baseline, reviewed like code. Adding a store is a compose entry, a set-up script and a baseline.

## Testing strategy

All `cargo test` runs work offline. Network use is loopback to the fake only.

- **Signer.** The SigV4 cases from the [aws-c-auth signing test suite](https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite) (Apache-2.0, `v4` directory) that apply to S3, and the worked examples in the [S3 SigV4 documentation](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html). A deliberately wrong signer (one that normalises `//` in the path, which S3 must not do) must fail those tests.
- **Checksums.** Each CRC against the catalogue's check value for `"123456789"` (`CRC_32_ISO_HDLC` 0xcbf43926, `CRC_32_ISCSI` 0xe3069283, `CRC_64_NVME` from crc-catalog 2.5.0). The `aws-chunked` encoder against the documented frame format, and the decoder against the encoder over random sizes, including zero and exact multiples of the chunk size.
- **Parsers.** S3 XML responses captured from the stores in the matrix, kept as fixtures. The HTTP response parser, and the request parser the fake uses, are fuzzed with random bytes and with mutations of valid messages, fed in reads of 1 to 64 bytes; they must return an error, never panic or loop. The fuzzer is a seeded test (`tests/fuzz_parsers.rs`), not cargo-fuzz, which needs a nightly compiler and does not run on every platform here. `cargo test` runs it for a few seconds; `PROOFMARK_FUZZ_SECONDS=600` runs it for the ten minutes of the M1 exit test.
- **Mutation test** ([ADR 0005](adr/0005-in-process-fake-as-the-test-bed.md)). Every probe passes against the correct fake and does not pass against each fault it declares, with the status it should report (`violation` and `silent` for ignored preconditions, `unsupported` for a 501). Every fault is caught by at least one probe; every probe declares at least one fault.
- **Judges.** Each `judge` has unit tests on hand-built observations, including the edge cases: a race with zero contended rounds, a 409 from a loser, a missing `ETag`.
- **Safety.** A bucket with one object in it makes `run --use-existing-bucket` exit 3 and write nothing. A foreign object written into the bucket during the run survives cleanup. A run killed part way (the test aborts the session after N requests) leaves a ledger, and `cleanup` removes exactly the ledger entries and nothing else. A cleanup that hits an undeletable object exits 5 and keeps the ledger.
- **Races.** The race probes run 100 times against `RacyIfNoneMatch` and must catch it every time, and 100 times against the correct fake with no false finding.
- **Reports.** Golden files for the terminal, Markdown and JUnit output. The JUnit file is parsed back and its counts compared with the report. JSON round-trips through `report --input`.
- **Exit codes.** One test per code, through the real binary.
- **Real stores.** The store matrix workflow (M7), Linux only, compared with checked-in baselines. It is the check on the fake: when a real store and the fake disagree about what is correct, one of them, or the expectation, is wrong.

## Platform support

- The binary: Windows (x86_64, MSVC), Linux (x86_64, aarch64) and macOS (aarch64). CI runs the full test suite on `windows-latest`, `ubuntu-latest` and `macos-latest`, so every probe is mutation-tested on every platform against the fake.
- The store matrix runs on Linux only, because it needs Docker. Running a store locally on Windows needs Docker Desktop; that is optional and documented, not required for development.
- Minimum Rust version 1.88, set by let chains and `slice::as_chunks`. The CI `msrv` job checks it.
- `ring` needs a C compiler at build time. That is present on the CI runners and on any machine with the Rust MSVC toolchain; release binaries need no compiler.

## Security considerations

- Credentials come from the environment and are never printed, written to a report or the ledger, or included in an error message. `Authorization` headers, `X-Amz-Signature` and `X-Amz-Credential` query values, `X-Amz-Security-Token` and `x-amz-security-token` are redacted in `--verbose` output and in the exchanges recorded in reports. The `Debug` output of a request and of a signature already hides them (M1). On top of that, everything the command writes (stdout, stderr, the verbose log, report files) is scrubbed as the last step of every secret the run used: the access key id, the secret key, the session token and the signature of every request sent, each as is, percent-encoded and base64-encoded ([ADR 0009](adr/0009-reports-are-built-from-codes-and-scrubbed.md), [ADR 0013](adr/0013-output-is-scrubbed-at-the-last-step.md)). A store can echo what it was sent, as AWS does in `SignatureDoesNotMatch`; reports are built from status codes, error codes and counts, never from response bodies. A test plants a session token and searches every output format, the verbose log and the ledger for it, for the access key id, for the secret key and for every signature the fake received; another has a store echo the signature and the access key id into its error code.
- TLS verification is always on, using the operating system's trust store (rustls-native-certs) plus `--ca-file`. There is no switch to turn it off. The HTTP client only takes a TLS configuration it built itself from those roots; a caller cannot hand it a rustls configuration with a verifier of its own. If a later milestone needs to probe a store whose self-signed certificate has no CA to pass with `--ca-file`, that will be a separate option with its own name, and every report from a run that used it will say so. It is not planned.
- Reports contain the endpoint URL, bucket names and request ids. They contain no object data beyond sizes and checksums.
- The data-safety rules are in [ADR 0004](adr/0004-only-touch-what-it-wrote.md). The ledger contains bucket names, keys and version ids, nothing secret.
- proofmark trusts nothing from the endpoint: response sizes are capped (bodies proofmark did not write are read up to a limit), and each exchange has one deadline, from the name lookup to the last byte of the response. `std` has no timeout for name lookups, so the lookup runs on a helper thread and the client stops waiting for it at the deadline; a lookup still running then is left to finish on its own, so that thread can outlive the call. Under TLS, every socket read and write that rustls makes gets the time left, not a timeout set once per TLS call.
- `proofmark fake` listens on `127.0.0.1` by default, accepts one fixed test key pair, and refuses any address that is not a loopback address. It is a test tool and keeps everything in memory.
- The race probes send at most 64 concurrent requests. proofmark is not a load generator and must not be usable as one; there is no option to loop.

## Dependencies

Planned, with the newest stable version and licence as checked on crates.io on 2026-11-22. None is added before the milestone that needs it, and each is added in its own commit with the reason.

| Crate | Version | Licence | Why |
| --- | --- | --- | --- |
| `httparse` | 1.10.1 | MIT OR Apache-2.0 | Parse HTTP/1.x request and response heads and chunk sizes, for the client and the fake. |
| `rustls` | 0.23.46 | Apache-2.0 OR ISC OR MIT | TLS. Built with the `ring` provider, not the default `aws-lc-rs`, to keep the Windows build free of CMake and NASM. |
| `ring` | 0.17.14 | Apache-2.0 AND ISC | Crypto provider for rustls, and SHA-256 and HMAC-SHA256 for SigV4 ([ADR 0007](adr/0007-ring-for-crypto-own-code-for-checksums.md)). |
| `rustls-native-certs` | 0.8.5 | Apache-2.0 OR ISC OR MIT | Use the operating system's trust store. `webpki-roots` is not used: its licence, CDLA-Permissive-2.0, is not on the allow list. |
| `roxmltree` | 0.21.2 | MIT OR Apache-2.0 | Read S3 XML responses, and request bodies in the fake. Read-only; its one dependency is `memchr` (Unlicense OR MIT). Added at M2. |
| `serde_json` | 1.0.154 | MIT OR Apache-2.0 | Write and read the JSON report and the ledger. Used through `Value`, so `serde`'s derive macros are not built. Added at M2. |

Deliberately not used: the AWS SDK ([ADR 0001](adr/0001-raw-http-and-own-signer.md)); tokio, hyper and ureq ([ADR 0002](adr/0002-own-http1-client-on-blocking-sockets.md)); clap (large for six subcommands; the help text is written by hand); `lexopt`, planned for argument parsing until M2 showed six commands with a few options each need none ([ADR 0010](adr/0010-arguments-parsed-by-hand.md)); crates for base64, hex, timestamps, randomness, JUnit XML and terminal colour, each of which is a few dozen lines with tests here; `sha2`, `hmac`, `md-5` and `crc`, which were planned until M1 showed that `ring` covers SHA-256 and HMAC and that MD5 and the CRCs are small enough to own against published vectors ([ADR 0007](adr/0007-ring-for-crypto-own-code-for-checksums.md)). The random source is a seeded SplitMix64: it only needs to make payloads and key names reproducible, not secret.

## Open questions

- **A reference run on real AWS.** A contributor with a free-tier account could run proofmark against S3 and publish the report, which would check the expectations directly. The free tier's request allowance, and whether Object Lock and the multipart probes stay inside it, are not checked. Not planned; welcome if offered.
- **Ceph RGW in CI.** The `ceph/demo` image is not on Docker Hub any more (checked 2026-11-22). Whether a single-container RGW can be started in a GitHub Actions job in reasonable time is not known. If not, Ceph is left out of the published matrix and users run proofmark against their own cluster.
- **MinIO in the matrix.** `minio/minio` is no longer on Docker Hub. Whether to include the last community image from another registry, as a historical reference for people migrating away, is undecided.
- **Apache Ozone in CI.** `apache/ozone` 2.2.2 is on Docker Hub (2026-10-30), but Ozone runs as several services. Whether its compose set-up fits the CI time budget is to be found out at M7.
- **Which clients use which features.** The `table-commit`, `restic` and `loki-mimir` profiles are not written yet. Which conditional operations Iceberg and Delta writers use, and which request shapes restic (through minio-go) and Loki and Mimir send, have not been checked in their sources.
- **`If-Match` on a missing key.** The AWS page says a write with `If-Match` evaluates against existing objects; the exact status for a missing key (404 is expected) was not confirmed in the text read on 2026-11-22. To be pinned when `cond.put-if-match-missing` is written, or the probe only checks that nothing was created.
- **Short retention.** No minimum retention is documented for a per-object `RetainUntilDate`. Whether stores accept 10 seconds is unknown; if many refuse, the default goes up and the probe takes longer.
- **ureq's `Host` handling.** If ureq lets a caller send any `Host` header and leaves every other header alone, it could replace the own client ([ADR 0002](adr/0002-own-http1-client-on-blocking-sockets.md)). Not checked, and not needed for the plan.
- **`ring`'s maintenance.** Settled at M1 (2026-11-25): `ring` stays, for the reasons in [ADR 0007](adr/0007-ring-for-crypto-own-code-for-checksums.md). The latest release is still 0.17.14 from 2025-03-11; RustSec lists no open advisory against it. Revisit if that changes or rustls drops the provider.
- **Signed streaming in practice.** Which current clients still send `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (signed chunks, without a trailer) was not checked. If none does, `sum.signed-streaming` moves out of the default selection.
- **What the matrix may claim.** The published matrix says what one version of each store did with its default configuration plus the documented set-up. Vendors may object to a result. The process is the same as for expectations: evidence in a pull request.
