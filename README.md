# proofmark

One binary that probes an S3-compatible endpoint and reports, feature by feature, whether it behaves the way S3 clients now expect. Point it at Garage, SeaweedFS, RustFS, Ceph RGW, Ozone or any other store before you move data onto it, and it tells you which rules the store breaks, which it refuses honestly, and which it silently ignores.

A proof mark is the stamp a proof house strikes on a gun barrel after it has survived a test firing. proofmark test-fires an endpoint.

## Status

Milestones M1 (wire and signing) and M2 (safety, runner and reports) of the roadmap are built. The 14 `basic` probes run; the other features come in later milestones. To try it with no store at all:

```
proofmark fake                      # one terminal: prints a published test key pair
# another terminal: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to that pair, then
proofmark run --endpoint http://127.0.0.1:9000 --report json=out.json
```

What exists, and the test behind each claim:

- `run`, `list`, `explain`, `cleanup` and `fake`, with one test per exit code through the real binary (`tests/cli.rs`, `exit_0_...` to `exit_5_...`).
- The 14 `basic` probes: object `PUT`, `GET`, `HEAD`, `DELETE`, metadata, ranges, `Content-MD5`, signatures, `100 Continue` and the common error responses. Each passes against the in-process fake and reports each fault it exists to catch with the right status and silence (`tests/probes.rs`).
- Data safety ([ADR 0004](docs/adr/0004-only-touch-what-it-wrote.md), [ADR 0008](docs/adr/0008-what-cleanup-infers-from-the-ledger.md), [ADR 0011](docs/adr/0011-a-ledger-names-only-what-proofmark-writes.md), [ADR 0012](docs/adr/0012-an-existing-bucket-must-be-shown-empty-and-unversioned.md)). A non-empty existing bucket makes `run` exit 3 having sent no write; so does one whose listings or versioning cannot be read as empty and never versioned (`the_empty_check_counts_what_it_cannot_read_as_empty_as_not_empty`, `an_existing_bucket_that_may_be_versioned_is_refused_before_any_write`). An object another client writes into the bucket mid-run survives cleanup. A run killed as any one of its requests arrives, for every request in the run, leaves a ledger from which `cleanup` puts the store back exactly as it was (`tests/cli.rs`). Cleanup refuses a ledger that names anything proofmark does not write (`cleanup_refuses_a_ledger_that_names_data_proofmark_does_not_write`), a key it removed that someone writes again survives the next cleanup (`a_second_cleanup_leaves_a_key_someone_wrote_after_the_first`), and no probe deletes a key the run did not write (`no_probe_deletes_a_key_the_run_has_not_written`).
- Secrets kept out of output ([ADR 0009](docs/adr/0009-reports-are-built-from-codes-and-scrubbed.md), [ADR 0013](docs/adr/0013-output-is-scrubbed-at-the-last-step.md)): a planted session token, the access key id, the secret key and every signature sent appear in none of the terminal output, the verbose log, the three report files and the ledger (`a_planted_secret_appears_in_no_output`); a signature or access key id that the store echoes into its error code is not printed (`a_secret_the_store_echoes_into_an_error_code_appears_in_no_output`); percent-encoded and base64 copies are scrubbed too (`scrub_covers_the_access_key_id_and_encoded_forms_of_each_secret`).
- From M1: a SigV4 signer that passes the 32 applicable cases of the aws-c-auth suite and the S3 guide's worked examples (`tests/sigv4_vectors.rs`); an HTTP/1.1 client with TLS, `100 Continue` and one deadline per exchange (`src/http.rs`, `tests/fake_round_trip.rs`); CRC32, CRC32C, CRC64NVME, MD5 and SHA-256 pinned to published check values (`src/checksum.rs`); a response parser fuzzed for ten minutes with no panic and no hang (`tests/fuzz_parsers.rs`).

The plan:

- [docs/design.md](docs/design.md): what it will do, what it will not do, and how each claim will be tested.
- [docs/roadmap.md](docs/roadmap.md): milestones to the first release, each with an exit test.
- [docs/adr/](docs/adr/): decisions that had a real alternative.

## The problem

"S3-compatible" stores differ from Amazon S3 in ways that corrupt data or break clients, and operators tend to find out in production.

- **People are moving between stores.** MinIO stopped publishing Docker images in October 2025 and ended active development of the community edition in December 2025 ([Linuxiac, December 2025](https://linuxiac.com/minio-ends-active-development/)). The `minio/minio` repository is no longer on Docker Hub (checked 2026-11-22). Its users are looking at Garage, SeaweedFS, RustFS, Ceph RGW and Apache Ozone.
- **SDK defaults changed under everyone.** In January 2025 the AWS SDKs started sending CRC checksums on uploads by default, often as a trailer on an `aws-chunked` body ([AWS SDK reference](https://docs.aws.amazon.com/sdkref/latest/guide/feature-dataintegrity.html), read 2026-11-22). Cloudflare R2 rejected those requests from 17 January to 3 February 2025 ([R2 incident](https://www.cloudflarestatus.com/incidents/t5nrjmpxc1cj)), and the Apache Iceberg project proposed turning the checksums off ([xuanwo.io, 2025-02-20](https://xuanwo.io/links/2025/02/aws_s3_sdk_breaks_its_compatible_services/)).
- **Conditional writes can be accepted and ignored.** Table formats, backup tools and other software use `If-None-Match` and `If-Match` as a lock. A store that accepts the header but does not enforce it loses data with no error. NVIDIA's storage runbook calls this the most dangerous gap and tells readers to test it deliberately, without naming a tool ([NVIDIA runbook](https://docs.omniverse.nvidia.com/ovstorage/ovstorage-guide/latest/runbooks/s3-compatibility.html), updated 2026-11-18). Garage once answered a stale `If-Match` read with `200` ([Garage #804](https://git.deuxfleurs.fr/Deuxfleurs/garage/issues/804)). Applications end up writing their own admission probes for this ([block/buzz, "Conformance"](https://github.com/block/buzz/blob/main/docs/git-on-object-storage.md)).
- **The existing suites are hard to run and sometimes wrong.** `minio/mint` is archived. `ceph/s3-tests` moved into the `ceph/ceph` repository in October 2026 and needs Python and tox. The Apache Ozone project built a whole dashboard to run those two suites daily, and found an `s3-tests` expectation for conditional writes that it had to dispute ([Ozone blog, 2026-06-27](https://ozone.apache.org/blog/2026/06/27/ozone-s3-compatibility)). Vendors' compatibility tables go out of date, and TrueNAS's evaluation guide says to test your own workload rather than compare feature lists ([TrueNAS, 2026-11-02](https://www.truenas.com/blog/how-to-evaluate-s3-compatible-object-storage/)).

## What the first release will do

- Run about 80 probes, grouped by feature: basic object operations and error codes; path-style and virtual-host addressing; `ListObjectsV2` pagination, delimiters and unusual keys; multipart uploads; checksums, including the shapes SDKs send by default since 2025; conditional `PUT`, `GET`, copy and multipart completion, including a race where N writers use `If-None-Match` and exactly one may win; versioning; Object Lock with a short retention; presigned URLs; `CopyObject` metadata.
- Pick the probes a client needs through profiles: the 2025 AWS SDK defaults, table-format commits, restic, Loki and Mimir, immutable backups.
- Give each probe one of five statuses: `pass`, `violation` (breaks documented AWS behaviour), `difference` (differs from what clients observed on AWS), `unsupported` (the store refuses honestly) or `inconclusive`. A violation where the store accepted a request and ignored part of it is marked `silent`. Every expectation cites the AWS documentation section, or the public record, it rests on.
- Write a terminal matrix, JSON, JUnit for CI and a Markdown matrix.
- Leave no trace and touch nothing it did not write. It creates its own buckets, records every write in a ledger before sending it, and deletes only ledger entries. It refuses to work in a bucket that is not empty.
- Run the same on Windows, macOS and Linux.
- Publish its own matrix: a CI job in this repository runs proofmark against container images of open stores, so the claims about each store can be reproduced.

## What it will not do

- Measure performance, test IAM and bucket policies, lifecycle rules over time, replication, S3 Select, website hosting, server-side encryption, ACLs, POST uploads from browser forms, SigV4a or HTTP/2.
- Prove anything. A pass means the store behaved as expected for the requests proofmark sent, on that build, configuration and load. A race probe that passes saw no lost update in the rounds it ran; it cannot show that none is possible.
- Detect durability problems: data lost on a crash, bit rot, a node that drops writes under failure. It sees the store as one client sees it.
- Replace your application's own tests. A pass on a profile says the store follows the rules that client relies on, as far as the probes go. It does not say the client works.
- Know the right answer for certain. There is no AWS account behind this project. The expectations come from the AWS documentation and public records, and they can be wrong; each one shows its evidence so you can check it, and disputes are welcome ([CONTRIBUTING.md](CONTRIBUTING.md)).

## Licence

Dual licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.
