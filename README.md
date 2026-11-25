# proofmark

One binary that probes an S3-compatible endpoint and reports, feature by feature, whether it behaves the way S3 clients now expect. Point it at Garage, SeaweedFS, RustFS, Ceph RGW, Ozone or any other store before you move data onto it, and it tells you which rules the store breaks, which it refuses honestly, and which it silently ignores.

A proof mark is the stamp a proof house strikes on a gun barrel after it has survived a test firing. proofmark test-fires an endpoint.

## Status

Milestone M1 of the roadmap, the wire and signing layer, is built. There are no commands yet: the binary still prints its name and version and exits. What M1 added, and the test behind each claim:

- A SigV4 signer for headers, presigned URLs and `aws-chunked` chunk and trailer signatures. It passes the 32 cases of the aws-c-auth signing suite that apply to S3 and the worked examples in the S3 guide (`tests/sigv4_vectors.rs`).
- An HTTP/1.1 client on blocking sockets, with TLS, `100 Continue`, chunked responses and a timeout per exchange. It sends headers exactly as built (`src/http.rs` unit tests, `tests/fake_round_trip.rs`).
- CRC32, CRC32C, CRC64NVME, MD5 and SHA-256, each pinned to published check values (`src/checksum.rs` unit tests).
- An in-process fake S3 server: path-style bucket and object `PUT`, `GET`, `HEAD` and `DELETE`, with signature checks, over HTTP or TLS. A signed upload and download round-trip through it, and a wrong secret gets `403` (`tests/fake_round_trip.rs`).
- The HTTP response parser ran for ten minutes under a fuzzer, 365 million inputs, with no panic and no hang (`tests/fuzz_parsers.rs`).

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
