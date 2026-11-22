# 0003: Every expectation carries its evidence, and the status says which kind

Status: accepted, 2026-11-22

## Context

A compatibility checker is only as good as its idea of the right answer, and there is no AWS account behind this project. The reference has to come from somewhere else.

Other suites have got the reference wrong. The Apache Ozone project found that `ceph/s3-tests` held a questionable expectation for conditional writes and opened [ceph/s3-tests#735](https://github.com/ceph/s3-tests/pull/735) on 2026-04-14 to align the tests with `If-None-Match: *` semantics ([Ozone blog, 2026-06-27](https://ozone.apache.org/blog/2026/06/27/ozone-s3-compatibility)). On 2026-11-22 that pull request was still open, and the repository had been archived on 2026-10-12 after the tests moved into `ceph/ceph`.

Not all expected behaviour is written down. AWS documents status codes for conditional writes in detail ([User Guide, "Conditional write behavior"](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html#conditional-error-response)), but many details clients depend on, such as the exact error code for some malformed requests, are known only from what people have observed.

And "the store does not do X" means different things. A store that answers `501 NotImplemented` to a conditional write is honest; a client sees the error. A store that answers `200` and ignores the header is the dangerous case the [NVIDIA runbook](https://docs.omniverse.nvidia.com/ovstorage/ovstorage-guide/latest/runbooks/s3-compatibility.html) (updated 2026-11-18) calls the most dangerous gap.

The options considered:

1. Pass or fail per probe, as `ceph/s3-tests` does per test.
2. Pass or fail, plus a free-text note.
3. A status that records which kind of evidence the expectation rests on, and separates an honest refusal from a silent difference.

## Decision

Option 3.

Every probe has an `Expectation` with a `basis`:

- `documented`: the AWS documentation states the behaviour. The citation is a URL, the section heading and the date it was read.
- `observed`: the behaviour is what clients observed on AWS but the documentation does not state it. The citation is a public record (an issue, a blog post, a captured exchange) with its date.

A probe's judge returns one of: matches, deviates, unsupported (the store refused with `501 NotImplemented`), or inconclusive (the probe could not set up or could not tell). The reported status combines the two:

| Judge says | Basis `documented` | Basis `observed` |
| --- | --- | --- |
| matches | `pass` | `pass` |
| deviates | `violation` | `difference` |
| refused with 501 | `unsupported` | `unsupported` |
| could not tell | `inconclusive` | `inconclusive` |

A deviation where the store accepted a request and ignored a part of it that changes the outcome (a precondition, a checksum, a retention date) is marked `silent` in the report and sorted first.

Expectations are corrected through the same process as code: a pull request with the new citation, a change to the fake server's reference behaviour, and an entry under **Expectation changes** in the changelog. Reports carry an `expectations_version` that is bumped by any such change.

## Consequences

- A reader can tell "this store breaks a documented rule" from "this store differs from what people saw on AWS" from "this store says no". These lead to different decisions.
- Writing a probe costs more: no citation, no probe. Probes that cannot be cited are not written, which leaves some useful checks out. The design lists them under open questions rather than guessing.
- Citations rot. On 2026-11-22 several S3 API reference URLs for SigV4 (for example `.../API/sigv4-streaming.html`) already redirected to the index page; the same pages answer under `.../developerguide/`. Citations therefore keep the section heading as well as the URL, and a weekly scheduled job checks that every cited URL still answers `200`.
- When every store in the matrix fails the same probe, the probe is the first suspect. The matrix report flags that case for review.
- The fake server and the probes are written from the same reading of the documentation, so they can share a misreading. The store matrix and disputes from users are the check on that; a run on real AWS would be the best check and is an open question, not a plan.
