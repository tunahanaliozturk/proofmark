# 0012: An existing bucket must be shown empty and never versioned

Status: accepted, 2026-11-27. Amends rule 2 of [ADR 0004](0004-only-touch-what-it-wrote.md).

## Context

ADR 0004 lets proofmark work in an existing bucket only if it is empty, checked by listing object versions and multipart uploads. The M2 code let several answers through that do not show that:

- A `501` to the version listing fell back to `ListObjectsV2`. Current objects say nothing of old versions and delete markers.
- A `501` to the upload listing counted as no uploads. A store that cannot list uploads may still hold some.
- Any listing root counted, including `<ListVersionsResult/>` with no `IsTruncated`, and an empty uploads listing returned for the versions request.

There was a second gap. In a bucket that has had versioning on, a plain `DELETE` does not remove an object: it adds a delete marker, and an unversioned write's version is kept. Cleanup sends plain deletes when it does not know a version id, so it could call itself complete and remove the ledger with versions and markers left behind. ADR 0008 left versioned buckets to M5.

## Decision

1. **Only a positive reading is empty.** Each listing must answer `200` with the root element of the operation asked for (`ListVersionsResult`, `ListMultipartUploadsResult`), `IsTruncated` present and `false`, and no entry. Any other answer, a `501` included, refuses the bucket with exit 3. There is no fallback listing.
2. **An existing bucket must never have had versioning on.** `GetBucketVersioning` must answer `200` with a `VersioningConfiguration` that has no `Status`. `Enabled`, `Suspended`, an error or anything unreadable refuses the bucket with exit 3, before the ledger exists.

## Consequences

- `the_empty_check_counts_what_it_cannot_read_as_empty_as_not_empty` and `an_existing_bucket_that_may_be_versioned_is_refused_before_any_write` test both rules against a scripted server; the fake answers `GetBucketVersioning` as an unversioned bucket.
- A store that implements neither listing or `GetBucketVersioning` cannot be used with `--use-existing-bucket`. The refusal says so and points at the default, a bucket proofmark creates itself.
- Whether a run may use a versioned existing bucket, deleting by version id, is left to M5, where versioning probes arrive. The roadmap lists it there.
