# 0004: proofmark only deletes what it wrote, and writes only where it may

Status: accepted, 2026-11-22

## Context

proofmark creates buckets, writes objects and versions, starts multipart uploads, puts retention on objects and deletes all of that again. It will be pointed at real stores, sometimes production ones, by people who are in the middle of a migration. A compatibility checker that deletes someone's data is the worst outcome this project can have, worse than any wrong verdict.

The usual way test suites clean up is to empty the test bucket: list everything and delete it. `go-faster/s3t` describes upstream `s3-tests` fixtures as nuking every test bucket before and after every test ([s3t README](https://github.com/go-faster/s3t), read 2026-11-22). That is fine on a throwaway server and destructive anywhere else, for example when the user passes the wrong bucket name, or another process writes into the bucket during the run.

The options considered:

1. Clean up by listing the bucket and deleting what is there, with a confirmation prompt.
2. Clean up by deleting only what this run recorded as written, and refuse to start where foreign data could be.

## Decision

Option 2. The rules, in order:

1. **Own buckets by default.** proofmark creates fresh buckets named `proofmark-<run id>-<purpose>` and deletes them at the end. Before creating one it checks the name does not exist. It never deletes a bucket it did not create in the same run.
2. **An existing bucket only on request, and only if empty.** `--bucket NAME --use-existing-bucket` lets proofmark work in a bucket it may not create (common with scoped credentials). It then refuses to start unless a listing of object versions (or of objects, if versioning is unsupported) and of in-progress multipart uploads is empty. All keys go under the prefix `proofmark-<run id>/`. The bucket itself is never deleted.
3. **A ledger, written before the write.** Every bucket creation, object write, multipart upload and retention setting is appended to a ledger file and flushed before the request is sent; the version id is appended when the response gives one. The ledger is a JSON-lines file in the working directory unless `--ledger` says otherwise.
4. **Delete only ledger entries.** Cleanup deletes exactly the keys, version ids and upload ids in the ledger, one by one. It never deletes by listing, and never sends a bulk delete built from a listing.
5. **Leftovers are reported, not forced.** If cleanup cannot remove something (an object under retention that has not expired, a store error), the run says so, keeps the ledger, and exits with code 5. `proofmark cleanup --ledger FILE` finishes the job later, also after a crash or Ctrl-C.
6. **Retention that cannot be lifted is opt-in.** Object Lock probes use governance mode with a short retention and remove it with the bypass header. Compliance mode, which no one can lift before it expires, runs only with `--allow-compliance-lock`, with a retention of at most a few minutes; the run waits for it to expire before cleanup.

## Consequences

- A wrong bucket name cannot cause deletion: either proofmark creates the bucket, or it refuses because the bucket is not empty.
- Another writer in the same bucket during the run loses nothing. The safety tests in M2 check exactly that: a foreign object written into the bucket mid-run must survive cleanup.
- A crash can leave proofmark's own objects behind until `proofmark cleanup` runs. That is the accepted price; leaving our own test data is far better than guessing what to delete.
- Users without permission to create buckets need an empty bucket. The error message says so and names the flag.
- Some probes need a special bucket (versioned, Object Lock enabled at creation). With `--use-existing-bucket` those probes are skipped unless the bucket has the needed configuration, and the report says why.
