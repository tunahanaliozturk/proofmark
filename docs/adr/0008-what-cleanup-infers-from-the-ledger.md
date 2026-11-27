# 0008: What cleanup infers from the ledger

Status: accepted, 2026-11-25. Amended by [ADR 0011](0011-a-ledger-names-only-what-proofmark-writes.md) (which ledgers are trusted, recorded deletes, refused writes) and [ADR 0012](0012-an-existing-bucket-must-be-shown-empty-and-unversioned.md) (versioned buckets).

## Context

[ADR 0004](0004-only-touch-what-it-wrote.md) says cleanup deletes only what the ledger names, and that each write is recorded before it is sent. Building it (M2) needed answers the ADR leaves open, all about a ledger that is not tidy:

- A write announced but with no recorded outcome. The process died, or the connection did, between sending and reading the response. The write may or may not have happened.
- A bucket creation answered with an error, such as `409 BucketAlreadyExists`. The bucket exists, but it is not this run's.
- A last line cut off by a crash in the middle of writing it.
- A write that returned a version id, in an existing bucket that has versioning on. A plain `DELETE` there does not remove the object; it adds a delete marker.
- The run's own cleanup at the end, and `proofmark cleanup` after a crash: whether they share one path.

The exit test makes these concrete: a run killed after N requests, for every N, must leave a ledger from which `cleanup` removes exactly what the run wrote.

## Decision

1. **An intent counts as a write.** Every key with an intent in the ledger is deleted, whether or not an outcome follows. Deleting a key that was never written costs one `204`. A bucket with an intent and no outcome is deleted too: its name has this run's random id in it, and the run checked with `HeadBucket` that it did not exist just before.
2. **A refused creation is not ours.** A bucket whose creation outcome is not 2xx is left alone, even if the same ledger has an intent for it.
3. **Version ids when known, a plain delete when not.** Each version id a write returned is deleted by id. A plain `DELETE` is sent as well only if some write of that key has no version id recorded (an unversioned bucket, or a missing outcome).
4. **A cut-off last line is skipped; any other bad line stops cleanup.** Lines are written and flushed one at a time before the request goes out, so a cut-off last line is an intent whose request was never sent. Damage anywhere else means the file is not what proofmark wrote, and guessing could delete the wrong thing.
5. **One path.** The run's own cleanup closes the ledger and reads it back from disk, exactly as `proofmark cleanup` does. Nothing is deleted from memory.
6. **The ledger exists only once a write may follow.** It is created after preflight and the read-only safety checks, so a refusal leaves no file. It is removed when cleanup leaves nothing, and kept otherwise.
7. **A ledger belongs to one endpoint.** `proofmark cleanup` refuses a ledger whose recorded endpoint differs from `--endpoint`.

## Consequences

- `a_run_killed_after_any_number_of_requests_leaves_a_ledger_that_cleanup_finishes` (`tests/cli.rs`) kills the binary as each request in turn reaches the fake, lets the fake carry the request out, and checks that `cleanup` puts the store back exactly as it was, with someone else's bucket and object untouched.
- A key written into a versioned bucket whose response was lost leaves a version proofmark cannot name, and the plain delete adds a delete marker. Removing that version would mean listing, which ADR 0004 rules out. This is left as it is until versioned buckets arrive in M5, which will decide whether a run in a versioned existing bucket needs its own rule.
- A refused cleanup keeps the ledger, so running `proofmark cleanup` again is always safe: every delete is idempotent.
