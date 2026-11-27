# 0011: A ledger names only what proofmark writes, and records its deletes

Status: accepted, 2026-11-27. Amends [ADR 0008](0008-what-cleanup-infers-from-the-ledger.md).

## Context

A review of M2 found four ways the ledger and cleanup could delete data that proofmark did not write, against [ADR 0004](0004-only-touch-what-it-wrote.md):

- Cleanup deleted whatever a ledger named once the endpoint matched. A ledger is a plain file; an edited or swapped one with `{"op":"put_object","bucket":"customer-data","key":"payroll.csv"}` deleted that object.
- `basic.delete-missing` sent a `DELETE` to a key the run had never written. Had someone written that key, it would have been deleted.
- A cleanup that kept its ledger (a foreign object held the bucket) sent the same deletes again next time. A key it had removed, which someone wrote in between, was deleted.
- A write the store refused still counted as a write, so cleanup deleted that key although the run never wrote it.

It also found the opposite mistake: every non-2xx `CreateBucket` outcome dropped the bucket from the plan, including a 5xx after which the bucket may exist.

## Decision

1. **A ledger is trusted only where it names proofmark's own data.** Before cleanup sends anything it checks, on the one read it deletes from, that the ledger was written for this endpoint, that its run id is shaped like one proofmark makes, that every bucket is `proofmark-<run id>-*` or the bucket given with `--bucket`, and that every key is under `proofmark-<run id>/`. Anything else refuses the whole ledger with exit 2, naming the line. Keys in a run's own bucket now carry the same prefix as in an existing bucket, so one rule covers both. `proofmark cleanup` takes `--bucket NAME` for a run that used an existing bucket.
2. **A probe never deletes or overwrites a key it did not create.** The session refuses, without sending, a `DELETE` of a key no write of this run created, any bucket `DELETE` from a probe, and a write to a key whose earlier write failed. `basic.delete-missing` writes its key, deletes it, and judges the second `DELETE`.
3. **Deletes are recorded.** Cleanup and the probes append each delete to the ledger as an outcome (`delete_object`, `delete_bucket`). The plan reads the ledger in order, and a recorded delete ends what was written before it. A delete that happened and was not recorded (a crash in between) is sent again, which is harmless; a recorded one is never repeated.
4. **A refused write is not ours; a failed one may be.** An outcome of 3xx or 4xx means the store refused the write, and cancels its intent, for objects as for buckets. A 5xx is treated like a missing answer: the write may have happened.

## Consequences

- `cleanup_refuses_a_ledger_that_names_data_proofmark_does_not_write`, `no_probe_deletes_a_key_the_run_has_not_written`, `a_probe_cannot_delete_or_overwrite_a_key_it_did_not_create`, `a_second_cleanup_leaves_a_key_someone_wrote_after_the_first` and `plans_only_what_may_have_been_written_and_not_yet_deleted` test each point.
- A store that refuses a write with a 4xx and stores the object anyway leaves that object behind, and cleanup does not know. The probe that sent the write reports the store as broken (`basic.bad-signature` and `basic.content-md5-mismatch` check exactly that), and leaving our object is the side ADR 0004 prefers.
- Some risk is left. A bucket whose creation got no answer is deleted on the strength of its random name and the `HeadBucket` check just before; someone could create that exact name in between. A delete that was sent but not recorded is sent again, so someone writing that key in the moment between is not protected. Both need a coincidence on a random run id or a crash at one exact point.
- The ledger format gains two ops. It stays format 1: nothing has been released.
