# 0013: Output is scrubbed at the last step, in every encoded form

Status: accepted, 2026-11-27. Amends [ADR 0009](0009-reports-are-built-from-codes-and-scrubbed.md).

## Context

ADR 0009 scrubbed chosen strings (details, targets, request ids, leftovers, log lines) of the secret key, the session token and each signature, matched as is. A review of M2 showed what that misses:

- Text that was never scrubbed: refusals printed to stderr, report metadata, usage errors. A store that answered the preflight with the request's signature as its error code got the signature printed, because a 64-character hex string passes the error-code filter.
- The access key id was not on the list.
- Encoded copies: a token with `/` echoed in a header as `%2F`, or a key pair echoed inside base64.
- The ledger's version ids were scrubbed, so a short secret could turn the id `abc` into `<redacted>bc`, and cleanup would delete a version that does not exist and call itself complete.

## Decision

1. **One shared list.** `Secrets` holds every secret a command uses: the access key id, the secret key and the session token from the environment, read when the command starts, and each signature as it is made. Clones share the list.
2. **Every form.** Each secret is held as is, percent-encoded as SigV4 encodes it, and base64-encoded: alone, and as the run of characters that depends only on the secret at each of the three offsets it can have inside a longer base64 text. Encoded forms shorter than 8 characters are left out, because they would match ordinary text.
3. **The last step.** The command holds its stdout and stderr and writes them scrubbed when it ends. Report files are scrubbed as they are written, and the verbose log line by line. A panic prints only its location. `proofmark fake` writes as it goes, because it serves until stopped, and prints only its own published key pair.
4. **Never what is sent back.** Values proofmark later sends as request input are kept exactly: the ledger records version ids as the store gave them. The ledger is a record of what to delete, not output.

## Consequences

- `a_secret_the_store_echoes_into_an_error_code_appears_in_no_output`, `scrub_covers_the_access_key_id_and_encoded_forms_of_each_secret`, `the_ledger_keeps_a_version_id_exactly_as_the_store_sent_it` and `a_planted_secret_appears_in_no_output` (which now also looks for the access key id) test it.
- Scrubbing the access key id also hides it where it is harmless, such as an echoed `Credential=` scope. That is the price of never printing it.
- A secret that is a common word, or a single character, makes the output hard to read, since every occurrence is replaced. That is the user's configuration; printing the secret would be worse.
- Forms not covered: lowercase percent escapes, a secret split across lines, or one encoded twice. Reports are still built from codes and counts, never from bodies, which keeps those out in the first place.
