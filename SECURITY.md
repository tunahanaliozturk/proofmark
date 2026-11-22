# Security policy

## Reporting a vulnerability

Report it privately through GitHub: the **Security** tab of this repository, then **Report a vulnerability**. Please do not open a public issue, discussion or pull request for it.

Include what you found and how to reproduce it. You will get an answer within 7 days, and a fix or a plan within 30 days for confirmed issues. You are credited in the advisory unless you ask not to be.

## Supported versions

Security fixes go into the latest release only.

## What counts

proofmark writes to and deletes from the storage it is pointed at, so the most serious bugs are the ones that touch data it does not own.

- proofmark deleting or overwriting an object, a version or a bucket that it did not create in the same run, or that is not listed in its ledger.
- proofmark writing into a bucket that was not empty or not created by it, without the explicit flag that allows it.
- A secret key, session token, `Authorization` header or presigned URL signature appearing in terminal output, a report file, the ledger or a log.
- A TLS connection that proceeds although the certificate does not verify.
- A response from the endpoint that makes proofmark panic, hang, or use memory without bound.
- The fake server (`proofmark fake`) listening on a non-loopback address without being told to.

Out of scope: a store that misbehaves when it receives the requests proofmark is documented to send. That is what proofmark reports, not a flaw in it.
