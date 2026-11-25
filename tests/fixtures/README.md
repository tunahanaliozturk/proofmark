# Test fixtures

## `aws-signing-test-suite/v4`

Copied unchanged from [awslabs/aws-c-auth](https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4), commit `f556deacd6e6d9dbf540ff00a9bf383688076874` (2026-11-19). Licensed under the Apache License 2.0, the same text as [LICENSE-APACHE](../../LICENSE-APACHE). `tests/sigv4_vectors.rs` explains which cases apply to S3 and why.

The files are compared byte for byte and have LF line ends, as upstream, so `.gitattributes` keeps git from converting them. Copy them with `git -c core.autocrlf=false archive`; a checkout with `core.autocrlf` on gives them Windows line ends.
