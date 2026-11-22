# 0001: Raw HTTP and an own SigV4 signer, not the AWS SDK

Status: accepted, 2026-11-22

## Context

proofmark sends requests to a store and judges the answers. Two kinds of request matter most:

- The exact shapes that current SDKs send by default. Since early 2025 the AWS SDKs add CRC checksums to uploads by default, often as a trailer at the end of an `aws-chunked` body ([AWS SDK reference, "Data Integrity Protections for Amazon S3"](https://docs.aws.amazon.com/sdkref/latest/guide/feature-dataintegrity.html), read 2026-11-22). That default broke several stores ([R2 incident, 17 January to 3 February 2025](https://www.cloudflarestatus.com/incidents/t5nrjmpxc1cj); [xuanwo.io, 2025-02-20](https://xuanwo.io/links/2025/02/aws_s3_sdk_breaks_its_compatible_services/)).
- Variants an SDK would never send on its own: a wrong checksum in a trailer, a mismatched `x-amz-content-sha256`, a tampered presigned URL, a request that is in flight at the same moment as seven others.

The responses also matter byte for byte: which status, which error code in the XML body, whether a checksum header comes back, whether the stored object contains the `aws-chunked` framing instead of the data.

There were three ways to build the requests:

1. Use the AWS SDK for Rust and configure or intercept it.
2. Use a general S3 client crate.
3. Build each request by hand and sign it with a SigV4 signer written here.

## Decision

Option 3. proofmark builds every request itself: method, target, header list in order, body bytes. A signer in this repository implements SigV4 for the `Authorization` header, for presigned URLs, and for signed `aws-chunked` streaming with trailers. Nothing between proofmark and the socket adds, removes or reorders a header.

## Consequences

- A probe shows exactly what it sent and what came back. The report can print both, minus secrets.
- Sending a deliberately wrong request is as easy as sending a right one. With an SDK, many of the wrong variants need hooks that fight the SDK's own validation.
- proofmark does not drift when an SDK changes its defaults. That is also a cost: it does not follow the SDKs automatically either. The request shapes that stand for "what SDKs send" are captured from real SDKs and checked in as fixtures at M4, and a probe's shape is tested against them.
- The signer is new code and signing bugs are easy to make. It is tested against the AWS signing test suite in [awslabs/aws-c-auth](https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite) (Apache-2.0) and the worked examples in the S3 documentation before any probe uses it (M1).
- The dependency tree stays small: no SDK, no async runtime. See [ADR 0002](0002-own-http1-client-on-blocking-sockets.md) for the transport.
