# 0002: An own HTTP/1.1 client on blocking sockets, threads for concurrency

Status: accepted, 2026-11-22

## Context

[ADR 0001](0001-raw-http-and-own-signer.md) settles that proofmark builds requests by hand. Something still has to put them on the wire and read the answers. The requirements:

- No header added, removed, reordered or rewritten without the probe asking. That includes `Host`: virtual-host addressing is tested by connecting to the endpoint's address and sending `Host: bucket.endpoint`, so that no wildcard DNS is needed.
- Interim `100 Continue` responses handled, and a probe able to send `Expect: 100-continue` as SDKs do for uploads.
- Status codes are data. A `412` is a result, not an error.
- Several requests really in flight at the same moment, for the conditional-write races. A race probe holds N connections open, handshakes done, and releases all N requests together.
- Runs on Windows, macOS and Linux, with and without TLS.
- The fake S3 server ([ADR 0005](0005-in-process-fake-as-the-test-bed.md)) needs an HTTP/1.1 server, so the parsing code serves both sides.

The options considered:

1. **ureq 3** (MIT OR Apache-2.0, 3.5.2 released 2026-11-12), a small blocking client. By default it treats 4xx and 5xx as errors, follows up to 10 redirects and adds `user-agent`, `accept` and `accept-encoding` headers; all of these can be configured off ([`ConfigBuilder` docs](https://docs.rs/ureq/latest/ureq/config/struct.ConfigBuilder.html), read 2026-11-22). The documentation does not say whether a caller can set `Host` independently of the connect address.
2. **hyper 1.x on tokio** (both MIT). Full control over the request, real concurrency through tasks, but an async runtime for a tool that sends a few hundred requests, and a second runtime story inside the fake server.
3. **An own minimal HTTP/1.1 client** on `std::net::TcpStream`, with rustls for TLS and [httparse](https://docs.rs/httparse/latest/httparse/) (MIT OR Apache-2.0, 1.10.1) to parse response heads and chunk sizes. Threads for concurrency.

## Decision

Option 3. One connection per request at first (keep-alive is a later optimisation, not needed for correctness). Each race worker is a thread with its own connection; a `std::sync::Barrier` releases them together. Request heads are written exactly as the probe built them. Response parsing handles `Content-Length`, chunked transfer encoding, connection close, `HEAD`, `1xx`, `204` and `304`.

## Consequences

- No async runtime and no client library between the probe and the socket. What a probe built is what was sent.
- HTTP/1.1 only. A store that behaves differently over HTTP/2 is not tested that way. HTTP/2 is listed as a non-goal in the design; if users report clients that depend on it, this decision is revisited.
- The client parser is code to own. It is small because the peer is a server answering requests proofmark chose, and it is fuzzed against arbitrary bytes from M1 so a hostile endpoint cannot make proofmark panic or hang.
- Threads cost memory per worker. The race width is capped (64 by default) and that is plenty to expose a missing lock.
- If ureq turns out to give full header control, swapping is cheap because probes only see proofmark's own `Request` and `Response` types. Nothing in the probe code depends on the transport.
