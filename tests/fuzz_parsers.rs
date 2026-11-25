//! Fuzzes the HTTP/1.1 response parser, and the request parser the fake
//! server uses, with random bytes and with mutations of valid messages.
//! The parsers must return a value or an error for every input: never
//! panic, never hang.
//!
//! cargo-fuzz needs a nightly compiler and does not run on every platform
//! this project supports, so the fuzzer is a plain test with a seeded
//! generator. Every iteration's input is derived from the base seed and the
//! iteration number, so a failure can be replayed from the two numbers it
//! prints.
//!
//! A normal `cargo test` runs it for a few seconds. The M1 exit test runs it
//! for ten minutes:
//!
//! ```text
//! PROOFMARK_FUZZ_SECONDS=600 cargo test --release --test fuzz_parsers -- --nocapture
//! ```
//!
//! `PROOFMARK_FUZZ_SEED` fixes the base seed.
#![cfg(test)]

use std::io::{self, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proofmark::http::{parse_request, parse_response};
use proofmark::rng::SplitMix64;

const DEFAULT_SECONDS: u64 = 3;
/// No single parse may take this long. Inputs are at most a few KiB.
const STALL: Duration = Duration::from_secs(5);

const RESPONSES: &[&[u8]] = &[
    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n6\r\n world\r\n0\r\nx-amz-checksum-crc32: DUoRhQ==\r\n\r\n",
    b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 102 Processing\r\n\r\nHTTP/1.1 204 No Content\r\nx-amz-request-id: 1\r\n\r\n",
    b"HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\nETag: \"abc\"\r\n\r\n",
    b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nuntil the connection closes",
    b"HTTP/1.1 404 Not Found\r\nContent-Type: application/xml\r\nContent-Length: 99\r\n\r\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>NoSuchKey</Code><Message>gone</Message></Error>",
    b"HTTP/1.1 200 OK\r\nContent-Length: 3, 3\r\nContent-Length: 3\r\nX-Dup: a\r\nX-Dup: b\r\n\r\nabc",
    b"HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-1/10\r\nTransfer-Encoding: gzip, chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n",
];

const REQUESTS: &[&[u8]] = &[
    b"PUT /b/k HTTP/1.1\r\nHost: 127.0.0.1:9000\r\nContent-Length: 4\r\nx-amz-content-sha256: UNSIGNED-PAYLOAD\r\n\r\ndata",
    b"PUT /b/k?x-id=PutObject HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n4\r\ndata\r\n0\r\n\r\n",
    b"GET /b?list-type=2&prefix=a%2Fb HTTP/1.1\r\nHost: h\r\n\r\n",
    b"DELETE /b/k%20x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n",
];

const TOKENS: &[&[u8]] = &[
    b"\r\n",
    b"\r\n\r\n",
    b"\n",
    b"Content-Length: 18446744073709551616\r\n",
    b"Content-Length: 99999999999\r\n",
    b"Content-Length: -1\r\n",
    b"Transfer-Encoding: chunked\r\n",
    b"ffffffffffffffff\r\n",
    b"10000000000000000;x\r\n",
    b"HTTP/1.1 100 Continue\r\n\r\n",
    b"0\r\n\r\n",
    b";chunk-signature=",
    b": ",
    b"\x00",
    b"\xff\xfe",
];

/// Chunks of 1 to 64 bytes, with an occasional `Interrupted`, so the
/// parser sees every buffer boundary.
struct Trickle {
    data: Vec<u8>,
    pos: usize,
    rng: SplitMix64,
}

impl Read for Trickle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.rng.below(50) == 0 {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let n = (1 + self.rng.below(64))
            .min(buf.len())
            .min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn pick<'a>(rng: &mut SplitMix64, items: &[&'a [u8]]) -> &'a [u8] {
    items[rng.below(items.len())]
}

fn mutate(rng: &mut SplitMix64, input: &mut Vec<u8>, corpus: &[&[u8]]) {
    for _ in 0..=rng.below(8) {
        let len = input.len();
        match rng.below(8) {
            0 if len > 0 => {
                let i = rng.below(len);
                input[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.below(len);
                input[i] = *pick(
                    rng,
                    &[b"\r", b"\n", b":", b" ", b"0", b"f", b";", b"\x00", b"\x7f"],
                )
                .first()
                .unwrap_or(&0);
            }
            2 => {
                let at = rng.below(len + 1);
                let token = pick(rng, TOKENS);
                input.splice(at..at, token.iter().copied());
            }
            3 if len > 0 => {
                let start = rng.below(len);
                let end = (start + 1 + rng.below(16)).min(len);
                input.drain(start..end);
            }
            4 if len > 0 => {
                let start = rng.below(len);
                let end = (start + 1 + rng.below(32)).min(len);
                let copy = input[start..end].to_vec();
                let at = rng.below(input.len() + 1);
                input.splice(at..at, copy);
            }
            5 => input.truncate(rng.below(len + 1)),
            6 => {
                let other = pick(rng, corpus);
                let from = rng.below(other.len() + 1);
                input.truncate(rng.below(len + 1));
                input.extend_from_slice(&other[from..]);
            }
            _ => {
                let at = rng.below(len + 1);
                let noise_len = 1 + rng.below(16);
                let noise = rng.bytes(noise_len);
                input.splice(at..at, noise);
            }
        }
    }
}

/// One iteration: builds an input from (`base`, `iteration`) and parses it.
fn run_one(base: u64, iteration: u64) {
    let mut rng = SplitMix64::new(base ^ iteration.wrapping_mul(0x9e37_79b9_7f4a_7c15));
    let as_request = rng.below(4) == 0;
    let corpus = if as_request { REQUESTS } else { RESPONSES };
    let mut input = if rng.below(10) == 0 {
        let len = rng.below(512);
        rng.bytes(len)
    } else {
        pick(&mut rng, corpus).to_vec()
    };
    mutate(&mut rng, &mut input, corpus);
    let max_body = if rng.below(2) == 0 {
        rng.below(4096)
    } else {
        1 << 20
    };
    let reader = Trickle {
        data: input,
        pos: 0,
        rng: SplitMix64::new(rng.next_u64()),
    };
    if as_request {
        if let Ok(request) = parse_request(reader, max_body) {
            assert!(
                request.body().len() <= max_body,
                "request body over the limit"
            );
        }
    } else {
        let method = ["GET", "HEAD", "PUT"][rng.below(3)];
        if let Ok(response) = parse_response(reader, method, max_body) {
            assert!(
                response.body().len() <= max_body,
                "response body over the limit"
            );
            assert!(
                (200..=999).contains(&response.status()),
                "interim status returned as final"
            );
            if method == "HEAD" {
                assert_eq!(response.body(), b"", "a HEAD response with a body");
            }
        }
    }
}

#[test]
#[expect(
    clippy::print_stderr,
    reason = "the fuzz run reports its seed and count so a failure can be replayed"
)]
fn the_parsers_never_panic_or_hang_on_any_input() {
    let seconds = std::env::var("PROOFMARK_FUZZ_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SECONDS);
    let base = std::env::var("PROOFMARK_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(1, |d| d.as_secs())
        });
    eprintln!("fuzzing the HTTP parsers for {seconds} s, base seed {base}");

    let progress = Arc::new(AtomicU64::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let worker = {
        let (progress, done) = (Arc::clone(&progress), Arc::clone(&done));
        thread::spawn(move || {
            let mut iteration = 0u64;
            while Instant::now() < deadline {
                progress.store(iteration, Ordering::SeqCst);
                run_one(base, iteration);
                iteration += 1;
            }
            done.store(true, Ordering::SeqCst);
            iteration
        })
    };

    let mut last = (u64::MAX, Instant::now());
    while !done.load(Ordering::SeqCst) && !worker.is_finished() {
        thread::sleep(Duration::from_millis(100));
        let now = progress.load(Ordering::SeqCst);
        if now != last.0 {
            last = (now, Instant::now());
        } else if last.1.elapsed() > STALL {
            panic!("hang: iteration {now} with base seed {base} has run for over {STALL:?}");
        }
    }
    match worker.join() {
        Ok(iterations) => eprintln!("{iterations} inputs, no panic and no hang"),
        Err(panic) => panic!(
            "the parser panicked at iteration {} with base seed {base} ({:?}); replay with PROOFMARK_FUZZ_SEED={base}",
            progress.load(Ordering::SeqCst),
            panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
        ),
    }
}

#[test]
fn the_seed_corpus_parses() {
    for (i, input) in RESPONSES.iter().enumerate() {
        assert!(
            parse_response(*input, "GET", 1 << 20).is_ok(),
            "response {i}"
        );
    }
    for (i, input) in REQUESTS.iter().enumerate() {
        assert!(parse_request(*input, 1 << 20).is_ok(), "request {i}");
    }
}
