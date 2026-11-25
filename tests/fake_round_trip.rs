//! Signed requests through the client to the in-process fake server, over
//! plain HTTP and over TLS. Everything binds 127.0.0.1 on a port the system
//! picks.
#![cfg(test)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use proofmark::aws_chunked;
use proofmark::checksum::{hex, md5, sha256_hex};
use proofmark::fake::{self, FakeConfig, FakeServer};
use proofmark::http::{
    Client, Endpoint, HttpError, Request, Response, tls_config_native, tls_config_with_roots,
};
use proofmark::rng::SplitMix64;
use proofmark::sigv4::{Credentials, STREAMING_SIGNED, Signer};
use proofmark::time::UtcTime;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls")
            .join(name),
    )
    .expect("fixture")
}

/// A request with `host` and, when there is a body, `content-length`,
/// signed with `credentials` over the SHA-256 of the body.
fn signed(
    endpoint: &Endpoint,
    credentials: &Credentials,
    method: &str,
    path: &str,
    body: &[u8],
) -> Request {
    let mut request = Request::new(method, path).with_header("host", &endpoint.authority());
    if !body.is_empty() {
        request.push_header("content-length", &body.len().to_string());
    }
    let mut request = request.with_body(body.to_vec());
    Signer::new(credentials, fake::DEFAULT_REGION, "s3", UtcTime::now())
        .sign_request(&mut request, &sha256_hex(body));
    request
}

fn error_code(response: &Response) -> String {
    let body = String::from_utf8_lossy(response.body());
    let start = body.find("<Code>").map_or(0, |i| i + 6);
    let end = body.find("</Code>").unwrap_or(start);
    body[start..end].to_owned()
}

fn round_trip(server: &FakeServer, client: &Client) {
    let endpoint = server.endpoint();
    let creds = fake::credentials();
    let send = |method: &str, path: &str, body: &[u8]| {
        client
            .send(&endpoint, &signed(&endpoint, &creds, method, path, body))
            .expect("exchange")
    };
    let data = SplitMix64::new(42).bytes(100_000);

    assert_eq!(send("PUT", "/round-trip", b"").status(), 200);
    let put = send("PUT", "/round-trip/some%20dir/key%2Bone.bin", &data);
    assert_eq!(put.status(), 200);
    let etag = format!("\"{}\"", hex(&md5(&data)));
    assert_eq!(put.header("etag"), Some(etag.as_str()));

    let get = send("GET", "/round-trip/some%20dir/key%2Bone.bin", b"");
    assert_eq!(get.status(), 200);
    assert_eq!(get.body(), data);
    assert_eq!(get.header("etag"), Some(etag.as_str()));

    let head = send("HEAD", "/round-trip/some%20dir/key%2Bone.bin", b"");
    assert_eq!(head.status(), 200);
    assert_eq!(head.header("content-length"), Some("100000"));
    assert_eq!(head.body(), b"");

    let list = send("GET", "/round-trip", b"");
    assert_eq!(list.status(), 200);
    assert!(String::from_utf8_lossy(list.body()).contains("<Key>some dir/key+one.bin</Key>"));

    assert_eq!(
        send("DELETE", "/round-trip/some%20dir/key%2Bone.bin", b"").status(),
        204
    );
    let gone = send("GET", "/round-trip/some%20dir/key%2Bone.bin", b"");
    assert_eq!(
        (gone.status(), error_code(&gone).as_str()),
        (404, "NoSuchKey")
    );
    assert_eq!(send("DELETE", "/round-trip", b"").status(), 204);
}

#[test]
fn a_signed_put_and_get_round_trip_through_the_fake() {
    let server = FakeServer::start(FakeConfig::new()).expect("fake starts");
    round_trip(&server, &Client::new());
}

#[test]
fn a_signed_put_and_get_round_trip_through_the_fake_over_tls() {
    let config = FakeConfig::new()
        .with_tls(&fixture("server.pem"), &fixture("server.key"))
        .expect("TLS config");
    let server = FakeServer::start(config).expect("fake starts");
    assert!(
        server
            .endpoint()
            .to_string()
            .starts_with("https://127.0.0.1:")
    );
    let client = Client::new().with_tls(tls_config_with_roots(&fixture("ca.pem")).expect("roots"));
    round_trip(&server, &client);
}

#[test]
fn a_wrong_secret_gets_403_and_writes_nothing() {
    let server = FakeServer::start(FakeConfig::new()).expect("fake starts");
    let endpoint = server.endpoint();
    let client = Client::new();
    let right = fake::credentials();
    let wrong = Credentials::new(fake::ACCESS_KEY_ID, "not-the-secret");
    let ok = client
        .send(&endpoint, &signed(&endpoint, &right, "PUT", "/b", b""))
        .expect("exchange");
    assert_eq!(ok.status(), 200);

    let refused = client
        .send(
            &endpoint,
            &signed(&endpoint, &wrong, "PUT", "/b/k", b"data"),
        )
        .expect("exchange");
    assert_eq!(
        (refused.status(), error_code(&refused).as_str()),
        (403, "SignatureDoesNotMatch")
    );
    let after = client
        .send(&endpoint, &signed(&endpoint, &right, "GET", "/b/k", b""))
        .expect("exchange");
    assert_eq!(
        after.status(),
        404,
        "the refused PUT must not have stored anything"
    );
}

#[test]
fn a_wrong_secret_with_expect_continue_is_refused_before_the_body() {
    let server = FakeServer::start(FakeConfig::new()).expect("fake starts");
    let endpoint = server.endpoint();
    // A long continue wait: if the fake asked for the body, or the client
    // waited for a 100 that never comes, this would take 10 seconds.
    let client = Client::new().with_continue_wait(Duration::from_secs(10));
    let right = fake::credentials();
    let wrong = Credentials::new(fake::ACCESS_KEY_ID, "not-the-secret");
    client
        .send(&endpoint, &signed(&endpoint, &right, "PUT", "/b", b""))
        .expect("exchange");

    let with_expect = |creds: &Credentials| {
        let mut request = Request::new("PUT", "/b/k")
            .with_header("host", &endpoint.authority())
            .with_header("content-length", "4")
            .with_header("expect", "100-continue")
            .with_body(b"data".to_vec());
        Signer::new(creds, fake::DEFAULT_REGION, "s3", UtcTime::now())
            .sign_request(&mut request, &sha256_hex(b"data"));
        request
    };
    let started = Instant::now();
    let refused = client
        .send(&endpoint, &with_expect(&wrong))
        .expect("exchange");
    assert_eq!(
        (refused.status(), error_code(&refused).as_str()),
        (403, "SignatureDoesNotMatch")
    );
    let accepted = client
        .send(&endpoint, &with_expect(&right))
        .expect("exchange");
    assert_eq!(accepted.status(), 200);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "took {:?}",
        started.elapsed()
    );

    // On a raw socket: send only the head. The fake must answer 403 at
    // once, not 100 Continue, and not wait for a body that never comes.
    let request = with_expect(&wrong);
    let mut head = format!("PUT {} HTTP/1.1\r\n", request.target());
    for (name, value) in request.headers() {
        head = head + name + ": " + value + "\r\n";
    }
    head.push_str("\r\n");
    let mut raw = TcpStream::connect(server.addr()).expect("connect");
    raw.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    raw.write_all(head.as_bytes()).expect("write head");
    let mut first = [0u8; 12];
    raw.read_exact(&mut first)
        .expect("a response without sending the body");
    assert_eq!(&first, b"HTTP/1.1 403");
}

#[test]
fn the_fake_refuses_unsigned_requests_and_mismatched_payload_hashes() {
    let server = FakeServer::start(FakeConfig::new()).expect("fake starts");
    let endpoint = server.endpoint();
    let client = Client::new();
    let creds = fake::credentials();
    client
        .send(&endpoint, &signed(&endpoint, &creds, "PUT", "/b", b""))
        .expect("exchange");

    let unsigned = Request::new("GET", "/b").with_header("host", &endpoint.authority());
    let response = client.send(&endpoint, &unsigned).expect("exchange");
    assert_eq!(
        (response.status(), error_code(&response).as_str()),
        (403, "AccessDenied")
    );

    // Signed correctly, over a hash that is not the hash of the body.
    let mut request = Request::new("PUT", "/b/k")
        .with_header("host", &endpoint.authority())
        .with_header("content-length", "4")
        .with_body(b"data".to_vec());
    Signer::new(&creds, fake::DEFAULT_REGION, "s3", UtcTime::now())
        .sign_request(&mut request, &sha256_hex(b"other"));
    let response = client.send(&endpoint, &request).expect("exchange");
    assert_eq!(
        (response.status(), error_code(&response).as_str()),
        (400, "XAmzContentSHA256Mismatch")
    );
}

#[test]
fn a_signed_aws_chunked_upload_stores_the_data_not_the_framing() {
    let server = FakeServer::start(FakeConfig::new()).expect("fake starts");
    let endpoint = server.endpoint();
    let client = Client::new();
    let creds = fake::credentials();
    client
        .send(&endpoint, &signed(&endpoint, &creds, "PUT", "/b", b""))
        .expect("exchange");

    let data = SplitMix64::new(7).bytes(20_000);
    let upload = |tamper: bool| {
        let now = UtcTime::now();
        let signer = Signer::new(&creds, fake::DEFAULT_REGION, "s3", now);
        let request = Request::new("PUT", "/b/chunked")
            .with_header("host", &endpoint.authority())
            .with_header("content-encoding", "aws-chunked")
            .with_header("x-amz-decoded-content-length", &data.len().to_string())
            .with_header("x-amz-date", &now.amz())
            .with_header("x-amz-content-sha256", STREAMING_SIGNED);
        let seed = signer.sign(&request, STREAMING_SIGNED);
        let chunk = NonZeroUsize::new(8_192).expect("non-zero");
        let mut body =
            aws_chunked::encode(&data, chunk, &[], Some(&mut signer.chunk_signer(&seed)));
        if tamper {
            // Flip one data byte inside the first chunk.
            let first_data = body.iter().position(|&b| b == b'\n').expect("a line") + 1;
            body[first_data] ^= 1;
        }
        let request = request
            .with_header("content-length", &body.len().to_string())
            .with_header("authorization", &signer.authorization(&seed))
            .with_body(body);
        client.send(&endpoint, &request).expect("exchange")
    };
    let tampered = upload(true);
    assert_eq!(
        (tampered.status(), error_code(&tampered).as_str()),
        (403, "SignatureDoesNotMatch")
    );
    assert_eq!(upload(false).status(), 200);
    let get = client
        .send(
            &endpoint,
            &signed(&endpoint, &creds, "GET", "/b/chunked", b""),
        )
        .expect("exchange");
    assert_eq!(get.body(), data);
}

#[test]
fn the_client_refuses_a_certificate_it_does_not_trust() {
    let config = FakeConfig::new()
        .with_tls(&fixture("server.pem"), &fixture("server.key"))
        .expect("TLS config");
    let server = FakeServer::start(config).expect("fake starts");
    let client = Client::new().with_tls(tls_config_native(None).expect("native roots"));
    let request = Request::new("GET", "/").with_header("host", &server.endpoint().authority());
    match client.send(&server.endpoint(), &request) {
        Err(HttpError::Tls(_)) => {}
        other => panic!("expected a TLS error, got {other:?}"),
    }
}

#[test]
fn a_silent_server_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let holder = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        thread::sleep(Duration::from_secs(2));
        drop(stream);
    });
    let endpoint = Endpoint::parse(&format!("http://{addr}")).expect("endpoint");
    let client = Client::new().with_timeout(Duration::from_millis(300));
    let started = Instant::now();
    let result = client.send(
        &endpoint,
        &Request::new("GET", "/").with_header("host", &endpoint.authority()),
    );
    assert!(matches!(result, Err(HttpError::TimedOut)), "{result:?}");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
    holder.join().expect("holder thread");
}

/// Sends `bytes` one at a time, 50 ms apart, for at most `limit`. Each byte
/// arrives well inside the client's timeout, so only a deadline over the
/// whole exchange stops the client.
fn trickle(tcp: &mut TcpStream, bytes: &[u8], limit: Duration) {
    let started = Instant::now();
    for byte in bytes {
        if started.elapsed() > limit || tcp.write_all(&[*byte]).is_err() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Sends a GET over TLS with a `timeout` deadline and returns the result
/// and how long it took.
fn tls_get(
    addr: std::net::SocketAddr,
    timeout: Duration,
) -> (Result<Response, HttpError>, Duration) {
    let endpoint = Endpoint::parse(&format!("https://{addr}")).expect("endpoint");
    let client = Client::new()
        .with_tls(tls_config_with_roots(&fixture("ca.pem")).expect("roots"))
        .with_timeout(timeout);
    let started = Instant::now();
    let result = client.send(
        &endpoint,
        &Request::new("GET", "/").with_header("host", &endpoint.authority()),
    );
    (result, started.elapsed())
}

#[test]
fn a_tls_peer_that_trickles_the_handshake_times_out_at_the_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let peer = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().expect("accept");
        let mut hello = [0u8; 4096];
        let _ = tcp.read(&mut hello);
        // A handshake record header that promises 16 KiB, then its body
        // one byte at a time.
        let _ = tcp.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00]);
        trickle(&mut tcp, &[0u8; 0x4000], Duration::from_secs(4));
    });
    let (result, took) = tls_get(addr, Duration::from_millis(500));
    assert!(matches!(result, Err(HttpError::TimedOut)), "{result:?}");
    assert!(took < Duration::from_millis(1500), "took {took:?}");
    peer.join().expect("peer thread");
}

#[test]
fn a_tls_peer_that_trickles_the_body_times_out_at_the_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_no_client_auth()
    .with_single_cert(
        CertificateDer::pem_slice_iter(&fixture("server.pem"))
            .collect::<Result<Vec<_>, _>>()
            .expect("chain"),
        PrivateKeyDer::from_pem_slice(&fixture("server.key")).expect("key"),
    )
    .expect("server config");
    let peer = thread::spawn(move || {
        let (mut tcp, _) = listener.accept().expect("accept");
        let mut tls = rustls::ServerConnection::new(Arc::new(config)).expect("session");
        while tls.is_handshaking() {
            tls.complete_io(&mut tcp).expect("handshake");
        }
        let mut request = Vec::new();
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            tls.complete_io(&mut tcp).expect("read the request");
            let mut buf = [0u8; 1024];
            match tls.reader().read(&mut buf) {
                Ok(n) => request.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("{e}"),
            }
        }
        tls.writer()
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n")
            .expect("head");
        tls.complete_io(&mut tcp).expect("send the head");
        // The body as one TLS record, sent a byte at a time.
        tls.writer().write_all(&[b'a'; 1000]).expect("body");
        let mut record = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut record).expect("encrypt");
        }
        trickle(&mut tcp, &record, Duration::from_secs(4));
    });
    let (result, took) = tls_get(addr, Duration::from_secs(1));
    assert!(matches!(result, Err(HttpError::TimedOut)), "{result:?}");
    assert!(took < Duration::from_secs(2), "took {took:?}");
    peer.join().expect("peer thread");
}

#[test]
fn the_body_goes_out_after_the_continue_wait_when_the_server_never_sends_100() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        // Ignores Expect: reads until the head and the 4-byte body are in.
        while !received.windows(4).any(|w| w == b"\r\n\r\n") || !received.ends_with(b"data") {
            let n = stream.read(&mut buf).expect("read");
            assert_ne!(n, 0, "client closed before sending the body");
            received.extend_from_slice(&buf[..n]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n")
            .expect("write");
    });
    let endpoint = Endpoint::parse(&format!("http://{addr}")).expect("endpoint");
    let client = Client::new().with_continue_wait(Duration::from_millis(200));
    let request = Request::new("PUT", "/b/k")
        .with_header("host", &endpoint.authority())
        .with_header("expect", "100-continue")
        .with_header("content-length", "4")
        .with_body(b"data".to_vec());
    let response = client.send(&endpoint, &request).expect("exchange");
    assert_eq!((response.status(), response.body()), (200, &b"ok"[..]));
    server.join().expect("server thread");
}
