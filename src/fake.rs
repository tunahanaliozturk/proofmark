//! An in-memory S3 server for tests and for trying proofmark out
//! ([ADR 0005](../docs/adr/0005-in-process-fake-as-the-test-bed.md)).
//!
//! Path-style bucket and object `PUT`, `GET`, `HEAD` and `DELETE`,
//! `ListBuckets`, unpaged object, version and upload listings, single byte
//! ranges and `Content-MD5`. Every request is checked against one fixed key
//! pair with SigV4, and `aws-chunked` uploads are decoded and their chunk
//! signatures checked.
//!
//! Each [`Fault`] is one named way of being wrong that a probe exists to
//! catch, switched on with [`FakeConfig::with_fault`].
//!
//! One global lock, no persistence, one request per connection. Listens on
//! loopback only.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::aws_chunked;
use crate::checksum::{base64, hex, md5, sha256, sha256_hex};
use crate::http::{
    Endpoint, HttpError, Request, Response, Scheme, Wire, crypto_provider, request_framing,
};
use crate::sigv4::{
    Authorization, Credentials, STREAMING_SIGNED, STREAMING_SIGNED_TRAILER,
    STREAMING_UNSIGNED_TRAILER, Signature, Signer, UNSIGNED_PAYLOAD,
};
use crate::time::UtcTime;

/// The access key id the fake accepts.
pub const ACCESS_KEY_ID: &str = "PROOFMARKFAKEKEYID01";
/// The secret key the fake accepts. Public on purpose: the fake is a test
/// tool and keeps nothing worth protecting.
pub const SECRET_ACCESS_KEY: &str = "proofmark/fake/secret/for/tests/only/0001";
/// The region the fake signs in unless configured otherwise.
pub const DEFAULT_REGION: &str = "us-east-1";

/// SigV4 refuses requests whose time is further than this from the server's.
const MAX_SKEW_SECONDS: i64 = 15 * 60;
/// How long a connection may sit idle before the fake gives up on it.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The key pair the fake accepts.
#[must_use]
pub fn credentials() -> Credentials {
    Credentials::new(ACCESS_KEY_ID, SECRET_ACCESS_KEY)
}

/// One named way of being wrong. Each is caught by at least one probe;
/// `proofmark explain` lists which.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Fault {
    /// Stores every byte of an upload but the last.
    TruncateObject,
    /// Answers with an `ETag` that is not the MD5 of the data.
    EtagNotMd5,
    /// Answers `HEAD` with `Content-Length: 0`.
    HeadReportsZeroLength,
    /// Accepts `x-amz-meta-*` headers and stores none of them.
    DropUserMetadata,
    /// Answers `200` to an empty upload and stores nothing.
    ZeroByteNotStored,
    /// Answers `200` to a write over an existing key and keeps the old data.
    IgnoreOverwrite,
    /// Answers a missing key with `404` and no XML error body.
    MissingKeyEmptyBody,
    /// Answers a key in a missing bucket with `NoSuchKey`.
    MissingBucketIsNoSuchKey,
    /// Answers a `DELETE` of a missing key with `404`.
    DeleteMissingIs404,
    /// Ignores `Range` and serves the whole object with `200`.
    IgnoreRange,
    /// Serves `bytes=-N` from the start of the object instead of the end.
    SuffixRangeFromStart,
    /// Serves a range that starts past the end as the whole object.
    UnsatisfiableRangeServesWhole,
    /// Accepts an upload whose `Content-MD5` does not match it.
    IgnoreContentMd5,
    /// Accepts a request whose signature does not match.
    IgnoreSignature,
    /// Refuses any request with `Expect: 100-continue` with `417`.
    RejectExpectContinue,
}

const FAULTS: &[(Fault, &str)] = &[
    (Fault::TruncateObject, "TruncateObject"),
    (Fault::EtagNotMd5, "EtagNotMd5"),
    (Fault::HeadReportsZeroLength, "HeadReportsZeroLength"),
    (Fault::DropUserMetadata, "DropUserMetadata"),
    (Fault::ZeroByteNotStored, "ZeroByteNotStored"),
    (Fault::IgnoreOverwrite, "IgnoreOverwrite"),
    (Fault::MissingKeyEmptyBody, "MissingKeyEmptyBody"),
    (Fault::MissingBucketIsNoSuchKey, "MissingBucketIsNoSuchKey"),
    (Fault::DeleteMissingIs404, "DeleteMissingIs404"),
    (Fault::IgnoreRange, "IgnoreRange"),
    (Fault::SuffixRangeFromStart, "SuffixRangeFromStart"),
    (
        Fault::UnsatisfiableRangeServesWhole,
        "UnsatisfiableRangeServesWhole",
    ),
    (Fault::IgnoreContentMd5, "IgnoreContentMd5"),
    (Fault::IgnoreSignature, "IgnoreSignature"),
    (Fault::RejectExpectContinue, "RejectExpectContinue"),
];

impl Fault {
    /// Every fault, in a stable order.
    pub fn all() -> impl Iterator<Item = Self> {
        FAULTS.iter().map(|(fault, _)| *fault)
    }

    /// The fault's name, as `proofmark fake --fault` takes it.
    #[must_use]
    pub fn name(self) -> &'static str {
        FAULTS
            .iter()
            .find(|(fault, _)| *fault == self)
            .map_or("", |(_, name)| name)
    }

    /// The fault named `name`, ignoring case.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        FAULTS
            .iter()
            .find(|(_, n)| n.eq_ignore_ascii_case(name))
            .map(|(fault, _)| *fault)
    }
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Called with the number of each request the fake has received (from 1)
/// and the request itself, once its body has been read and before it is
/// answered. Tests use it to watch what a client sends and to interfere
/// mid-run.
pub type RequestHook = Arc<dyn Fn(u64, &Request) + Send + Sync>;

#[derive(Clone)]
struct Hook(RequestHook);

impl std::fmt::Debug for Hook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RequestHook")
    }
}

/// How a fake server behaves.
#[derive(Debug, Clone)]
pub struct FakeConfig {
    region: String,
    max_body: usize,
    tls: Option<Arc<rustls::ServerConfig>>,
    faults: BTreeSet<Fault>,
    hook: Option<Hook>,
}

impl Default for FakeConfig {
    fn default() -> Self {
        Self {
            region: DEFAULT_REGION.to_owned(),
            max_body: 64 * 1024 * 1024,
            tls: None,
            faults: BTreeSet::new(),
            hook: None,
        }
    }
}

impl FakeConfig {
    /// Plain HTTP, region `us-east-1`, request bodies up to 64 MiB.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The same configuration, signing in `region`.
    #[must_use]
    pub fn with_region(mut self, region: &str) -> Self {
        region.clone_into(&mut self.region);
        self
    }

    /// The same configuration, serving HTTPS with the given certificate
    /// chain and private key, both PEM.
    ///
    /// # Errors
    ///
    /// [`HttpError::TlsConfig`] if the PEM data is not a usable chain and key.
    pub fn with_tls(mut self, chain_pem: &[u8], key_pem: &[u8]) -> Result<Self, HttpError> {
        let tls_error = |e: &dyn std::fmt::Display| HttpError::TlsConfig(e.to_string());
        let chain = CertificateDer::pem_slice_iter(chain_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| tls_error(&e))?;
        let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| tls_error(&e))?;
        let config = rustls::ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| tls_error(&e))?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|e| tls_error(&e))?;
        self.tls = Some(Arc::new(config));
        Ok(self)
    }

    /// The same configuration with `fault` switched on as well.
    #[must_use]
    pub fn with_fault(mut self, fault: Fault) -> Self {
        self.faults.insert(fault);
        self
    }

    /// The same configuration, calling `hook` for every request.
    #[must_use]
    pub fn with_request_hook(mut self, hook: RequestHook) -> Self {
        self.hook = Some(Hook(hook));
        self
    }

    fn has(&self, fault: Fault) -> bool {
        self.faults.contains(&fault)
    }
}

#[derive(Debug)]
struct Object {
    body: Vec<u8>,
    etag: String,
    content_type: Option<String>,
    metadata: Vec<(String, String)>,
    last_modified: UtcTime,
}

#[derive(Debug)]
struct Bucket {
    created: UtcTime,
    objects: BTreeMap<String, Object>,
}

#[derive(Debug, Default)]
struct Store {
    buckets: BTreeMap<String, Bucket>,
}

/// What a fake holds: for each bucket, each key and its `ETag`.
pub type Snapshot = BTreeMap<String, BTreeMap<String, String>>;

#[derive(Debug)]
struct Shared {
    config: FakeConfig,
    store: Mutex<Store>,
    stop: AtomicBool,
    requests: AtomicU64,
}

/// A running fake server. Dropping it stops accepting connections.
#[derive(Debug)]
pub struct FakeServer {
    addr: SocketAddr,
    scheme: Scheme,
    shared: Arc<Shared>,
    accept: Option<JoinHandle<()>>,
}

impl FakeServer {
    /// Starts a server on `127.0.0.1` with a port the system picks.
    ///
    /// # Errors
    ///
    /// The I/O error if the socket cannot be bound or the thread started.
    pub fn start(config: FakeConfig) -> io::Result<Self> {
        Self::bind(SocketAddr::from(([127, 0, 0, 1], 0)), config)
    }

    /// Starts a server on `addr`, which must be a loopback address. The
    /// fake accepts a published key pair, so it never listens where another
    /// machine could reach it.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] if `addr` is not a loopback address,
    /// or the I/O error if the socket cannot be bound or the thread started.
    pub fn bind(addr: SocketAddr, config: FakeConfig) -> io::Result<Self> {
        if !addr.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the fake listens only on loopback addresses, not {addr}"),
            ));
        }
        let listener = TcpListener::bind(addr)?;
        let addr = listener.local_addr()?;
        let scheme = if config.tls.is_some() {
            Scheme::Https
        } else {
            Scheme::Http
        };
        let shared = Arc::new(Shared {
            config,
            store: Mutex::new(Store::default()),
            stop: AtomicBool::new(false),
            requests: AtomicU64::new(0),
        });
        let for_thread = Arc::clone(&shared);
        let accept = thread::Builder::new()
            .name("proofmark-fake".to_owned())
            .spawn(move || accept_loop(&listener, &for_thread))?;
        Ok(Self {
            addr,
            scheme,
            shared,
            accept: Some(accept),
        })
    }

    /// The address the server listens on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The endpoint to point a client at.
    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        Endpoint::from_addr(self.scheme, self.addr)
    }

    /// The region requests must be signed for.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.shared.config.region
    }

    /// Every bucket, key and `ETag` the server holds now.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        let store = self
            .shared
            .store
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        store
            .buckets
            .iter()
            .map(|(name, bucket)| {
                let objects = bucket
                    .objects
                    .iter()
                    .map(|(key, object)| (key.clone(), object.etag.clone()))
                    .collect();
                (name.clone(), objects)
            })
            .collect()
    }
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        // Wakes the blocking accept so the thread sees the flag. If the
        // connect fails, the thread is left to end with the process.
        if TcpStream::connect_timeout(&self.addr, Duration::from_secs(1)).is_ok()
            && let Some(accept) = self.accept.take()
        {
            // A panic in the accept thread has already been reported.
            let _ = accept.join();
        }
    }
}

fn accept_loop(listener: &TcpListener, shared: &Arc<Shared>) {
    for stream in listener.incoming() {
        if shared.stop.load(Ordering::SeqCst) {
            return;
        }
        let Ok(stream) = stream else { continue };
        let shared = Arc::clone(shared);
        // If the thread cannot start, the connection is dropped and the
        // client sees it closed.
        let _ = thread::Builder::new()
            .name("proofmark-fake-conn".to_owned())
            .spawn(move || serve(stream, &shared));
    }
}

enum ServerStream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>),
}

impl ServerStream {
    fn tcp(&self) -> &TcpStream {
        match self {
            Self::Plain(tcp) => tcp,
            Self::Tls(tls) => &tls.sock,
        }
    }
}

impl Read for ServerStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(tcp) => tcp.read(buf),
            Self::Tls(tls) => tls.read(buf),
        }
    }
}

impl Write for ServerStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(tcp) => tcp.write(buf),
            Self::Tls(tls) => tls.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(tcp) => tcp.flush(),
            Self::Tls(tls) => tls.flush(),
        }
    }
}

fn serve(tcp: TcpStream, shared: &Shared) {
    if tcp.set_read_timeout(Some(IDLE_TIMEOUT)).is_err()
        || tcp.set_write_timeout(Some(IDLE_TIMEOUT)).is_err()
    {
        return;
    }
    let stream = match &shared.config.tls {
        None => ServerStream::Plain(tcp),
        Some(config) => match rustls::ServerConnection::new(Arc::clone(config)) {
            Ok(session) => ServerStream::Tls(Box::new(rustls::StreamOwned::new(session, tcp))),
            Err(_) => return,
        },
    };
    let mut wire = Wire::new(stream);
    let number = shared.requests.fetch_add(1, Ordering::SeqCst) + 1;
    let request_id = format!("{number:016X}");
    let (response, head_only) = handle(&mut wire, shared, &request_id, number);
    let stream = wire.get_mut();
    // The client may already be gone; there is nobody to tell.
    let _ = write_response(stream, &response, head_only, &request_id);
    close(stream);
}

fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        204 => "No Content",
        206 => "Partial Content",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        501 => "Not Implemented",
        _ => "",
    }
}

fn write_response(
    stream: &mut ServerStream,
    response: &Response,
    head_only: bool,
    request_id: &str,
) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\n",
        response.status(),
        reason(response.status())
    );
    let _ = write!(
        head,
        "x-amz-request-id: {request_id}\r\nDate: {}\r\nServer: proofmark-fake\r\n",
        UtcTime::now().http_date()
    );
    for (name, value) in response.headers() {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    if response.header("content-length").is_none() {
        let _ = write!(head, "Content-Length: {}\r\n", response.body().len());
    }
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    if !head_only {
        stream.write_all(response.body())?;
    }
    stream.flush()
}

/// Ends the connection politely: TLS `close_notify`, then a TCP half-close,
/// then reading whatever the client still sends, so that closing with
/// unread data does not turn into a reset that destroys the response.
fn close(stream: &mut ServerStream) {
    if let ServerStream::Tls(tls) = stream {
        tls.conn.send_close_notify();
        let _ = tls.flush();
    }
    let tcp = stream.tcp();
    let _ = tcp.shutdown(Shutdown::Write);
    let _ = tcp.set_read_timeout(Some(Duration::from_millis(500)));
    let mut sink = [0u8; 4096];
    let mut drained = 0usize;
    let mut raw = tcp;
    while drained < 16 * 1024 * 1024 {
        match raw.read(&mut sink) {
            Ok(0) | Err(_) => break,
            Ok(n) => drained += n,
        }
    }
}

/// An S3 error response: status, code and message.
#[derive(Debug)]
struct S3Error {
    status: u16,
    code: &'static str,
    message: String,
    /// More elements after `RequestId`, the way AWS adds detail to some
    /// errors.
    detail: Vec<(&'static str, String)>,
}

impl S3Error {
    fn new(status: u16, code: &'static str, message: &str) -> Self {
        Self {
            status,
            code,
            message: message.to_owned(),
            detail: Vec::new(),
        }
    }

    fn signature_mismatch() -> Self {
        Self::new(
            403,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
        )
    }

    fn not_implemented() -> Self {
        Self::new(
            501,
            "NotImplemented",
            "A header or query you provided implies functionality that is not implemented.",
        )
    }

    fn into_response(self, resource: &str, request_id: &str) -> Response {
        let mut body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>{}</Code><Message>{}</Message><Resource>{}</Resource><RequestId>{}</RequestId>",
            self.code,
            xml_escape(&self.message),
            xml_escape(resource),
            request_id
        );
        for (name, value) in &self.detail {
            let _ = write!(body, "<{name}>{}</{name}>", xml_escape(value));
        }
        body.push_str("</Error>");
        Response::new(
            self.status,
            vec![("Content-Type".to_owned(), "application/xml".to_owned())],
            body.into_bytes(),
        )
    }
}

fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// What a valid signature established, kept to check chunk signatures.
struct Verified {
    time: UtcTime,
    seed: Signature,
}

fn verify(
    request: &Request,
    config: &FakeConfig,
    credentials: &Credentials,
) -> Result<Verified, S3Error> {
    let header = request
        .header("authorization")
        .ok_or_else(|| S3Error::new(403, "AccessDenied", "Access Denied"))?;
    let malformed = |message: &str| S3Error::new(400, "AuthorizationHeaderMalformed", message);
    let auth = Authorization::parse(header)
        .ok_or_else(|| malformed("The authorization header is malformed."))?;
    if auth.access_key_id() != credentials.access_key_id() {
        return Err(S3Error::new(
            403,
            "InvalidAccessKeyId",
            "The AWS Access Key Id you provided does not exist in our records.",
        ));
    }
    if auth.region() != config.region {
        return Err(malformed(&format!(
            "The authorization header is malformed; the region '{}' is wrong; expecting '{}'",
            auth.region(),
            config.region
        )));
    }
    if auth.service() != "s3" {
        return Err(malformed(
            "The authorization header is malformed; the service must be 's3'.",
        ));
    }
    let time = request
        .header("x-amz-date")
        .and_then(UtcTime::parse_amz)
        .ok_or_else(|| {
            S3Error::new(
                403,
                "AccessDenied",
                "AWS authentication requires a valid Date or x-amz-date header",
            )
        })?;
    if time.amz_date() != auth.date() {
        return Err(S3Error::signature_mismatch());
    }
    if (UtcTime::now().unix() - time.unix()).abs() > MAX_SKEW_SECONDS {
        return Err(S3Error::new(
            403,
            "RequestTimeTooSkewed",
            "The difference between the request time and the current time is too large.",
        ));
    }
    let payload_hash = request.header("x-amz-content-sha256").ok_or_else(|| {
        S3Error::new(
            400,
            "InvalidRequest",
            "Missing required header for this request: x-amz-content-sha256",
        )
    })?;
    let signed_headers = auth.signed_headers();
    if !signed_headers.contains(&"host") {
        return Err(S3Error::signature_mismatch());
    }
    let signer = Signer::new(credentials, &config.region, "s3", time);
    let expected = signer
        .sign_named(request, payload_hash, &signed_headers)
        .ok_or_else(S3Error::signature_mismatch)?;
    if expected.signature() != auth.signature() && !config.has(Fault::IgnoreSignature) {
        // AWS echoes what it signed, so the caller can compare. The echo
        // carries the provided signature and, in the canonical request, the
        // session token: what a client must never write to a report.
        let mut error = S3Error::signature_mismatch();
        error.detail = vec![
            ("AWSAccessKeyId", auth.access_key_id().to_owned()),
            ("StringToSign", expected.string_to_sign().to_owned()),
            ("SignatureProvided", auth.signature().to_owned()),
            ("CanonicalRequest", expected.canonical_request().to_owned()),
        ];
        return Err(error);
    }
    Ok(Verified {
        time,
        seed: expected,
    })
}

/// The object data, after checking the payload hash or removing and
/// checking the `aws-chunked` framing.
fn payload(
    request: &Request,
    verified: &Verified,
    config: &FakeConfig,
    credentials: &Credentials,
) -> Result<Vec<u8>, S3Error> {
    let declared = request.header("x-amz-content-sha256").unwrap_or_default();
    match declared {
        UNSIGNED_PAYLOAD => Ok(request.body().to_vec()),
        STREAMING_SIGNED | STREAMING_SIGNED_TRAILER | STREAMING_UNSIGNED_TRAILER => {
            let decoded = aws_chunked::decode(request.body())
                .map_err(|e| S3Error::new(400, "IncompleteBody", &e.to_string()))?;
            if declared != STREAMING_UNSIGNED_TRAILER {
                let signer = Signer::new(credentials, &config.region, "s3", verified.time);
                if !decoded.signatures_match(&mut signer.chunk_signer(&verified.seed)) {
                    return Err(S3Error::signature_mismatch());
                }
            }
            let length = request
                .header("x-amz-decoded-content-length")
                .and_then(|v| v.parse::<usize>().ok());
            if length != Some(decoded.data().len()) {
                return Err(S3Error::new(
                    400,
                    "IncompleteBody",
                    "You did not provide the number of bytes specified by the x-amz-decoded-content-length header.",
                ));
            }
            Ok(decoded.into_data())
        }
        hash if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) => {
            if sha256_hex(request.body()) == hash.to_ascii_lowercase() {
                Ok(request.body().to_vec())
            } else {
                Err(S3Error::new(
                    400,
                    "XAmzContentSHA256Mismatch",
                    "The provided 'x-amz-content-sha256' header does not match what was computed.",
                ))
            }
        }
        _ => Err(S3Error::new(
            400,
            "InvalidArgument",
            "x-amz-content-sha256 must be a SHA-256 or a known payload type.",
        )),
    }
}

/// Reads one request, checks it, and answers it. The `bool` says whether
/// the response is to a `HEAD` and must be sent without its body.
fn handle<S: Read + Write>(
    wire: &mut Wire<S>,
    shared: &Shared,
    request_id: &str,
    number: u64,
) -> (Response, bool) {
    let Ok(head) = wire.request_head() else {
        return (Response::new(400, Vec::new(), Vec::new()), false);
    };
    let request = Request::from_target(&head.method, &head.target, head.headers);
    let resource = request.path().to_owned();
    let head_only = request.method() == "HEAD";
    let fail = |error: S3Error| (error.into_response(&resource, request_id), head_only);
    let Ok(framing) = request_framing(request.headers()) else {
        return fail(S3Error::new(
            400,
            "InvalidRequest",
            "The request framing is not supported.",
        ));
    };
    let credentials = credentials();
    let verified = verify(&request, &shared.config, &credentials);
    let expects_continue = request
        .header("expect")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("100-continue"));
    if expects_continue && shared.config.has(Fault::RejectExpectContinue) {
        return fail(S3Error::new(
            417,
            "ExpectationFailed",
            "The server does not support Expect: 100-continue.",
        ));
    }
    if expects_continue {
        // S3 checks the signature before asking for the body, so a bad
        // signature is refused without the body ever being sent.
        if let Err(error) = verified {
            return fail(error);
        }
        let interim = wire.get_mut().write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        if interim.and_then(|()| wire.get_mut().flush()).is_err() {
            return fail(S3Error::new(
                400,
                "RequestTimeout",
                "Could not send 100 Continue.",
            ));
        }
    }
    let body = match wire.body(framing, shared.config.max_body) {
        Ok(body) => body,
        Err(HttpError::TooLarge) => {
            return fail(S3Error::new(
                400,
                "EntityTooLarge",
                "Your proposed upload exceeds the maximum allowed size.",
            ));
        }
        Err(_) => {
            return fail(S3Error::new(
                400,
                "IncompleteBody",
                "The request body could not be read.",
            ));
        }
    };
    let request = request.with_body(body);
    if let Some(Hook(hook)) = &shared.config.hook {
        hook(number, &request);
    }
    let result = verified
        .and_then(|verified| payload(&request, &verified, &shared.config, &credentials))
        .and_then(|data| route(&request, data, shared));
    match result {
        Ok(response) => (response, head_only),
        Err(error) => fail(error),
    }
}

fn decoded_utf8(raw: &str) -> Result<String, S3Error> {
    String::from_utf8(crate::sigv4::percent_decode(raw))
        .map_err(|_| S3Error::new(400, "InvalidURI", "Couldn't parse the specified URI."))
}

fn method_not_allowed() -> S3Error {
    S3Error::new(
        405,
        "MethodNotAllowed",
        "The specified method is not allowed against this resource.",
    )
}

fn route(request: &Request, data: Vec<u8>, shared: &Shared) -> Result<Response, S3Error> {
    let rest = request
        .path()
        .strip_prefix('/')
        .ok_or_else(|| S3Error::new(400, "InvalidURI", "Couldn't parse the specified URI."))?;
    let (bucket, key) = match rest.split_once('/') {
        Some((bucket, key)) if !key.is_empty() => (bucket, Some(decoded_utf8(key)?)),
        Some((bucket, _)) => (bucket, None),
        None => (rest, None),
    };
    // `x-id` names the operation for logging; SDKs add it. Anything else is
    // a sub-resource or option.
    let options: Vec<&str> = request
        .query()
        .iter()
        .map(|(k, _)| k.as_str())
        .filter(|k| *k != "x-id")
        .collect();
    let mut store = shared.store.lock().unwrap_or_else(PoisonError::into_inner);
    if bucket.is_empty() {
        return match request.method() {
            "GET" if options.is_empty() => Ok(list_buckets(&store)),
            _ => Err(S3Error::not_implemented()),
        };
    }
    let bucket = decoded_utf8(bucket)?;
    let config = &shared.config;
    match (key, options.as_slice()) {
        (None, ["versions"]) if request.method() == "GET" => {
            let objects = &store
                .buckets
                .get(&bucket)
                .ok_or_else(no_such_bucket)?
                .objects;
            Ok(list_versions(&bucket, objects))
        }
        (None, ["uploads"]) if request.method() == "GET" => {
            store.buckets.get(&bucket).ok_or_else(no_such_bucket)?;
            Ok(xml_response(&format!(
                "<ListMultipartUploadsResult xmlns=\"{XMLNS}\"><Bucket>{}</Bucket><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>",
                xml_escape(&bucket)
            )))
        }
        (None, options) if options.iter().all(|k| *k == "list-type") => {
            bucket_request(&mut store, request.method(), &bucket)
        }
        (Some(key), []) => object_request(&mut store, config, request, &bucket, &key, data),
        _ => Err(S3Error::not_implemented()),
    }
}

const XMLNS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

fn xml_response(body: &str) -> Response {
    Response::new(
        200,
        vec![("Content-Type".to_owned(), "application/xml".to_owned())],
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{body}").into_bytes(),
    )
}

fn no_such_bucket() -> S3Error {
    S3Error::new(404, "NoSuchBucket", "The specified bucket does not exist")
}

fn list_buckets(store: &Store) -> Response {
    let mut xml = format!(
        "<ListAllMyBucketsResult xmlns=\"{XMLNS}\"><Owner><ID>proofmark-fake</ID></Owner><Buckets>"
    );
    for (name, bucket) in &store.buckets {
        let _ = write!(
            xml,
            "<Bucket><Name>{}</Name><CreationDate>{}</CreationDate></Bucket>",
            xml_escape(name),
            bucket.created.iso8601()
        );
    }
    xml.push_str("</Buckets></ListAllMyBucketsResult>");
    xml_response(&xml)
}

fn bucket_request(store: &mut Store, method: &str, bucket: &str) -> Result<Response, S3Error> {
    match method {
        "PUT" => {
            if store.buckets.contains_key(bucket) {
                // AWS answers 200 here in us-east-1 for a bucket the caller
                // owns, and this error everywhere else (CreateBucket, "Errors").
                return Err(S3Error::new(
                    409,
                    "BucketAlreadyOwnedByYou",
                    "Your previous request to create the named bucket succeeded and you already own it.",
                ));
            }
            store.buckets.insert(
                bucket.to_owned(),
                Bucket {
                    created: UtcTime::now(),
                    objects: BTreeMap::new(),
                },
            );
            Ok(Response::new(
                200,
                vec![("Location".to_owned(), format!("/{bucket}"))],
                Vec::new(),
            ))
        }
        "HEAD" => {
            if store.buckets.contains_key(bucket) {
                Ok(Response::new(200, Vec::new(), Vec::new()))
            } else {
                Err(no_such_bucket())
            }
        }
        "DELETE" => match store.buckets.get(bucket) {
            None => Err(no_such_bucket()),
            Some(existing) if !existing.objects.is_empty() => Err(S3Error::new(
                409,
                "BucketNotEmpty",
                "The bucket you tried to delete is not empty",
            )),
            Some(_) => {
                store.buckets.remove(bucket);
                Ok(Response::new(204, Vec::new(), Vec::new()))
            }
        },
        "GET" => {
            let existing = store.buckets.get(bucket).ok_or_else(no_such_bucket)?;
            Ok(list_objects(bucket, &existing.objects))
        }
        _ => Err(method_not_allowed()),
    }
}

/// Every key in one page, without prefix, delimiter or pagination. Listing
/// proper is milestone M3.
fn list_objects(bucket: &str, objects: &BTreeMap<String, Object>) -> Response {
    let mut xml = format!(
        "<ListBucketResult xmlns=\"{XMLNS}\"><Name>{}</Name><Prefix></Prefix><KeyCount>{}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>",
        xml_escape(bucket),
        objects.len()
    );
    for (key, object) in objects {
        let _ = write!(
            xml,
            "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size><StorageClass>STANDARD</StorageClass></Contents>",
            xml_escape(key),
            object.last_modified.iso8601(),
            xml_escape(&object.etag),
            object.body.len()
        );
    }
    xml.push_str("</ListBucketResult>");
    xml_response(&xml)
}

/// The fake has no versioning yet, so every object is its own only
/// version, with the version id `null` that S3 gives objects written while
/// versioning was off.
fn list_versions(bucket: &str, objects: &BTreeMap<String, Object>) -> Response {
    let mut xml = format!(
        "<ListVersionsResult xmlns=\"{XMLNS}\"><Name>{}</Name><Prefix></Prefix><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>",
        xml_escape(bucket)
    );
    for (key, object) in objects {
        let _ = write!(
            xml,
            "<Version><Key>{}</Key><VersionId>null</VersionId><IsLatest>true</IsLatest><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size></Version>",
            xml_escape(key),
            object.last_modified.iso8601(),
            xml_escape(&object.etag),
            object.body.len()
        );
    }
    xml.push_str("</ListVersionsResult>");
    xml_response(&xml)
}

fn object_headers(object: &Object) -> Vec<(String, String)> {
    let mut headers = vec![
        ("ETag".to_owned(), object.etag.clone()),
        ("Last-Modified".to_owned(), object.last_modified.http_date()),
        (
            "Content-Type".to_owned(),
            object
                .content_type
                .clone()
                .unwrap_or_else(|| "binary/octet-stream".to_owned()),
        ),
        ("Accept-Ranges".to_owned(), "bytes".to_owned()),
    ];
    headers.extend(object.metadata.iter().cloned());
    headers
}

/// A single byte range, inclusive, already clamped to the object.
enum Range {
    Whole,
    Part(usize, usize),
    Unsatisfiable,
}

/// Reads `Range` the way RFC 9110 section 14.2 says to: a header that does
/// not parse, or asks for several ranges (which S3 does not support), is
/// ignored and the whole object is served.
fn range(header: Option<&str>, len: usize, config: &FakeConfig) -> Range {
    let Some(spec) = header.and_then(|h| h.trim().strip_prefix("bytes=")) else {
        return Range::Whole;
    };
    if config.has(Fault::IgnoreRange) || spec.contains(',') {
        return Range::Whole;
    }
    let Some((first, last)) = spec.split_once('-') else {
        return Range::Whole;
    };
    let number = |s: &str| -> Option<usize> {
        let s = s.trim();
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        // Too many digits for usize is still a position past the end.
        Some(s.parse().unwrap_or(usize::MAX))
    };
    let unsatisfiable = || {
        if config.has(Fault::UnsatisfiableRangeServesWhole) {
            Range::Whole
        } else {
            Range::Unsatisfiable
        }
    };
    match (number(first), last.trim().is_empty(), number(last)) {
        (None, _, Some(0)) => unsatisfiable(),
        (None, _, Some(_)) if len == 0 => unsatisfiable(),
        (None, _, Some(suffix)) => {
            let take = suffix.min(len);
            if config.has(Fault::SuffixRangeFromStart) {
                Range::Part(0, take - 1)
            } else {
                Range::Part(len - take, len - 1)
            }
        }
        (Some(start), true, _) if start < len => Range::Part(start, len - 1),
        (Some(start), false, Some(end)) if start <= end && start < len => {
            Range::Part(start, end.min(len - 1))
        }
        (Some(start), _, _) if start >= len => unsatisfiable(),
        _ => Range::Whole,
    }
}

/// `Content-MD5` must be the base64 of the 16-byte MD5 of the data:
/// `InvalidDigest` if it is not even that shape, `BadDigest` if it is and
/// does not match (Error responses, "List of error codes").
fn check_content_md5(request: &Request, data: &[u8], config: &FakeConfig) -> Result<(), S3Error> {
    let Some(given) = request.header("content-md5").map(str::trim) else {
        return Ok(());
    };
    if given == base64(&md5(data)) || config.has(Fault::IgnoreContentMd5) {
        return Ok(());
    }
    let well_formed = given.len() == 24
        && given.ends_with("==")
        && given[..22]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/');
    if well_formed {
        Err(S3Error::new(
            400,
            "BadDigest",
            "The Content-MD5 you specified did not match what we received.",
        ))
    } else {
        Err(S3Error::new(
            400,
            "InvalidDigest",
            "The Content-MD5 you specified is not valid.",
        ))
    }
}

fn put_object(
    objects: &mut BTreeMap<String, Object>,
    config: &FakeConfig,
    request: &Request,
    key: &str,
    data: Vec<u8>,
) -> Result<Response, S3Error> {
    check_content_md5(request, &data, config)?;
    let etag = if config.has(Fault::EtagNotMd5) {
        format!("\"{}\"", hex(&sha256(&data)[..16]))
    } else {
        format!("\"{}\"", hex(&md5(&data)))
    };
    let metadata = if config.has(Fault::DropUserMetadata) {
        Vec::new()
    } else {
        request
            .headers()
            .iter()
            .filter(|(name, _)| name.to_ascii_lowercase().starts_with("x-amz-meta-"))
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect()
    };
    let mut body = data;
    if config.has(Fault::TruncateObject) {
        body.pop();
    }
    let skip = (body.is_empty() && config.has(Fault::ZeroByteNotStored))
        || (objects.contains_key(key) && config.has(Fault::IgnoreOverwrite));
    if !skip {
        let object = Object {
            body,
            etag: etag.clone(),
            content_type: request.header("content-type").map(str::to_owned),
            metadata,
            last_modified: UtcTime::now(),
        };
        objects.insert(key.to_owned(), object);
    }
    Ok(Response::new(
        200,
        vec![("ETag".to_owned(), etag)],
        Vec::new(),
    ))
}

fn object_request(
    store: &mut Store,
    config: &FakeConfig,
    request: &Request,
    bucket: &str,
    key: &str,
    data: Vec<u8>,
) -> Result<Response, S3Error> {
    let no_such_key = || S3Error::new(404, "NoSuchKey", "The specified key does not exist.");
    let Some(objects) = store.buckets.get_mut(bucket).map(|b| &mut b.objects) else {
        return Err(if config.has(Fault::MissingBucketIsNoSuchKey) {
            no_such_key()
        } else {
            no_such_bucket()
        });
    };
    match request.method() {
        "PUT" => put_object(objects, config, request, key, data),
        "GET" | "HEAD" => {
            let Some(object) = objects.get(key) else {
                if config.has(Fault::MissingKeyEmptyBody) {
                    return Ok(Response::new(404, Vec::new(), Vec::new()));
                }
                return Err(no_such_key());
            };
            let mut headers = object_headers(object);
            let len = object.body.len();
            if request.method() == "HEAD" {
                let shown = if config.has(Fault::HeadReportsZeroLength) {
                    0
                } else {
                    len
                };
                headers.push(("Content-Length".to_owned(), shown.to_string()));
                return Ok(Response::new(200, headers, Vec::new()));
            }
            match range(request.header("range"), len, config) {
                Range::Whole => Ok(Response::new(200, headers, object.body.clone())),
                Range::Part(start, end) => {
                    headers.push((
                        "Content-Range".to_owned(),
                        format!("bytes {start}-{end}/{len}"),
                    ));
                    Ok(Response::new(
                        206,
                        headers,
                        object.body[start..=end].to_vec(),
                    ))
                }
                Range::Unsatisfiable => {
                    let mut error = S3Error::new(
                        416,
                        "InvalidRange",
                        "The requested range is not satisfiable",
                    );
                    error.detail = vec![
                        (
                            "RangeRequested",
                            request.header("range").unwrap_or_default().to_owned(),
                        ),
                        ("ActualObjectSize", len.to_string()),
                    ];
                    Err(error)
                }
            }
        }
        "DELETE" => {
            if objects.remove(key).is_none() && config.has(Fault::DeleteMissingIs404) {
                return Err(no_such_key());
            }
            Ok(Response::new(204, Vec::new(), Vec::new()))
        }
        _ => Err(method_not_allowed()),
    }
}
