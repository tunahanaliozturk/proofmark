//! An HTTP/1.1 client on blocking sockets, with optional TLS
//! ([ADR 0002](../docs/adr/0002-own-http1-client-on-blocking-sockets.md)).
//!
//! What a [`Request`] holds is what goes on the wire: the client adds no
//! header, removes none and reorders none. One connection per request,
//! closed afterwards. Status codes are data: a `412` is a [`Response`], not
//! an error.

mod wire;

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};

use crate::sigv4::{REDACTED, encode_component, is_secret_name, percent_decode};

pub(crate) use wire::{Wire, request_framing};

/// One request, exactly as it will be sent.
///
/// `Debug` hides the values of the `Authorization` header, the session
/// token and the presigned signature and credential, and shows the body's
/// length rather than its bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    /// A request with no query, no headers and no body. `path` is sent as
    /// given, so it must already be percent-encoded.
    #[must_use]
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            query: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// The same request with one more query parameter, unencoded.
    #[must_use]
    pub fn with_query(mut self, key: &str, value: &str) -> Self {
        self.push_query(key, value);
        self
    }

    /// The same request with one more header.
    #[must_use]
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.push_header(name, value);
        self
    }

    /// The same request with `body`.
    #[must_use]
    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Appends a query parameter, unencoded.
    pub fn push_query(&mut self, key: &str, value: &str) {
        self.query.push((key.to_owned(), value.to_owned()));
    }

    /// Keeps only the query parameters for which `keep` is true.
    pub(crate) fn retain_query(&mut self, keep: impl FnMut(&(String, String)) -> bool) {
        self.query.retain(keep);
    }

    /// Appends a header.
    pub fn push_header(&mut self, name: &str, value: &str) {
        self.headers.push((name.to_owned(), value.to_owned()));
    }

    /// The method.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The path, percent-encoded, as sent.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The query parameters, unencoded, in send order.
    #[must_use]
    pub fn query(&self) -> &[(String, String)] {
        &self.query
    }

    /// The headers in send order.
    #[must_use]
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The first header named `name`, ignoring case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        first(&self.headers, name)
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The request target: the path, and the query encoded with SigV4's
    /// rules. A parameter with an empty value is sent as `key` alone, the
    /// way S3 sub-resources such as `?uploads` are written.
    #[must_use]
    pub fn target(&self) -> String {
        let mut target = self.path.clone();
        for (i, (key, value)) in self.query.iter().enumerate() {
            target.push(if i == 0 { '?' } else { '&' });
            target.push_str(&encode_component(key.as_bytes()));
            if !value.is_empty() {
                target.push('=');
                target.push_str(&encode_component(value.as_bytes()));
            }
        }
        target
    }

    /// Splits a request target as received into a path and decoded query
    /// parameters, the inverse of [`Request::target`].
    pub(crate) fn from_target(method: &str, target: &str, headers: Vec<(String, String)>) -> Self {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let query = query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                let decode = |s: &str| String::from_utf8_lossy(&percent_decode(s)).into_owned();
                (decode(key), decode(value))
            })
            .collect();
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            query,
            headers,
            body: Vec::new(),
        }
    }

    fn head_bytes(&self) -> Result<Vec<u8>, HttpError> {
        let bad = |s: &str| s.bytes().any(|b| b == b'\r' || b == b'\n');
        if bad(&self.method)
            || self.method.contains(' ')
            || bad(&self.path)
            || self.path.contains(' ')
        {
            return Err(HttpError::InvalidRequest(
                "method or path contains a space or line break",
            ));
        }
        let mut head = format!("{} {} HTTP/1.1\r\n", self.method, self.target());
        for (name, value) in &self.headers {
            if bad(name) || bad(value) || name.contains(':') || name.is_empty() {
                return Err(HttpError::InvalidRequest(
                    "header contains a line break or bad name",
                ));
            }
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        Ok(head.into_bytes())
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |pairs: &[(String, String)]| -> Vec<(String, String)> {
            pairs
                .iter()
                .map(|(name, value)| {
                    let shown = if is_secret_name(name) {
                        REDACTED
                    } else {
                        value
                    };
                    (name.clone(), shown.to_owned())
                })
                .collect()
        };
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("query", &redact(&self.query))
            .field("headers", &redact(&self.headers))
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// One response, with headers in received order and duplicates kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    /// A response, as the fake server builds them.
    #[must_use]
    pub fn new(status: u16, headers: Vec<(String, String)>, body: Vec<u8>) -> Self {
        Self {
            status,
            headers,
            body,
        }
    }

    /// The status code.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }

    /// The headers in received order.
    #[must_use]
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// The first header named `name`, ignoring case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        first(&self.headers, name)
    }

    /// The body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

fn first<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Why an exchange failed. A response with any status code is not a
/// failure; these are the cases where there is no response to judge.
#[derive(Debug)]
#[non_exhaustive]
pub enum HttpError {
    /// The endpoint URL is not `http://host[:port]` or `https://host[:port]`.
    InvalidEndpoint(String),
    /// The request cannot be written as HTTP/1.1.
    InvalidRequest(&'static str),
    /// An `https` endpoint with a client that has no TLS configuration.
    TlsNotConfigured,
    /// The TLS configuration could not be built.
    TlsConfig(String),
    /// Could not connect.
    Connect(io::Error),
    /// The TLS handshake or a TLS record failed.
    Tls(rustls::Error),
    /// Reading or writing failed.
    Io(io::Error),
    /// The request did not finish within the timeout.
    TimedOut,
    /// The peer closed the connection in the middle of a message.
    UnexpectedEof,
    /// The peer sent something that is not HTTP/1.1.
    Malformed(String),
    /// A body is larger than the limit.
    TooLarge,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint(why) => write!(f, "invalid endpoint: {why}"),
            Self::InvalidRequest(why) => write!(f, "invalid request: {why}"),
            Self::TlsNotConfigured => f.write_str("https endpoint, but TLS is not configured"),
            Self::TlsConfig(why) => write!(f, "TLS configuration: {why}"),
            Self::Connect(e) => write!(f, "could not connect: {e}"),
            Self::Tls(e) => write!(f, "TLS: {e}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::TimedOut => f.write_str("timed out"),
            Self::UnexpectedEof => f.write_str("connection closed in the middle of a message"),
            Self::Malformed(why) => write!(f, "malformed HTTP: {why}"),
            Self::TooLarge => f.write_str("body larger than the limit"),
        }
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Connect(e) | Self::Io(e) => Some(e),
            Self::Tls(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for HttpError {
    fn from(e: io::Error) -> Self {
        if let Some(tls) = e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            return Self::Tls(tls.clone());
        }
        match e.kind() {
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => Self::TimedOut,
            io::ErrorKind::UnexpectedEof => Self::UnexpectedEof,
            _ => Self::Io(e),
        }
    }
}

/// `http` or `https`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// Plain TCP.
    Http,
    /// TLS over TCP.
    Https,
}

/// Where requests go: scheme, host and port. No path.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    scheme: Scheme,
    host: String,
    port: u16,
}

impl Endpoint {
    /// Parses `http://host[:port]` or `https://host[:port]`, with an
    /// optional trailing `/`. IPv6 hosts are written in brackets.
    ///
    /// # Errors
    ///
    /// [`HttpError::InvalidEndpoint`] for any other shape.
    pub fn parse(url: &str) -> Result<Self, HttpError> {
        let invalid = |why: &str| HttpError::InvalidEndpoint(format!("{url:?}: {why}"));
        let (scheme, rest) = if let Some(rest) = url.strip_prefix("http://") {
            (Scheme::Http, rest)
        } else if let Some(rest) = url.strip_prefix("https://") {
            (Scheme::Https, rest)
        } else {
            return Err(invalid("must start with http:// or https://"));
        };
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.is_empty() || authority.contains(['/', '?', '#', '@', ' ']) {
            return Err(invalid("must be scheme://host[:port] with no path"));
        }
        let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
            let (host, after) = inner
                .split_once(']')
                .ok_or_else(|| invalid("unclosed '['"))?;
            (host, after.strip_prefix(':'))
        } else {
            match authority.rsplit_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            }
        };
        if host.is_empty() {
            return Err(invalid("empty host"));
        }
        let port = match port {
            Some(port) => port.parse().map_err(|_| invalid("bad port"))?,
            None if scheme == Scheme::Http => 80,
            None => 443,
        };
        Ok(Self {
            scheme,
            host: host.to_owned(),
            port,
        })
    }

    /// An `http` endpoint for a socket address, as the fake server listens on.
    #[must_use]
    pub fn from_addr(scheme: Scheme, addr: SocketAddr) -> Self {
        Self {
            scheme,
            host: addr.ip().to_string(),
            port: addr.port(),
        }
    }

    /// The scheme.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The host, without brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The `Host` header value: the host, and the port unless it is the
    /// scheme's default.
    #[must_use]
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = matches!(
            (self.scheme, self.port),
            (Scheme::Http, 80) | (Scheme::Https, 443)
        );
        if default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = if self.scheme == Scheme::Http {
            "http"
        } else {
            "https"
        };
        write!(f, "{scheme}://{}", self.authority())
    }
}

/// A TLS client configuration that trusts the operating system's roots
/// and, if given, the certificates in `extra_ca_pem`.
///
/// # Errors
///
/// [`HttpError::TlsConfig`] if `extra_ca_pem` holds no usable certificate.
pub fn tls_config_native(
    extra_ca_pem: Option<&[u8]>,
) -> Result<Arc<rustls::ClientConfig>, HttpError> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    if let Some(pem) = extra_ca_pem {
        add_pem(&mut roots, pem)?;
    }
    build_client_config(roots)
}

/// A TLS client configuration that trusts only the certificates in
/// `ca_pem`, for tests against a server with a private CA.
///
/// # Errors
///
/// [`HttpError::TlsConfig`] if `ca_pem` holds no usable certificate.
pub fn tls_config_with_roots(ca_pem: &[u8]) -> Result<Arc<rustls::ClientConfig>, HttpError> {
    let mut roots = rustls::RootCertStore::empty();
    add_pem(&mut roots, ca_pem)?;
    build_client_config(roots)
}

fn add_pem(roots: &mut rustls::RootCertStore, pem: &[u8]) -> Result<(), HttpError> {
    let certs = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| HttpError::TlsConfig(format!("reading PEM: {e}")))?;
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(HttpError::TlsConfig(
            "no usable CA certificate in the PEM data".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) fn crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn build_client_config(
    roots: rustls::RootCertStore,
) -> Result<Arc<rustls::ClientConfig>, HttpError> {
    let config = rustls::ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| HttpError::TlsConfig(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

enum Conn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

/// A connection whose every read and write must finish by `deadline`.
struct Timed {
    conn: Conn,
    deadline: Instant,
}

impl Timed {
    fn arm(&self) -> io::Result<()> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let tcp = match &self.conn {
            Conn::Plain(tcp) => tcp,
            Conn::Tls(tls) => &tls.sock,
        };
        tcp.set_read_timeout(Some(left))?;
        tcp.set_write_timeout(Some(left))
    }
}

impl Read for Timed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm()?;
        match &mut self.conn {
            Conn::Plain(tcp) => tcp.read(buf),
            Conn::Tls(tls) => tls.read(buf),
        }
    }
}

impl Write for Timed {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm()?;
        match &mut self.conn {
            Conn::Plain(tcp) => tcp.write(buf),
            Conn::Tls(tls) => tls.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.arm()?;
        match &mut self.conn {
            Conn::Plain(tcp) => tcp.flush(),
            Conn::Tls(tls) => tls.flush(),
        }
    }
}

/// Sends requests. Cheap to clone; holds only settings.
#[derive(Debug, Clone)]
pub struct Client {
    timeout: Duration,
    continue_wait: Duration,
    max_body: usize,
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            continue_wait: Duration::from_secs(1),
            max_body: 64 * 1024 * 1024,
            tls: None,
        }
    }
}

impl Client {
    /// A client for `http` endpoints, with a 30-second timeout per request,
    /// a 1-second wait for `100 Continue` and a 64 MiB response body limit.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The same client with `timeout` for each whole exchange, from
    /// connecting to the last byte of the response.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The same client, waiting `wait` for a `100 Continue` before sending
    /// the body anyway (RFC 9110, section 10.1.1).
    #[must_use]
    pub fn with_continue_wait(mut self, wait: Duration) -> Self {
        self.continue_wait = wait;
        self
    }

    /// The same client, refusing response bodies over `max_body` bytes.
    #[must_use]
    pub fn with_max_body(mut self, max_body: usize) -> Self {
        self.max_body = max_body;
        self
    }

    /// The same client, able to reach `https` endpoints.
    #[must_use]
    pub fn with_tls(mut self, config: Arc<rustls::ClientConfig>) -> Self {
        self.tls = Some(config);
        self
    }

    /// Sends `request` to `endpoint` on a new connection and reads the
    /// final response.
    ///
    /// With `Expect: 100-continue`, the body is held back until the server
    /// answers `100 Continue`, or the continue wait passes. If the server
    /// sends a final response first, the body is never sent and that
    /// response is returned.
    ///
    /// # Errors
    ///
    /// [`HttpError`] when there is no complete response: connecting, TLS,
    /// I/O, the timeout, a malformed or oversized response.
    pub fn send(&self, endpoint: &Endpoint, request: &Request) -> Result<Response, HttpError> {
        let deadline = Instant::now() + self.timeout;
        let head = request.head_bytes()?;
        let tcp = connect(endpoint, deadline)?;
        let conn = match endpoint.scheme {
            Scheme::Http => Conn::Plain(tcp),
            Scheme::Https => {
                let config = self.tls.as_ref().ok_or(HttpError::TlsNotConfigured)?;
                let name = ServerName::try_from(endpoint.host.clone())
                    .map_err(|e| HttpError::InvalidEndpoint(e.to_string()))?;
                let session = rustls::ClientConnection::new(Arc::clone(config), name)
                    .map_err(HttpError::Tls)?;
                Conn::Tls(Box::new(rustls::StreamOwned::new(session, tcp)))
            }
        };
        let mut timed = Timed { conn, deadline };
        let expects_continue = request
            .header("expect")
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("100-continue"));
        timed.write_all(&head)?;
        if !expects_continue {
            timed.write_all(&request.body)?;
        }
        timed.flush()?;
        let mut wire = Wire::new(timed);

        if expects_continue {
            wire.get_mut().deadline = deadline.min(Instant::now() + self.continue_wait);
            let early = loop {
                match wire.response_head() {
                    Ok(head) if head.status == 100 => break None,
                    Ok(head) if head.status < 200 => {}
                    Ok(head) => break Some(head),
                    Err(HttpError::TimedOut) if Instant::now() < deadline => break None,
                    Err(e) => return Err(e),
                }
            };
            wire.get_mut().deadline = deadline;
            if let Some(head) = early {
                return self.finish(&mut wire, request, head);
            }
            wire.get_mut().write_all(&request.body)?;
            wire.get_mut().flush()?;
        }

        let head = loop {
            let head = wire.response_head()?;
            if head.status >= 200 {
                break head;
            }
        };
        self.finish(&mut wire, request, head)
    }

    fn finish<R: Read>(
        &self,
        wire: &mut Wire<R>,
        request: &Request,
        head: wire::ResponseHead,
    ) -> Result<Response, HttpError> {
        let framing = wire::response_framing(head.status, &request.method, &head.headers)?;
        let body = wire.body(framing, self.max_body)?;
        Ok(Response {
            status: head.status,
            headers: head.headers,
            body,
        })
    }
}

fn connect(endpoint: &Endpoint, deadline: Instant) -> Result<TcpStream, HttpError> {
    let addrs = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(HttpError::Connect)?;
    let mut last = io::Error::new(io::ErrorKind::NotFound, "the host resolved to no address");
    for addr in addrs {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(HttpError::TimedOut);
        }
        match TcpStream::connect_timeout(&addr, left) {
            Ok(tcp) => {
                tcp.set_nodelay(true).map_err(HttpError::Connect)?;
                return Ok(tcp);
            }
            Err(e) => last = e,
        }
    }
    Err(HttpError::Connect(last))
}

/// Parses one complete response from `input`, as the client would after
/// sending a request with `method`. For tests and fuzzing: the client
/// itself reads from a socket with timeouts.
///
/// # Errors
///
/// [`HttpError`] if `input` is not one complete, well-formed response
/// within `max_body`.
pub fn parse_response(
    input: impl Read,
    method: &str,
    max_body: usize,
) -> Result<Response, HttpError> {
    let mut wire = Wire::new(input);
    let head = loop {
        let head = wire.response_head()?;
        if head.status >= 200 {
            break head;
        }
    };
    let framing = wire::response_framing(head.status, method, &head.headers)?;
    let body = wire.body(framing, max_body)?;
    Ok(Response {
        status: head.status,
        headers: head.headers,
        body,
    })
}

/// Parses one complete request from `input`, as the fake server would.
/// For tests and fuzzing.
///
/// # Errors
///
/// [`HttpError`] if `input` is not one complete, well-formed request within
/// `max_body`.
pub fn parse_request(input: impl Read, max_body: usize) -> Result<Request, HttpError> {
    let mut wire = Wire::new(input);
    let head = wire.request_head()?;
    let framing = request_framing(&head.headers)?;
    let mut request = Request::from_target(&head.method, &head.target, head.headers);
    request.body = wire.body(framing, max_body)?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_the_target_with_encoded_query() {
        let request = Request::new("GET", "/bucket/a%20b")
            .with_query("uploads", "")
            .with_query("prefix", "x/y z");
        assert_eq!(request.target(), "/bucket/a%20b?uploads&prefix=x%2Fy%20z");
    }

    #[test]
    fn writes_headers_in_order_and_adds_none() {
        let request = Request::new("PUT", "/b/k")
            .with_header("Host", "h")
            .with_header("x-b", "2")
            .with_header("x-a", "1")
            .with_body(b"data".to_vec());
        let head = String::from_utf8(request.head_bytes().expect("renders")).expect("utf-8");
        assert_eq!(
            head,
            "PUT /b/k HTTP/1.1\r\nHost: h\r\nx-b: 2\r\nx-a: 1\r\n\r\n"
        );
    }

    #[test]
    fn refuses_header_injection() {
        let request = Request::new("GET", "/").with_header("x", "a\r\nInjected: 1");
        assert!(matches!(
            request.head_bytes(),
            Err(HttpError::InvalidRequest(_))
        ));
        let request = Request::new("GET", "/a b");
        assert!(matches!(
            request.head_bytes(),
            Err(HttpError::InvalidRequest(_))
        ));
    }

    #[test]
    fn parses_endpoints() {
        let e = Endpoint::parse("http://127.0.0.1:9000").expect("parses");
        assert_eq!(
            (e.scheme(), e.host(), e.port()),
            (Scheme::Http, "127.0.0.1", 9000)
        );
        assert_eq!(e.authority(), "127.0.0.1:9000");
        let e = Endpoint::parse("https://s3.example.com/").expect("parses");
        assert_eq!(
            (e.port(), e.authority()),
            (443, "s3.example.com".to_owned())
        );
        let e = Endpoint::parse("http://[::1]:9000").expect("parses");
        assert_eq!((e.host(), e.authority()), ("::1", "[::1]:9000".to_owned()));
        for bad in [
            "ftp://x",
            "http://",
            "http://h/path",
            "http://h:port",
            "http://h:70000",
            "x",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_a_request_target_back_into_parts() {
        let original = Request::new("GET", "/b/k%2B1")
            .with_query("prefix", "a+b c")
            .with_query("uploads", "");
        let parsed = Request::from_target("GET", &original.target(), Vec::new());
        assert_eq!(parsed.path(), "/b/k%2B1");
        assert_eq!(parsed.query(), original.query());
    }

    #[test]
    fn skips_interim_responses() {
        let input = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let response = parse_response(&input[..], "PUT", 1024).expect("parses");
        assert_eq!((response.status(), response.body()), (200, &b"ok"[..]));
    }

    #[test]
    fn reads_to_close_without_a_length() {
        let input = b"HTTP/1.1 200 OK\r\n\r\nall of it";
        let response = parse_response(&input[..], "GET", 1024).expect("parses");
        assert_eq!(response.body(), b"all of it");
    }

    #[test]
    fn a_head_response_has_no_body_even_with_a_length() {
        let input = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
        let response = parse_response(&input[..], "HEAD", 1024).expect("parses");
        assert_eq!(response.header("content-length"), Some("1000"));
        assert_eq!(response.body(), b"");
    }

    #[test]
    fn a_truncated_body_is_an_error() {
        let input = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort";
        assert!(matches!(
            parse_response(&input[..], "GET", 1024),
            Err(HttpError::UnexpectedEof)
        ));
    }
}
