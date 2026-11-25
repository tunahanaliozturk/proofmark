//! AWS Signature Version 4 as S3 uses it: the `Authorization` header,
//! presigned URLs, and the chunk and trailer signatures of signed
//! `aws-chunked` uploads.
//!
//! Everything here is pure. The time is an argument, and the request is the
//! one [`crate::http`] will send, so what is signed is what goes on the wire.
//!
//! S3 differs from other services in two ways that matter here: the path is
//! not normalised (`a//b` and `a/./b` are distinct keys), and it is encoded
//! once, not twice. References: [S3 header-based
//! auth](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html),
//! sections "Canonical request" and "Examples: Signature Calculations".

use std::collections::BTreeMap;
use std::fmt;

use ring::hmac;

use crate::checksum::{hex, sha256_hex};
use crate::http::Request;
use crate::time::UtcTime;

/// The only algorithm proofmark signs with.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// `x-amz-content-sha256` value for a body that is not signed.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
/// `x-amz-content-sha256` value for signed `aws-chunked` uploads.
pub const STREAMING_SIGNED: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
/// `x-amz-content-sha256` value for signed `aws-chunked` uploads with a signed trailer.
pub const STREAMING_SIGNED_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
/// `x-amz-content-sha256` value for unsigned `aws-chunked` uploads with a trailer.
pub const STREAMING_UNSIGNED_TRAILER: &str = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";
/// SHA-256 of the empty string, in hex.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Headers never signed, because proxies and transports add, drop or rewrite
/// them. The list is the one in aws-c-auth (`s_skipped_headers` in
/// `source/aws_signing.c`), plus `authorization` itself.
const UNSIGNED_HEADERS: [&str; 10] = [
    "authorization",
    "x-amzn-trace-id",
    "user-agent",
    "connection",
    "expect",
    "sec-websocket-key",
    "sec-websocket-protocol",
    "sec-websocket-version",
    "upgrade",
    "transfer-encoding",
];

/// An access key pair, and a session token if the credentials are temporary.
///
/// `Debug` prints the access key id only.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

impl Credentials {
    /// Long-term credentials, with no session token.
    #[must_use]
    pub fn new(access_key_id: &str, secret_access_key: &str) -> Self {
        Self {
            access_key_id: access_key_id.to_owned(),
            secret_access_key: secret_access_key.to_owned(),
            session_token: None,
        }
    }

    /// The same credentials with a session token.
    #[must_use]
    pub fn with_session_token(mut self, token: &str) -> Self {
        self.session_token = Some(token.to_owned());
        self
    }

    /// The access key id, which is not secret.
    #[must_use]
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// The session token, if any.
    #[must_use]
    pub fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// The intermediate and final values of one signature, so that tests can
/// compare each step with published vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    canonical_request: String,
    string_to_sign: String,
    signed_headers: String,
    hex: String,
}

impl Signature {
    /// The canonical request, step 1 of the algorithm.
    #[must_use]
    pub fn canonical_request(&self) -> &str {
        &self.canonical_request
    }

    /// The string to sign, step 2.
    #[must_use]
    pub fn string_to_sign(&self) -> &str {
        &self.string_to_sign
    }

    /// The `;`-separated lowercase names of the signed headers.
    #[must_use]
    pub fn signed_headers(&self) -> &str {
        &self.signed_headers
    }

    /// The signature, in lowercase hex.
    #[must_use]
    pub fn signature(&self) -> &str {
        &self.hex
    }
}

/// Signs requests for one set of credentials, region, service and time.
#[derive(Debug, Clone, Copy)]
pub struct Signer<'a> {
    credentials: &'a Credentials,
    region: &'a str,
    service: &'a str,
    time: UtcTime,
}

impl<'a> Signer<'a> {
    /// A signer for `service` (`s3` for S3) in `region` at `time`.
    #[must_use]
    pub fn new(
        credentials: &'a Credentials,
        region: &'a str,
        service: &'a str,
        time: UtcTime,
    ) -> Self {
        Self {
            credentials,
            region,
            service,
            time,
        }
    }

    /// The credential scope, `20130524/us-east-1/s3/aws4_request`.
    #[must_use]
    pub fn scope(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            self.time.amz_date(),
            self.region,
            self.service
        )
    }

    fn key(&self) -> hmac::Key {
        let secret = format!("AWS4{}", self.credentials.secret_access_key);
        let mut key = hmac_sha256(secret.as_bytes(), self.time.amz_date().as_bytes());
        for part in [self.region, self.service, "aws4_request"] {
            key = hmac_sha256(&key, part.as_bytes());
        }
        hmac::Key::new(hmac::HMAC_SHA256, &key)
    }

    fn finish(&self, canonical_request: String, signed_headers: String) -> Signature {
        let string_to_sign = format!(
            "{ALGORITHM}\n{}\n{}\n{}",
            self.time.amz(),
            self.scope(),
            sha256_hex(canonical_request.as_bytes())
        );
        let signature = hex(hmac::sign(&self.key(), string_to_sign.as_bytes()).as_ref());
        Signature {
            canonical_request,
            string_to_sign,
            signed_headers,
            hex: signature,
        }
    }

    /// Signs `request` as it stands, over every header except those that
    /// transports rewrite. The caller has already added `host`,
    /// `x-amz-date` and anything else that must be signed.
    #[must_use]
    pub fn sign(&self, request: &Request, payload_hash: &str) -> Signature {
        let (canonical, signed) = canonical_request(request, &[], payload_hash, &|name| {
            !UNSIGNED_HEADERS.contains(&name)
        });
        self.finish(canonical, signed)
    }

    /// Signs `request` over exactly the headers named in `signed_headers`
    /// (lowercase, as in an `Authorization` header). This is how a server
    /// checks a signature. Returns `None` if a named header is missing.
    #[must_use]
    pub fn sign_named(
        &self,
        request: &Request,
        payload_hash: &str,
        signed_headers: &[&str],
    ) -> Option<Signature> {
        let present = |name: &str| {
            request
                .headers()
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case(name))
        };
        if signed_headers.is_empty() || !signed_headers.iter().all(|name| present(name)) {
            return None;
        }
        let (canonical, signed) = canonical_request(request, &[], payload_hash, &|name| {
            signed_headers.contains(&name)
        });
        Some(self.finish(canonical, signed))
    }

    /// The `Authorization` header value for `signature`.
    #[must_use]
    pub fn authorization(&self, signature: &Signature) -> String {
        format!(
            "{ALGORITHM} Credential={}/{}, SignedHeaders={}, Signature={}",
            self.credentials.access_key_id,
            self.scope(),
            signature.signed_headers,
            signature.hex
        )
    }

    /// Adds `x-amz-date`, `x-amz-content-sha256`, the session token if
    /// there is one, and finally `authorization`, in that order, to the end
    /// of the request's headers.
    pub fn sign_request(&self, request: &mut Request, payload_hash: &str) -> Signature {
        request.push_header("x-amz-date", &self.time.amz());
        request.push_header("x-amz-content-sha256", payload_hash);
        if let Some(token) = self.credentials.session_token() {
            request.push_header("x-amz-security-token", token);
        }
        let signature = self.sign(request, payload_hash);
        request.push_header("authorization", &self.authorization(&signature));
        signature
    }

    /// Turns `request` into a presigned request: appends the `X-Amz-*`
    /// query parameters, with `X-Amz-Signature` last. S3 uses
    /// [`UNSIGNED_PAYLOAD`] as the payload hash of a presigned URL.
    pub fn presign(
        &self,
        request: &mut Request,
        expires_seconds: u32,
        payload_hash: &str,
    ) -> Signature {
        let (_, signed_headers) =
            canonical_headers(request, &|name| !UNSIGNED_HEADERS.contains(&name));
        let mut auth = vec![
            ("X-Amz-Algorithm".to_owned(), ALGORITHM.to_owned()),
            (
                "X-Amz-Credential".to_owned(),
                format!("{}/{}", self.credentials.access_key_id, self.scope()),
            ),
            ("X-Amz-Date".to_owned(), self.time.amz()),
            ("X-Amz-Expires".to_owned(), expires_seconds.to_string()),
            ("X-Amz-SignedHeaders".to_owned(), signed_headers),
        ];
        if let Some(token) = self.credentials.session_token() {
            auth.push(("X-Amz-Security-Token".to_owned(), token.to_owned()));
        }
        let (canonical, signed) = canonical_request(request, &auth, payload_hash, &|name| {
            !UNSIGNED_HEADERS.contains(&name)
        });
        let signature = self.finish(canonical, signed);
        for (key, value) in auth {
            request.push_query(&key, &value);
        }
        request.push_query("X-Amz-Signature", &signature.hex);
        signature
    }

    /// A signer for the chunks of a signed `aws-chunked` body whose request
    /// was signed with `seed`.
    #[must_use]
    pub fn chunk_signer(&self, seed: &Signature) -> ChunkSigner {
        ChunkSigner {
            key: self.key(),
            time: self.time.amz(),
            scope: self.scope(),
            previous: seed.hex.clone(),
        }
    }
}

/// Signs the chunks, and then the trailer, of one `aws-chunked` body. Each
/// signature covers the one before it, so the order of calls matters.
pub struct ChunkSigner {
    key: hmac::Key,
    time: String,
    scope: String,
    previous: String,
}

impl fmt::Debug for ChunkSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChunkSigner")
            .field("scope", &self.scope)
            .field("previous", &self.previous)
            .finish_non_exhaustive()
    }
}

impl ChunkSigner {
    fn chain(&mut self, string_to_sign: &str) -> String {
        let signature = hex(hmac::sign(&self.key, string_to_sign.as_bytes()).as_ref());
        self.previous.clone_from(&signature);
        signature
    }

    /// The signature of the next chunk. The final, empty chunk is signed too.
    pub fn sign_chunk(&mut self, data: &[u8]) -> String {
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{EMPTY_SHA256}\n{}",
            self.time,
            self.scope,
            self.previous,
            sha256_hex(data)
        );
        self.chain(&string_to_sign)
    }

    /// The signature of the trailer, sent as `x-amz-trailer-signature`.
    /// Each trailer is hashed as `name:value\n`.
    pub fn sign_trailer(&mut self, trailers: &[(String, String)]) -> String {
        let canonical: Vec<String> = trailers
            .iter()
            .map(|(name, value)| format!("{name}:{value}\n"))
            .collect();
        let canonical = canonical.concat();
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
            self.time,
            self.scope,
            self.previous,
            sha256_hex(canonical.as_bytes())
        );
        self.chain(&string_to_sign)
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data)
        .as_ref()
        .to_vec()
}

fn canonical_request(
    request: &Request,
    extra_query: &[(String, String)],
    payload_hash: &str,
    include: &dyn Fn(&str) -> bool,
) -> (String, String) {
    let mut query: Vec<(String, String)> = request
        .query()
        .iter()
        .chain(extra_query)
        .map(|(key, value)| {
            (
                encode_component(key.as_bytes()),
                encode_component(value.as_bytes()),
            )
        })
        .collect();
    // By encoded key, then by encoded value. Sorting the joined `key=value`
    // strings instead would put `a-b` before `a`, because `-` sorts before `=`.
    query.sort_unstable();
    let query: Vec<String> = query
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect();
    let (headers, signed) = canonical_headers(request, include);
    let canonical = format!(
        "{}\n{}\n{}\n{headers}\n{signed}\n{payload_hash}",
        request.method(),
        canonical_uri(request.path()),
        query.join("&"),
    );
    (canonical, signed)
}

fn canonical_headers(request: &Request, include: &dyn Fn(&str) -> bool) -> (String, String) {
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in request.headers() {
        let name = name.to_ascii_lowercase();
        if include(&name) {
            grouped
                .entry(name)
                .or_default()
                .push(collapse_spaces(value));
        }
    }
    let block: Vec<String> = grouped
        .iter()
        .map(|(name, values)| format!("{name}:{}\n", values.join(",")))
        .collect();
    let block = block.concat();
    let signed = grouped
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(";");
    (block, signed)
}

/// Trims a header value and turns each run of spaces or tabs into one space.
fn collapse_spaces(value: &str) -> String {
    value
        .split([' ', '\t'])
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The canonical URI of a path as sent: each segment between literal `/`
/// decoded, then encoded once, so an escaped `%2F` inside a segment stays
/// escaped. S3 does not normalise, so `//` and `.` segments stay as they
/// are. An empty path is `/`.
#[must_use]
pub fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        return "/".to_owned();
    }
    path.split('/')
        .map(|segment| encode_component(&percent_decode(segment)))
        .collect::<Vec<_>>()
        .join("/")
}

fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn encode(bytes: &[u8], keep: &dyn Fn(u8) -> bool) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        if keep(byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
    }
    out
}

/// URI-encodes an object key or path the way SigV4 wants: every byte except
/// the unreserved characters and `/`, with uppercase hex.
#[must_use]
pub fn encode_path(bytes: &[u8]) -> String {
    encode(bytes, &|b| is_unreserved(b) || b == b'/')
}

/// URI-encodes a query key or value: every byte except the unreserved
/// characters, `/` included.
#[must_use]
pub fn encode_component(bytes: &[u8]) -> String {
    encode(bytes, &is_unreserved)
}

/// Decodes `%XX` escapes. A `%` that does not start a valid escape is kept
/// as it is, and `+` stays `+`.
#[must_use]
pub fn percent_decode(text: &str) -> Vec<u8> {
    fn digit(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let (Some(high), Some(low)) = (
                bytes.get(i + 1).copied().and_then(digit),
                bytes.get(i + 2).copied().and_then(digit),
            )
        {
            out.push(high << 4 | low);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// The parts of an `Authorization: AWS4-HMAC-SHA256 ...` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    access_key_id: String,
    date: String,
    region: String,
    service: String,
    signed_headers: Vec<String>,
    signature: String,
}

impl Authorization {
    /// Parses the header value. Returns `None` if it is not a well-formed
    /// SigV4 header.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let rest = value.strip_prefix(ALGORITHM)?.strip_prefix(' ')?;
        let (mut credential, mut signed, mut signature) = (None, None, None);
        for part in rest.split(',') {
            let (name, value) = part.trim().split_once('=')?;
            match name {
                "Credential" => credential = Some(value),
                "SignedHeaders" => signed = Some(value),
                "Signature" => signature = Some(value),
                _ => return None,
            }
        }
        let mut scope = credential?.split('/');
        let access_key_id = scope.next()?.to_owned();
        let date = scope.next()?.to_owned();
        let region = scope.next()?.to_owned();
        let service = scope.next()?.to_owned();
        if scope.next() != Some("aws4_request") || scope.next().is_some() {
            return None;
        }
        let signed_headers: Vec<String> = signed?.split(';').map(str::to_owned).collect();
        let signature = signature?.to_owned();
        if signature.len() != 64 || !signature.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self {
            access_key_id,
            date,
            region,
            service,
            signed_headers,
            signature,
        })
    }

    /// The access key id from the credential.
    #[must_use]
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// The scope date, `YYYYMMDD`.
    #[must_use]
    pub fn date(&self) -> &str {
        &self.date
    }

    /// The scope region.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The scope service.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The signed header names, as sent.
    #[must_use]
    pub fn signed_headers(&self) -> Vec<&str> {
        self.signed_headers.iter().map(String::as_str).collect()
    }

    /// The signature, as sent.
    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_like_the_s3_uri_encode_rules() {
        assert_eq!(
            encode_path(b"photos/Jan/sample.jpg"),
            "photos/Jan/sample.jpg"
        );
        assert_eq!(encode_component(b"photos/Jan"), "photos%2FJan");
        assert_eq!(encode_path("a b+c$~".as_bytes()), "a%20b%2Bc%24~");
        assert_eq!(encode_path("\u{1234}".as_bytes()), "%E1%88%B4");
    }

    #[test]
    fn decodes_escapes_and_keeps_stray_percent_signs() {
        assert_eq!(percent_decode("a%20b%2fc"), b"a b/c");
        assert_eq!(percent_decode("100%"), b"100%");
        assert_eq!(percent_decode("%zz+%4"), b"%zz+%4");
    }

    #[test]
    fn the_canonical_uri_keeps_double_slashes_and_dot_segments() {
        assert_eq!(canonical_uri("//example//"), "//example//");
        assert_eq!(canonical_uri("/a/./b/../c"), "/a/./b/../c");
        assert_eq!(canonical_uri("/test$file.text"), "/test%24file.text");
    }

    #[test]
    fn the_canonical_uri_keeps_an_escaped_slash_escaped() {
        // `a%2Fb` is one key segment holding a slash; decoding it to `a/b`
        // would sign a different path from the one sent.
        assert_eq!(canonical_uri("/bucket/a%2Fb"), "/bucket/a%2Fb");
        assert_eq!(canonical_uri("/bucket/a%2fb"), "/bucket/a%2Fb");
        assert_eq!(canonical_uri("/bucket/a%20b/c"), "/bucket/a%20b/c");
    }

    #[test]
    fn an_empty_path_canonicalises_to_a_slash() {
        assert_eq!(canonical_uri(""), "/");
    }

    #[test]
    fn collapses_runs_of_spaces_in_header_values() {
        assert_eq!(collapse_spaces("  \"a   b   c\"  "), "\"a b c\"");
    }

    #[test]
    fn credentials_debug_hides_the_secret_and_the_token() {
        let creds = Credentials::new("AKID", "very-secret").with_session_token("token-value");
        let shown = format!("{creds:?}");
        assert!(shown.contains("AKID"));
        assert!(!shown.contains("very-secret"));
        assert!(!shown.contains("token-value"));
    }

    #[test]
    fn parses_an_authorization_header_with_or_without_spaces() {
        let sig = "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";
        for value in [
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range,Signature={sig}"
            ),
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range, Signature={sig}"
            ),
        ] {
            let auth = Authorization::parse(&value).expect("parses");
            assert_eq!(auth.access_key_id(), "AKIAIOSFODNN7EXAMPLE");
            assert_eq!(auth.date(), "20130524");
            assert_eq!(auth.region(), "us-east-1");
            assert_eq!(auth.service(), "s3");
            assert_eq!(auth.signed_headers(), ["host", "range"]);
            assert_eq!(auth.signature(), sig);
        }
    }

    #[test]
    fn rejects_malformed_authorization_headers() {
        for value in [
            "",
            "AWS4-HMAC-SHA256",
            "AWS AKID:sig",
            "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, SignedHeaders=host",
            "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3, SignedHeaders=host, Signature=00",
            "AWS4-HMAC-SHA256 Credential=AKID/20130524/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=zz",
        ] {
            assert_eq!(Authorization::parse(value), None, "{value:?}");
        }
    }
}
