//! The signer against published vectors, not against the fake: a signer and
//! a verifier written by the same hand agree with each other even when
//! both are wrong.
//!
//! Two sources:
//!
//! - The aws-c-auth SigV4 test suite (`tests/fixtures/aws-signing-test-suite/v4`).
//!   S3 never normalises paths, so a case marked `"normalize": true` applies
//!   only when normalising would leave its path unchanged. The
//!   `*-unnormalized` cases with `//` and `.` segments are the ones that
//!   catch a signer that normalises.
//! - The worked examples in the S3 developer guide, read 2026-11-25:
//!   "Examples: Signature Calculations" in
//!   <https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html>,
//!   the presigned URL example in
//!   <https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-query-string-auth.html>,
//!   "Example: PUT Object" in
//!   <https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming.html>
//!   and in
//!   <https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sigv4-streaming-trailers.html>.
#![cfg(test)]

use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use proofmark::aws_chunked;
use proofmark::checksum::sha256_hex;
use proofmark::http::Request;
use proofmark::sigv4::{
    Credentials, EMPTY_SHA256, STREAMING_SIGNED, STREAMING_SIGNED_TRAILER, Signer, percent_decode,
};
use proofmark::time::UtcTime;

fn suite_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/aws-signing-test-suite/v4")
}

/// The value of `"key": "string"` or `"key": true` in a flat JSON object.
/// The context files are small and regular; this is not a JSON parser.
fn json_value(json: &str, key: &str) -> Option<String> {
    let after_key = &json[json.find(&format!("\"{key}\""))? + key.len() + 2..];
    let value = after_key.trim_start().strip_prefix(':')?.trim_start();
    if let Some(quoted) = value.strip_prefix('"') {
        return Some(quoted[..quoted.find('"')?].to_owned());
    }
    let end = value.find([',', '}', '\n', '\r']).unwrap_or(value.len());
    Some(value[..end].trim().to_owned())
}

fn decode(text: &str) -> String {
    String::from_utf8(percent_decode(text)).expect("UTF-8")
}

/// `request.txt` (LF line ends, as upstream) as method, path, query, headers
/// and body. Header lines that start with whitespace continue the previous
/// header (obs-fold).
/// Method, path, query, headers, body.
type RequestFile = (
    String,
    String,
    Vec<(String, String)>,
    Vec<(String, String)>,
    Vec<u8>,
);

fn parse_request_file(raw: &str) -> RequestFile {
    let (head, body) = raw.split_once("\n\n").unwrap_or((raw, ""));
    let mut lines = head.lines();
    let request_line = lines.next().expect("request line");
    let (method, rest) = request_line.split_once(' ').expect("method");
    let (target, _version) = rest.rsplit_once(' ').expect("version");
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(key), decode(value))
        })
        .collect();
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if line.starts_with([' ', '\t']) {
            let last = headers.last_mut().expect("a header before a continuation");
            last.1.push(' ');
            last.1.push_str(line);
        } else if let Some((name, value)) = line.split_once(':') {
            headers.push((name.to_owned(), value.to_owned()));
        }
    }
    (
        method.to_owned(),
        path.to_owned(),
        query,
        headers,
        body.as_bytes().to_vec(),
    )
}

fn build(
    method: &str,
    path: &str,
    query: &[(String, String)],
    headers: &[(String, String)],
    body: &[u8],
) -> Request {
    let mut request = Request::new(method, path).with_body(body.to_vec());
    for (key, value) in query {
        request.push_query(key, value);
    }
    for (name, value) in headers {
        request.push_header(name, value);
    }
    request
}

/// True if RFC 3986 dot-segment removal and slash merging leave `path` as
/// it is, so a normalising and a non-normalising signer agree on it.
fn already_normal(path: &str) -> bool {
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    let last = segments.len().saturating_sub(1);
    segments
        .iter()
        .enumerate()
        .all(|(i, s)| *s != "." && *s != ".." && (!s.is_empty() || i == last))
}

fn read(dir: &Path, name: &str) -> String {
    fs::read_to_string(dir.join(name))
        .unwrap_or_else(|e| panic!("{}: {e}", dir.join(name).display()))
}

/// One case's context and request, read from its directory.
struct Case {
    name: String,
    dir: PathBuf,
    context: String,
    request: RequestFile,
}

impl Case {
    fn flag(&self, key: &str) -> bool {
        json_value(&self.context, key).as_deref() == Some("true")
    }

    fn value(&self, key: &str) -> String {
        json_value(&self.context, key).unwrap_or_else(|| panic!("{}: no {key}", self.name))
    }

    fn expect_file(&self, actual: &str, file: &str) {
        assert_eq!(actual, read(&self.dir, file), "{}: {file}", self.name);
    }

    fn credentials(&self) -> Credentials {
        let credentials = Credentials::new(
            &self.value("access_key_id"),
            &self.value("secret_access_key"),
        );
        // With omit_session_token the token is added after signing, so it
        // is not part of what is signed.
        match json_value(&self.context, "token") {
            Some(token) if !self.flag("omit_session_token") => {
                credentials.with_session_token(&token)
            }
            _ => credentials,
        }
    }

    fn check(&self) {
        let (method, path, query, file_headers, body) = &self.request;
        let time = UtcTime::parse_amz(&self.value("timestamp").replace(['-', ':'], ""))
            .expect("timestamp");
        let credentials = self.credentials();
        let (region, service) = (self.value("region"), self.value("service"));
        let signer = Signer::new(&credentials, &region, &service, time);
        let payload_hash = sha256_hex(body);

        // Authorization header.
        let mut headers = file_headers.clone();
        headers.push(("X-Amz-Date".to_owned(), time.amz()));
        if let Some(token) = credentials.session_token() {
            headers.push(("X-Amz-Security-Token".to_owned(), token.to_owned()));
        }
        if self.flag("sign_body") {
            headers.push(("x-amz-content-sha256".to_owned(), payload_hash.clone()));
        }
        let signature = signer.sign(&build(method, path, query, &headers, body), &payload_hash);
        self.expect_file(
            signature.canonical_request(),
            "header-canonical-request.txt",
        );
        self.expect_file(signature.string_to_sign(), "header-string-to-sign.txt");
        self.expect_file(signature.signature(), "header-signature.txt");
        let signed_request = read(&self.dir, "header-signed-request.txt");
        let expected = signed_request
            .lines()
            .find_map(|line| line.strip_prefix("Authorization:"))
            .expect("Authorization line");
        assert_eq!(
            signer.authorization(&signature),
            expected,
            "{}: Authorization",
            self.name
        );

        // Presigned (query string) form.
        let expires: u32 = self.value("expiration_in_seconds").parse().expect("number");
        let mut request = build(method, path, query, file_headers, body);
        let presigned = signer.presign(&mut request, expires);
        self.expect_file(presigned.canonical_request(), "query-canonical-request.txt");
        self.expect_file(presigned.string_to_sign(), "query-string-to-sign.txt");
        self.expect_file(presigned.signature(), "query-signature.txt");
    }
}

#[test]
fn the_applicable_aws_c_auth_cases_pass() {
    let mut dirs: Vec<PathBuf> = fs::read_dir(suite_dir())
        .expect("suite directory")
        .map(|e| e.expect("entry").path())
        .collect();
    dirs.sort();
    let (mut applied, mut skipped) = (Vec::new(), Vec::new());
    for dir in dirs {
        let case = Case {
            name: dir
                .file_name()
                .expect("name")
                .to_string_lossy()
                .into_owned(),
            context: read(&dir, "context.json"),
            request: parse_request_file(&read(&dir, "request.txt")),
            dir,
        };
        if case.flag("normalize") && !already_normal(&case.request.1) {
            skipped.push(case.name);
            continue;
        }
        case.check();
        applied.push(case.name);
    }
    // 38 cases; the 6 normalised ones with `//` or dot segments do not apply
    // to S3. A change in either number means the suite or the rule moved.
    assert_eq!(
        skipped,
        [
            "get-relative-normalized",
            "get-relative-relative-normalized",
            "get-slash-dot-slash-normalized",
            "get-slash-normalized",
            "get-slash-pointless-dot-normalized",
            "get-slashes-normalized",
        ]
    );
    assert_eq!(applied.len(), 32);
}

fn example_credentials() -> Credentials {
    Credentials::new(
        "AKIAIOSFODNN7EXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )
}

fn example_time() -> UtcTime {
    UtcTime::parse_amz("20130524T000000Z").expect("time")
}

#[test]
fn the_s3_get_object_example_signs_as_documented() {
    let credentials = example_credentials();
    let signer = Signer::new(&credentials, "us-east-1", "s3", example_time());
    let request = Request::new("GET", "/test.txt")
        .with_header("Host", "examplebucket.s3.amazonaws.com")
        .with_header("Range", "bytes=0-9 ")
        .with_header("x-amz-content-sha256", EMPTY_SHA256)
        .with_header("x-amz-date", "20130524T000000Z ");
    let signature = signer.sign(&request, EMPTY_SHA256);
    assert_eq!(
        signature.canonical_request(),
        "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        signature.string_to_sign(),
        "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972"
    );
    assert_eq!(
        signature.signature(),
        "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
    // The guide writes the header without spaces after the commas; S3
    // accepts both, and the SDKs send the spaced form.
    assert_eq!(
        signer.authorization(&signature).replace(", ", ","),
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
    );
}

#[test]
fn the_s3_put_object_example_signs_as_documented() {
    let credentials = example_credentials();
    let signer = Signer::new(&credentials, "us-east-1", "s3", example_time());
    let body = b"Welcome to Amazon S3.".to_vec();
    let payload_hash = sha256_hex(&body);
    assert_eq!(
        payload_hash,
        "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
    );
    // The guide's request line reads `PUT test$file.text`; its canonical URI
    // shows the leading slash, which is what the signer is given here.
    let request = Request::new("PUT", "/test$file.text")
        .with_header("Host", "examplebucket.s3.amazonaws.com")
        .with_header("Date", "Fri, 24 May 2013 00:00:00 GMT")
        .with_header("x-amz-date", "20130524T000000Z")
        .with_header("x-amz-storage-class", "REDUCED_REDUNDANCY")
        .with_header("x-amz-content-sha256", &payload_hash)
        .with_body(body);
    let signature = signer.sign(&request, &payload_hash);
    assert!(
        signature
            .canonical_request()
            .starts_with("PUT\n/test%24file.text\n\n")
    );
    assert_eq!(
        signature.string_to_sign(),
        "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d"
    );
    assert_eq!(
        signature.signature(),
        "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
    );
    assert_eq!(
        signature.signed_headers(),
        "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class"
    );
}

#[test]
fn the_s3_lifecycle_and_list_examples_sign_as_documented() {
    let credentials = example_credentials();
    let signer = Signer::new(&credentials, "us-east-1", "s3", example_time());
    let base = |request: Request| {
        request
            .with_header("Host", "examplebucket.s3.amazonaws.com")
            .with_header("x-amz-date", "20130524T000000Z")
            .with_header("x-amz-content-sha256", EMPTY_SHA256)
    };
    let lifecycle = signer.sign(
        &base(Request::new("GET", "/").with_query("lifecycle", "")),
        EMPTY_SHA256,
    );
    assert!(
        lifecycle
            .canonical_request()
            .starts_with("GET\n/\nlifecycle=\nhost:")
    );
    assert_eq!(
        lifecycle.signature(),
        "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
    );

    let list = signer.sign(
        &base(
            Request::new("GET", "/")
                .with_query("max-keys", "2")
                .with_query("prefix", "J"),
        ),
        EMPTY_SHA256,
    );
    assert!(
        list.canonical_request()
            .starts_with("GET\n/\nmax-keys=2&prefix=J\nhost:")
    );
    assert_eq!(
        list.string_to_sign().lines().last(),
        Some("df57d21db20da04d7fa30298dd4488ba3a2b47ca3a489c74750e0f1e7df1b9b7")
    );
    assert_eq!(
        list.signature(),
        "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"
    );
}

#[test]
fn the_s3_presigned_url_example_signs_as_documented() {
    let credentials = example_credentials();
    let signer = Signer::new(&credentials, "us-east-1", "s3", example_time());
    let mut request =
        Request::new("GET", "/test.txt").with_header("Host", "examplebucket.s3.amazonaws.com");
    let signature = signer.presign(&mut request, 86_400);
    assert_eq!(
        signature.canonical_request(),
        "GET\n/test.txt\nX-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host\nhost:examplebucket.s3.amazonaws.com\n\nhost\nUNSIGNED-PAYLOAD"
    );
    assert_eq!(
        signature.string_to_sign().lines().last(),
        Some("3bfa292879f6447bbcda7001decf97f4a54dc650c8942174ae0a9121cf58ad04")
    );
    assert_eq!(
        signature.signature(),
        "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    );
    assert_eq!(
        request.target(),
        "/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"
    );
}

/// The chunk header lines of an encoded body, in order.
fn chunk_lines(body: &[u8]) -> Vec<String> {
    let decoded = aws_chunked::decode(body).expect("decodes");
    decoded
        .chunks()
        .iter()
        .map(|c| {
            format!(
                "{:x};chunk-signature={}",
                c.range().len(),
                c.signature().unwrap_or("")
            )
        })
        .collect()
}

#[test]
fn the_s3_signed_streaming_example_signs_every_chunk_as_documented() {
    let credentials = example_credentials();
    let signer = Signer::new(&credentials, "us-east-1", "s3", example_time());
    let data = vec![b'a'; 66_560];
    let request = Request::new("PUT", "/examplebucket/chunkObject.txt")
        .with_header("Host", "s3.amazonaws.com")
        .with_header("x-amz-date", "20130524T000000Z")
        .with_header("x-amz-storage-class", "REDUCED_REDUNDANCY")
        .with_header("x-amz-content-sha256", STREAMING_SIGNED)
        .with_header("Content-Encoding", "aws-chunked")
        .with_header("x-amz-decoded-content-length", "66560")
        .with_header("Content-Length", "66824");
    let seed = signer.sign(&request, STREAMING_SIGNED);
    assert_eq!(
        seed.string_to_sign().lines().last(),
        Some("cee3fed04b70f867d036f722359b0b1f2f0e5dc0efadbc082b76c4c60e316455")
    );
    assert_eq!(
        seed.signature(),
        "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9"
    );

    let chunk_size = NonZeroUsize::new(65_536).expect("non-zero");
    let body = aws_chunked::encode(
        &data,
        chunk_size,
        &[],
        Some(&mut signer.chunk_signer(&seed)),
    );
    assert_eq!(body.len(), 66_824, "the documented Content-Length");
    assert_eq!(
        chunk_lines(&body),
        [
            "10000;chunk-signature=ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
            "400;chunk-signature=0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
            "0;chunk-signature=b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
        ]
    );
    let decoded = aws_chunked::decode(&body).expect("decodes");
    assert_eq!(decoded.data(), data);
    assert!(decoded.signatures_match(&mut signer.chunk_signer(&seed)));
}

#[test]
fn the_s3_trailer_example_signs_the_chunks_and_the_trailer_as_documented() {
    let credentials = example_credentials();
    let signer = Signer::new(&credentials, "us-east-1", "s3", example_time());
    let data = vec![b'a'; 66_560];
    // The guide's canonical request signs these seven headers and not
    // Content-Length, although its request also sends Content-Length.
    let request = Request::new("PUT", "/examplebucket/chunkObject.txt")
        .with_header("Host", "s3.amazonaws.com")
        .with_header("x-amz-date", "20130524T000000Z")
        .with_header("x-amz-storage-class", "REDUCED_REDUNDANCY")
        .with_header("x-amz-content-sha256", STREAMING_SIGNED_TRAILER)
        .with_header("Content-Encoding", "aws-chunked")
        .with_header("x-amz-decoded-content-length", "66560")
        .with_header("x-amz-trailer", "x-amz-checksum-crc32c");
    let seed = signer.sign(&request, STREAMING_SIGNED_TRAILER);
    assert_eq!(
        seed.string_to_sign().lines().last(),
        Some("44d48b8c2f70eae815a0198cc73d7a546a73a93359c070abbaa5e6c7de112559")
    );
    assert_eq!(
        seed.signature(),
        "106e2a8a18243abcf37539882f36619c00e2dfc72633413f02d3b74544bfeb8e"
    );

    let trailers = [("x-amz-checksum-crc32c".to_owned(), "sOO8/Q==".to_owned())];
    let chunk_size = NonZeroUsize::new(65_536).expect("non-zero");
    let body = aws_chunked::encode(
        &data,
        chunk_size,
        &trailers,
        Some(&mut signer.chunk_signer(&seed)),
    );
    assert_eq!(body.len(), 66_946, "the documented Content-Length");
    assert_eq!(
        chunk_lines(&body),
        [
            "10000;chunk-signature=b474d8862b1487a5145d686f57f013e54db672cee1c953b3010fb58501ef5aa2",
            "400;chunk-signature=1c1344b170168f8e65b41376b44b20fe354e373826ccbbe2c1d40a8cae51e5c7",
            "0;chunk-signature=2ca2aba2005185cf7159c6277faf83795951dd77a3a99e6e65d5c9f85863f992",
        ]
    );
    assert!(body.ends_with(
        b"x-amz-checksum-crc32c:sOO8/Q==\r\nx-amz-trailer-signature:d81f82fc3505edab99d459891051a732e8730629a2e4a59689829ca17fe2e435\r\n\r\n"
    ));
    let decoded = aws_chunked::decode(&body).expect("decodes");
    assert_eq!(decoded.trailers(), trailers);
    assert!(decoded.signatures_match(&mut signer.chunk_signer(&seed)));
}

#[test]
fn query_parameters_sort_by_key_before_value() {
    // `a-b=1` sorts before `a=2` as a string, but key `a` sorts before `a-b`.
    let credentials = example_credentials();
    let signer = Signer::new(&credentials, "us-east-1", "s3", example_time());
    let request = Request::new("GET", "/")
        .with_query("a-b", "1")
        .with_query("a", "2")
        .with_query("a", "1");
    let signature = signer.sign(&request.with_header("Host", "h"), EMPTY_SHA256);
    assert!(
        signature
            .canonical_request()
            .starts_with("GET\n/\na=1&a=2&a-b=1\n")
    );
}
