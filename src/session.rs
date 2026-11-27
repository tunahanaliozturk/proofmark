//! Sending signed S3 requests for one run: [`Remote`] signs and sends, and
//! [`Session`] adds the ledger, the run's bucket and key prefix, and the
//! record of each probe's exchanges.
//!
//! Every `PUT` and `POST` that goes through a [`Session`] is written to the
//! ledger before it is sent ([ADR 0004](../docs/adr/0004-only-touch-what-it-wrote.md)).
//! A probe cannot write around it.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, PoisonError};

use crate::checksum::{base64, sha256_hex};
use crate::http::{Client, Endpoint, HttpError, Request, Response};
use crate::ledger::{Entry, Ledger};
use crate::rng::SplitMix64;
use crate::s3;
use crate::sigv4::{Credentials, REDACTED, Signer, encode_component, is_secret_name};
use crate::time::UtcTime;

/// One S3 request before it is signed: method, bucket, key, query,
/// headers and body. `host`, `content-length` and the SigV4 headers are
/// added when it is sent.
#[derive(Debug, Clone)]
pub struct Call {
    method: &'static str,
    bucket: String,
    key: Option<String>,
    query: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    wrong_secret: bool,
}

impl Call {
    /// A request to `bucket`, or to `key` in it.
    #[must_use]
    pub fn new(method: &'static str, bucket: &str, key: Option<&str>) -> Self {
        Self {
            method,
            bucket: bucket.to_owned(),
            key: key.map(str::to_owned),
            query: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
            wrong_secret: false,
        }
    }

    /// The same request with a query parameter, unencoded.
    #[must_use]
    pub fn query(mut self, key: &str, value: &str) -> Self {
        self.query.push((key.to_owned(), value.to_owned()));
        self
    }

    /// The same request with one more header.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    /// The same request with `body`.
    #[must_use]
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// The same request, signed with a secret key that is not the right
    /// one, for probing that a store checks signatures.
    #[must_use]
    pub fn signed_with_wrong_secret(mut self) -> Self {
        self.wrong_secret = true;
        self
    }

    fn is_write(&self) -> bool {
        matches!(self.method, "PUT" | "POST")
    }

    fn ledger_entry(&self) -> Entry {
        match &self.key {
            Some(key) => Entry::put_object(&self.bucket, key),
            None => Entry::create_bucket(&self.bucket),
        }
    }
}

/// Every secret a run has used, in each form a store could echo it in:
/// as is, percent-encoded, and base64-encoded, alone or inside a longer
/// base64 text. Clones share one list, so whoever writes output last can
/// scrub it of every secret known by then, signatures included.
#[derive(Clone, Default)]
pub struct Secrets(Arc<Mutex<Vec<String>>>);

impl fmt::Debug for Secrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secrets { .. }")
    }
}

/// Shorter encoded forms are not added: they would match ordinary text.
const MIN_ENCODED: usize = 8;

impl Secrets {
    /// The access key id, the secret key and the session token.
    #[must_use]
    pub fn of(credentials: &Credentials) -> Self {
        let secrets = Self::default();
        secrets.add_credentials(credentials);
        secrets
    }

    fn add_credentials(&self, credentials: &Credentials) {
        self.add(credentials.access_key_id());
        self.add(credentials.secret_access_key());
        if let Some(token) = credentials.session_token() {
            self.add(token);
        }
    }

    /// Adds `secret` and its encoded forms. An empty one is ignored.
    pub fn add(&self, secret: &str) {
        if secret.is_empty() {
            return;
        }
        let bytes = secret.as_bytes();
        let mut forms = vec![secret.to_owned(), encode_component(bytes)];
        // Inside a longer base64 text the secret starts at byte 0, 1 or 2
        // of a 3-byte group. The characters before its first whole sextet
        // and after its last one also carry bits of its neighbours; the
        // ones between depend on the secret alone, whatever surrounds it.
        for skip in 0..3 {
            let mut shifted = vec![0_u8; skip];
            shifted.extend_from_slice(bytes);
            let encoded = base64(&shifted);
            let (start, end) = ((skip * 4).div_ceil(3), shifted.len() * 4 / 3);
            forms.extend(encoded.get(start..end).map(str::to_owned));
        }
        forms.push(base64(bytes));
        let mut list = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        for form in forms {
            let long_enough = form == secret || form.len() >= MIN_ENCODED;
            if long_enough && !list.contains(&form) {
                list.push(form);
            }
        }
        // The longest first, so that a form is not cut up by a shorter one
        // that occurs inside it.
        list.sort_by_key(|form| std::cmp::Reverse(form.len()));
    }

    /// `text` with every form of every secret replaced.
    #[must_use]
    pub fn scrub(&self, text: &str) -> String {
        let list = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let mut text = text.to_owned();
        for form in list.iter() {
            if text.contains(form.as_str()) {
                text = text.replace(form.as_str(), REDACTED);
            }
        }
        text
    }
}

/// Signs and sends requests to one endpoint, and remembers every secret it
/// used so that output can be scrubbed of them.
pub struct Remote {
    client: Client,
    endpoint: Endpoint,
    credentials: Credentials,
    region: String,
    clock_offset: i64,
    log: Option<Box<dyn Write + Send>>,
    secrets: Secrets,
}

impl fmt::Debug for Remote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Remote")
            .field("endpoint", &self.endpoint)
            .field("credentials", &self.credentials)
            .field("region", &self.region)
            .field("clock_offset", &self.clock_offset)
            .field("logging", &self.log.is_some())
            .finish_non_exhaustive()
    }
}

impl Remote {
    /// A remote for `endpoint`, signing with `credentials` in `region`.
    #[must_use]
    pub fn new(client: Client, endpoint: Endpoint, credentials: Credentials, region: &str) -> Self {
        let secrets = Secrets::of(&credentials);
        Self {
            client,
            endpoint,
            credentials,
            region: region.to_owned(),
            clock_offset: 0,
            log: None,
            secrets,
        }
    }

    /// The same remote, keeping its secrets in `secrets`, a list shared
    /// with whoever writes the run's output.
    #[must_use]
    pub fn with_secrets(mut self, secrets: Secrets) -> Self {
        secrets.add_credentials(&self.credentials);
        self.secrets = secrets;
        self
    }

    /// The same remote, writing every exchange to `log` with secrets
    /// redacted.
    #[must_use]
    pub fn with_log(mut self, log: Box<dyn Write + Send>) -> Self {
        self.log = Some(log);
        self
    }

    /// Signs with the server's clock from now on: `offset` seconds are
    /// added to the local time.
    pub fn set_clock_offset(&mut self, offset: i64) {
        self.clock_offset = offset;
    }

    /// The endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The signing region.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// `text` with every secret this remote has used replaced, in each of
    /// its forms: the access key id, the secret key, the session token, and
    /// every signature it has sent.
    #[must_use]
    pub fn scrub(&self, text: &str) -> String {
        self.secrets.scrub(text)
    }

    /// Signs `call` and sends it.
    ///
    /// # Errors
    ///
    /// [`HttpError`] when there is no response.
    pub fn send(&mut self, call: &Call) -> Result<(Request, Response), HttpError> {
        let mut request = Request::new(call.method, &s3::path(&call.bucket, call.key.as_deref()))
            .with_header("host", &self.endpoint.authority());
        for (key, value) in &call.query {
            request.push_query(key, value);
        }
        if !call.body.is_empty() || call.is_write() {
            request.push_header("content-length", &call.body.len().to_string());
        }
        for (name, value) in &call.headers {
            request.push_header(name, value);
        }
        let mut request = request.with_body(call.body.clone());
        let time = UtcTime::from_unix(UtcTime::now().unix().saturating_add(self.clock_offset));
        let wrong;
        let credentials = if call.wrong_secret {
            let key = Credentials::new(
                self.credentials.access_key_id(),
                &format!("{}-wrong", self.credentials.secret_access_key()),
            );
            // Only the secret is wrong: the token stays, so that a store
            // using temporary credentials judges the signature.
            wrong = match self.credentials.session_token() {
                Some(token) => key.with_session_token(token),
                None => key,
            };
            &wrong
        } else {
            &self.credentials
        };
        let signature = Signer::new(credentials, &self.region, "s3", time)
            .sign_request(&mut request, &sha256_hex(&call.body));
        self.secrets.add(signature.signature());
        self.log_request(&request);
        let response = self.client.send(&self.endpoint, &request);
        match &response {
            Ok(response) => self.log_response(response),
            Err(e) => self.log_line(&format!("< error: {e}")),
        }
        Ok((request, response?))
    }

    fn log_line(&mut self, line: &str) {
        let line = self.scrub(line);
        if let Some(log) = &mut self.log {
            // A log that cannot be written to is not a reason to stop.
            let _ = writeln!(log, "{line}");
        }
    }

    fn log_headers(&mut self, prefix: &str, headers: &[(String, String)]) {
        for (name, value) in headers {
            let shown = if is_secret_name(name) {
                REDACTED
            } else {
                value
            };
            self.log_line(&format!("{prefix} {name}: {shown}"));
        }
    }

    fn log_request(&mut self, request: &Request) {
        if self.log.is_none() {
            return;
        }
        self.log_line(&format!(
            "> {} {} ({} body bytes)",
            request.method(),
            request.redacted_target(),
            request.body().len()
        ));
        self.log_headers(">", request.headers());
    }

    fn log_response(&mut self, response: &Response) {
        if self.log.is_none() {
            return;
        }
        self.log_line(&format!(
            "< {} ({} body bytes)",
            response.status(),
            response.body().len()
        ));
        self.log_headers("<", response.headers());
    }
}

/// One request a probe sent and the response it got.
#[derive(Debug, Clone)]
pub struct Exchange {
    /// The probe's name for this step, such as `put` or `get`.
    pub label: &'static str,
    /// The request as sent. Its `Debug` output hides the signature.
    pub request: Request,
    /// The response.
    pub response: Response,
}

/// Why a probe could not finish.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProbeError {
    /// An exchange failed with no response.
    Http(HttpError),
    /// The ledger could not be written, so the write was not sent. The run
    /// stops here.
    Ledger(io::Error),
    /// A `DELETE`, or a `PUT` over a key whose earlier write failed, aimed
    /// at something this run has not created. It was not sent.
    NotWritten(String),
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(e) => write!(f, "{e}"),
            Self::Ledger(e) => write!(f, "could not write the ledger: {e}"),
            Self::NotWritten(what) => write!(
                f,
                "not sent: {what} was not created by this run, and proofmark only deletes or overwrites what it created"
            ),
        }
    }
}

impl std::error::Error for ProbeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Http(e) => Some(e),
            Self::Ledger(e) => Some(e),
            Self::NotWritten(_) => None,
        }
    }
}

impl From<HttpError> for ProbeError {
    fn from(e: HttpError) -> Self {
        Self::Http(e)
    }
}

/// One run's connection to the store: the remote, the ledger, the bucket
/// probes work in, and what the current probe has sent.
#[derive(Debug)]
pub struct Session {
    remote: Remote,
    ledger: Ledger,
    run_id: String,
    bucket: String,
    prefix: String,
    rng: SplitMix64,
    probe: &'static str,
    exchanges: Vec<Exchange>,
    /// Keys this run has sent a write to, and those a write created.
    attempted: HashSet<(String, String)>,
    created: HashSet<(String, String)>,
}

impl Session {
    /// A session working in `bucket`, with every key under `prefix`.
    #[must_use]
    pub fn new(
        remote: Remote,
        ledger: Ledger,
        run_id: &str,
        bucket: &str,
        prefix: &str,
        seed: u64,
    ) -> Self {
        Self {
            remote,
            ledger,
            run_id: run_id.to_owned(),
            bucket: bucket.to_owned(),
            prefix: prefix.to_owned(),
            rng: SplitMix64::new(seed),
            probe: "",
            exchanges: Vec::new(),
            attempted: HashSet::new(),
            created: HashSet::new(),
        }
    }

    /// Starts recording for the probe `id`.
    pub fn begin(&mut self, id: &'static str) {
        self.probe = id;
        self.exchanges.clear();
    }

    /// The exchanges since [`Session::begin`].
    #[must_use]
    pub fn take_exchanges(&mut self) -> Vec<Exchange> {
        std::mem::take(&mut self.exchanges)
    }

    /// The bucket probes work in.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// A bucket name that this run never creates, for probing what a
    /// missing bucket gets.
    #[must_use]
    pub fn absent_bucket(&self) -> String {
        format!("proofmark-{}-absent", self.run_id)
    }

    /// A key for the current probe: `<prefix><probe id>/<name>`.
    #[must_use]
    pub fn key(&self, name: &str) -> String {
        format!("{}{}/{name}", self.prefix, self.probe)
    }

    /// `len` bytes from the run's seeded source.
    pub fn payload(&mut self, len: usize) -> Vec<u8> {
        self.rng.bytes(len)
    }

    /// The remote, for scrubbing output.
    #[must_use]
    pub fn remote(&self) -> &Remote {
        &self.remote
    }

    /// Gives back the remote and the ledger.
    #[must_use]
    pub fn into_parts(self) -> (Remote, Ledger) {
        (self.remote, self.ledger)
    }

    /// Sends `call`, recording it under `label`. A write is announced in
    /// the ledger first and its outcome recorded after.
    ///
    /// A `DELETE` is sent only for a key a write of this run created, and a
    /// write only to a key that is new or that this run created: a key
    /// whose earlier write failed may hold someone else's data.
    ///
    /// # Errors
    ///
    /// [`ProbeError::NotWritten`] for a `DELETE` or write that breaks that
    /// rule; [`ProbeError::Ledger`] if the ledger cannot be written; in
    /// both cases nothing was sent. [`ProbeError::Http`] if there was no
    /// response.
    pub fn send(&mut self, label: &'static str, call: &Call) -> Result<&Response, ProbeError> {
        let target = (call.bucket.clone(), call.key.clone().unwrap_or_default());
        let allowed = match (call.method, &call.key) {
            ("DELETE", None) => false,
            ("DELETE", Some(_)) => self.created.contains(&target),
            (_, Some(_)) if call.is_write() => {
                !self.attempted.contains(&target) || self.created.contains(&target)
            }
            _ => true,
        };
        if !allowed {
            return Err(ProbeError::NotWritten(format!(
                "{} {}/{}",
                call.method, target.0, target.1
            )));
        }
        let intent = call.is_write().then(|| call.ledger_entry());
        if let Some(intent) = &intent {
            self.ledger.record(intent).map_err(ProbeError::Ledger)?;
            self.attempted.insert(target.clone());
        }
        let (request, response) = self.remote.send(call)?;
        if intent.is_some() && (200..300).contains(&response.status()) {
            self.created.insert(target);
        }
        if let Some(intent) = &intent {
            // Kept exactly as sent: cleanup sends it back. The ledger is a
            // record of what to delete, not output to scrub.
            let version = response.header("x-amz-version-id").map(str::to_owned);
            self.ledger
                .record(&intent.outcome(response.status(), version.as_deref()))
                .map_err(ProbeError::Ledger)?;
        }
        if call.method == "DELETE"
            && let Some(key) = &call.key
        {
            // So that cleanup does not delete the key again, perhaps after
            // someone else has written it.
            self.ledger
                .record(&Entry::delete_object(&call.bucket, key).outcome(response.status(), None))
                .map_err(ProbeError::Ledger)?;
        }
        self.exchanges.push(Exchange {
            label,
            request,
            response,
        });
        Ok(&self.exchanges[self.exchanges.len() - 1].response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_replaces_the_secret_key_and_the_session_token_anywhere() {
        let credentials = Credentials::new("AKID", "s3cr3t/key").with_session_token("tok-123");
        let remote = Remote::new(
            Client::new(),
            Endpoint::parse("http://127.0.0.1:9").expect("endpoint"),
            credentials,
            "us-east-1",
        );
        assert_eq!(
            remote.scrub(
                "<CanonicalRequest>x-amz-security-token:tok-123</CanonicalRequest> s3cr3t/key AKID"
            ),
            "<CanonicalRequest>x-amz-security-token:<redacted></CanonicalRequest> <redacted> <redacted>"
        );
        assert!(!format!("{remote:?}").contains("s3cr3t"));
        assert!(!format!("{remote:?}").contains("tok-123"));
    }

    /// A store can echo a secret the way it received it or encoded: in a
    /// query string, in a header, inside base64 such as a `Basic`
    /// credential. Every one of those forms is scrubbed.
    #[test]
    fn scrub_covers_the_access_key_id_and_encoded_forms_of_each_secret() {
        use crate::checksum::base64;
        let (id, secret, token) = ("AKIDEXAMPLE7Q2", "s3cr3t/key+abc=", "tok/en+123456789");
        let remote = Remote::new(
            Client::new(),
            Endpoint::parse("http://127.0.0.1:9").expect("endpoint"),
            Credentials::new(id, secret).with_session_token(token),
            "us-east-1",
        );
        for leak in [
            id.to_owned(),
            "s3cr3t%2Fkey%2Babc%3D".to_owned(),
            "tok%2Fen%2B123456789".to_owned(),
            base64(secret.as_bytes()),
            base64(token.as_bytes()),
            base64(id.as_bytes()),
        ] {
            let scrubbed = remote.scrub(&format!("echo: {leak}."));
            assert!(!scrubbed.contains(&leak), "{leak} survived: {scrubbed}");
        }
        // Inside a longer base64 text the secret can sit at any offset.
        for prefix in ["", "u:", "us:", "use:"] {
            let leak = base64(format!("{prefix}{secret}").as_bytes());
            let scrubbed = remote.scrub(&leak);
            assert!(scrubbed.contains(REDACTED), "{prefix:?}: {leak} survived");
        }
        assert_eq!(remote.scrub("nothing secret here"), "nothing secret here");
    }

    /// A one-shot server on loopback that answers the first request with
    /// `response`.
    fn answer_once(response: String) -> Endpoint {
        use std::io::Read;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut seen = Vec::new();
            let mut buf = [0_u8; 4096];
            while let Ok(n @ 1..) = stream.read(&mut buf) {
                seen.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&seen);
                if let Some(end) = text.find("\r\n\r\n") {
                    let length = text[..end]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if seen.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let _ = stream.write_all(response.as_bytes());
        });
        Endpoint::parse(&format!("http://127.0.0.1:{port}")).expect("endpoint")
    }

    /// A version id is what cleanup sends back to delete that version, so
    /// the ledger keeps it exactly, even when it happens to contain text
    /// that equals a secret.
    #[test]
    fn the_ledger_keeps_a_version_id_exactly_as_the_store_sent_it() {
        let endpoint = answer_once(
            "HTTP/1.1 200 OK\r\nx-amz-version-id: abc\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                .to_owned(),
        );
        let remote = Remote::new(
            Client::new(),
            endpoint.clone(),
            Credentials::new("AKID", "a"),
            "us-east-1",
        );
        let dir = std::env::temp_dir().join(format!("proofmark-session-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("version.jsonl");
        let _ = std::fs::remove_file(&path);
        let header = crate::ledger::Header {
            run_id: "abc123".to_owned(),
            endpoint: endpoint.to_string(),
            region: "us-east-1".to_owned(),
        };
        let ledger = Ledger::create(&path, &header).expect("ledger");
        let mut session = Session::new(remote, ledger, "abc123", "b", "proofmark-abc123/", 1);
        session.begin("t");
        let put = Call::new("PUT", "b", Some("proofmark-abc123/t/k"));
        assert_eq!(session.send("put", &put).expect("put").status(), 200);
        drop(session);
        let (_, entries) = crate::ledger::read(&path).expect("read");
        assert_eq!(entries[1].version_id.as_deref(), Some("abc"));
    }

    /// ADR 0004: a probe never deletes a key, or writes over one, unless
    /// this run's own write created it.
    #[test]
    fn a_probe_cannot_delete_or_overwrite_a_key_it_did_not_create() {
        let server =
            crate::fake::FakeServer::start(crate::fake::FakeConfig::new()).expect("fake starts");
        let remote = Remote::new(
            Client::new(),
            server.endpoint(),
            crate::fake::credentials(),
            crate::fake::DEFAULT_REGION,
        );
        let dir = std::env::temp_dir().join(format!("proofmark-session-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("guard.jsonl");
        let _ = std::fs::remove_file(&path);
        let header = crate::ledger::Header {
            run_id: "abc123".to_owned(),
            endpoint: server.endpoint().to_string(),
            region: crate::fake::DEFAULT_REGION.to_owned(),
        };
        let ledger = Ledger::create(&path, &header).expect("ledger");
        let mut session = Session::new(remote, ledger, "abc123", "b", "proofmark-abc123/", 1);
        session.begin("t");
        let made = session.send("bucket", &Call::new("PUT", "b", None));
        assert_eq!(made.expect("bucket").status(), 200);

        let refused =
            |r: Result<&Response, ProbeError>| matches!(r, Err(ProbeError::NotWritten(_)));
        let never = Call::new("DELETE", "b", Some("proofmark-abc123/t/never"));
        assert!(refused(session.send("delete", &never)));
        assert!(refused(
            session.send("bucket", &Call::new("DELETE", "b", None))
        ));

        // A write that was refused did not create the key: no second try.
        let key = Some("proofmark-abc123/t/refused");
        let bad = Call::new("PUT", "b", key).signed_with_wrong_secret();
        assert_eq!(session.send("put", &bad).expect("put").status(), 403);
        assert!(refused(session.send("put", &Call::new("PUT", "b", key))));
        assert!(refused(
            session.send("delete", &Call::new("DELETE", "b", key))
        ));

        let key = Some("proofmark-abc123/t/mine");
        assert_eq!(
            session
                .send("put", &Call::new("PUT", "b", key))
                .expect("put")
                .status(),
            200
        );
        assert_eq!(
            session
                .send("put", &Call::new("PUT", "b", key))
                .expect("put")
                .status(),
            200
        );
        let delete = Call::new("DELETE", "b", key);
        assert_eq!(
            session.send("delete", &delete).expect("delete").status(),
            204
        );
        assert_eq!(
            session.send("delete", &delete).expect("delete").status(),
            204
        );
    }

    /// The wrong-secret request keeps the session token: without it a store
    /// that uses temporary credentials may refuse the request for the
    /// missing token before it ever looks at the signature.
    #[test]
    fn a_request_signed_with_the_wrong_secret_keeps_the_session_token() {
        let server =
            crate::fake::FakeServer::start(crate::fake::FakeConfig::new()).expect("fake starts");
        let mut remote = Remote::new(
            Client::new(),
            server.endpoint(),
            crate::fake::credentials().with_session_token("tok-123"),
            crate::fake::DEFAULT_REGION,
        );
        let call = Call::new("PUT", "b", Some("k")).signed_with_wrong_secret();
        let (request, _) = remote.send(&call).expect("answered");
        assert_eq!(request.header("x-amz-security-token"), Some("tok-123"));
    }

    /// The scrub would hide a leak here too, so the name redaction of the
    /// verbose log is checked on its own, with values the scrub does not know.
    #[test]
    fn the_log_redacts_secret_headers_by_name() {
        #[derive(Clone, Default)]
        struct Shared(Arc<Mutex<Vec<u8>>>);
        impl Write for Shared {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let log = Shared::default();
        let mut remote = Remote::new(
            Client::new(),
            Endpoint::parse("http://127.0.0.1:9").expect("endpoint"),
            Credentials::new("AKID", "secret"),
            "us-east-1",
        )
        .with_log(Box::new(log.clone()));
        remote.log_headers(
            ">",
            &[
                (
                    "Authorization".to_owned(),
                    "Signature=unknown-sig".to_owned(),
                ),
                (
                    "x-amz-security-token".to_owned(),
                    "unknown-token".to_owned(),
                ),
                ("content-length".to_owned(), "5".to_owned()),
            ],
        );
        let written = String::from_utf8_lossy(&log.0.lock().expect("log")).into_owned();
        assert_eq!(
            written,
            "> Authorization: <redacted>\n> x-amz-security-token: <redacted>\n> content-length: 5\n"
        );
    }
}
