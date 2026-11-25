//! Sending signed S3 requests for one run: [`Remote`] signs and sends, and
//! [`Session`] adds the ledger, the run's bucket and key prefix, and the
//! record of each probe's exchanges.
//!
//! Every `PUT` and `POST` that goes through a [`Session`] is written to the
//! ledger before it is sent ([ADR 0004](../docs/adr/0004-only-touch-what-it-wrote.md)).
//! A probe cannot write around it.

use std::fmt;
use std::io::{self, Write};

use crate::checksum::sha256_hex;
use crate::http::{Client, Endpoint, HttpError, Request, Response};
use crate::ledger::{Entry, Ledger};
use crate::rng::SplitMix64;
use crate::s3;
use crate::sigv4::{Credentials, REDACTED, Signer, is_secret_name};
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

/// Signs and sends requests to one endpoint, and remembers every secret it
/// used so that output can be scrubbed of them.
pub struct Remote {
    client: Client,
    endpoint: Endpoint,
    credentials: Credentials,
    region: String,
    clock_offset: i64,
    log: Option<Box<dyn Write + Send>>,
    secrets: Vec<String>,
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
        let mut secrets = vec![credentials.secret_access_key().to_owned()];
        secrets.extend(credentials.session_token().map(str::to_owned));
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

    /// `text` with every secret this remote has used replaced: the secret
    /// key, the session token, and every signature it has sent.
    #[must_use]
    pub fn scrub(&self, text: &str) -> String {
        let mut text = text.to_owned();
        for secret in self.secrets.iter().filter(|s| !s.is_empty()) {
            if text.contains(secret.as_str()) {
                text = text.replace(secret.as_str(), REDACTED);
            }
        }
        text
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
            wrong = Credentials::new(
                self.credentials.access_key_id(),
                &format!("{}-wrong", self.credentials.secret_access_key()),
            );
            &wrong
        } else {
            &self.credentials
        };
        let signature = Signer::new(credentials, &self.region, "s3", time)
            .sign_request(&mut request, &sha256_hex(&call.body));
        self.secrets.push(signature.signature().to_owned());
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
}

impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(e) => write!(f, "{e}"),
            Self::Ledger(e) => write!(f, "could not write the ledger: {e}"),
        }
    }
}

impl std::error::Error for ProbeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Http(e) => Some(e),
            Self::Ledger(e) => Some(e),
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
    /// # Errors
    ///
    /// [`ProbeError::Ledger`] if the ledger cannot be written, in which
    /// case nothing was sent; [`ProbeError::Http`] if there was no
    /// response.
    pub fn send(&mut self, label: &'static str, call: &Call) -> Result<&Response, ProbeError> {
        let intent = call.is_write().then(|| call.ledger_entry());
        if let Some(intent) = &intent {
            self.ledger.record(intent).map_err(ProbeError::Ledger)?;
        }
        let (request, response) = self.remote.send(call)?;
        if let Some(intent) = &intent {
            let version = response
                .header("x-amz-version-id")
                .map(|v| self.remote.scrub(v));
            self.ledger
                .record(&intent.outcome(response.status(), version.as_deref()))
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
