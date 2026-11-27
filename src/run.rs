//! One run from start to finish: preflight, safety set-up, the probes,
//! cleanup and the report. The design's "data flow of a run", steps 2 to 6.

use std::fmt::{self, Write as _};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::http::{Client, Endpoint, HttpError, Scheme, tls_config_native};
use crate::ledger::{self, Header, Ledger};
use crate::probe::{self, Judgement, Probe, Status};
use crate::report::{ExchangeSummary, ProbeResult, Report};
use crate::s3;
use crate::safety::{self, Cleanup, Emptiness};
use crate::session::{Call, Exchange, ProbeError, Remote, Secrets, Session};
use crate::sigv4::Credentials;
use crate::time::UtcTime;

/// SigV4 requests fail when the clocks differ by more than this.
const MAX_SKEW_SECONDS: i64 = 15 * 60;

/// Where the probes work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketMode {
    /// Create `proofmark-<run id>-main`, work under `proofmark-<run id>/`
    /// in it, and delete it afterwards.
    Own,
    /// Work under `proofmark-<run id>/` in this bucket, which must be empty.
    Existing(String),
}

/// Everything a run needs, validated.
#[derive(Debug, Clone)]
pub struct RunConfig {
    /// The endpoint.
    pub endpoint: Endpoint,
    /// The signing region.
    pub region: String,
    /// The credentials.
    pub credentials: Credentials,
    /// The probes to run, in order.
    pub probes: Vec<&'static Probe>,
    /// What was asked for: probe ids and features, both empty for all.
    pub selection: (Vec<String>, Vec<String>),
    /// Own bucket or an existing one.
    pub bucket: BucketMode,
    /// Where the ledger goes; `proofmark-ledger-<run id>.jsonl` if `None`.
    pub ledger: Option<PathBuf>,
    /// Extra trusted CA certificates, PEM.
    pub ca_pem: Option<Vec<u8>>,
    /// The deadline for each exchange.
    pub timeout: Duration,
    /// The seed for payloads.
    pub seed: u64,
    /// The run id.
    pub run_id: String,
    /// Statuses that make the exit code 1.
    pub fail_on: Vec<Status>,
}

/// A run that stopped before the probes, with its exit code: 3 for a
/// safety refusal, 4 when it could not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The exit code.
    pub code: u8,
    /// What happened, for the user.
    pub message: String,
}

impl Refusal {
    fn safety(message: String) -> Self {
        Self { code: 3, message }
    }

    fn start(message: String) -> Self {
        Self { code: 4, message }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

/// The client for `endpoint`: TLS from the system's roots plus `ca_pem`.
///
/// # Errors
///
/// [`Refusal`] with code 4 if the TLS configuration cannot be built.
pub fn client(
    endpoint: &Endpoint,
    ca_pem: Option<&[u8]>,
    timeout: Duration,
) -> Result<Client, Refusal> {
    let client = Client::new().with_timeout(timeout);
    if endpoint.scheme() == Scheme::Http {
        return Ok(client);
    }
    let tls = tls_config_native(ca_pem).map_err(|e| Refusal::start(e.to_string()))?;
    Ok(client.with_tls(tls))
}

fn status_text(response: &crate::http::Response) -> String {
    match s3::error_code(response.body()) {
        Some(code) => format!("{} {code}", response.status()),
        None => response.status().to_string(),
    }
}

/// Parses an HTTP date, `Fri, 24 May 2013 00:00:00 GMT`.
fn parse_http_date(text: &str) -> Option<UtcTime> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let parts: Vec<&str> = text.split_whitespace().collect();
    let [_, day, month, year, time, "GMT"] = parts.as_slice() else {
        return None;
    };
    let month = MONTHS.iter().position(|m| m == month)? + 1;
    let time = time.replace(':', "");
    UtcTime::parse_amz(&format!("{year}{month:02}{day:0>2}T{time}Z"))
}

/// Sends one signed request that proves the endpoint is reachable and the
/// credentials work, and sets the clock offset from the server's `Date`.
fn preflight(remote: &mut Remote, mode: &BucketMode) -> Result<(), Refusal> {
    let call = match mode {
        BucketMode::Own => Call::new("GET", "", None),
        BucketMode::Existing(bucket) => Call::new("HEAD", bucket, None),
    };
    let what = match mode {
        BucketMode::Own => "ListBuckets".to_owned(),
        BucketMode::Existing(bucket) => format!("HeadBucket on {bucket}"),
    };
    let sent_at = UtcTime::now();
    let (_, response) = remote
        .send(&call)
        .map_err(|e| Refusal::start(format!("could not reach {}: {e}", remote.endpoint())))?;
    if response.status() != 200 {
        let status = status_text(&response);
        let hint = match s3::error_code(response.body()).as_deref() {
            Some("RequestTimeTooSkewed") => "; this machine's clock is too far from the server's",
            Some("AuthorizationHeaderMalformed") => "; the region may be wrong (--region)",
            Some("InvalidAccessKeyId" | "SignatureDoesNotMatch") => {
                "; check AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
            }
            _ if response.status() == 404 => "; the bucket does not exist",
            _ => "",
        };
        return Err(Refusal::start(format!(
            "the preflight {what} answered {status}{hint}"
        )));
    }
    if let Some(server) = response.header("date").and_then(parse_http_date) {
        let offset = server.unix() - sent_at.unix();
        if offset.abs() > MAX_SKEW_SECONDS {
            return Err(Refusal::start(format!(
                "the server's clock differs from this machine's by {offset} seconds, more than SigV4 allows"
            )));
        }
        remote.set_clock_offset(offset);
    }
    Ok(())
}

fn summary(exchange: &Exchange, remote: &Remote) -> ExchangeSummary {
    ExchangeSummary {
        label: exchange.label.to_owned(),
        method: exchange.request.method().to_owned(),
        target: remote.scrub(&exchange.request.redacted_target()),
        status: exchange.response.status(),
        request_id: exchange
            .response
            .header("x-amz-request-id")
            .map(|id| remote.scrub(id)),
    }
}

fn result_of(
    probe: &Probe,
    judgement: &Judgement,
    exchanges: &[Exchange],
    remote: &Remote,
) -> ProbeResult {
    let (detail, silent) = match judgement {
        Judgement::Matches => (String::new(), false),
        Judgement::Deviates { detail, silent } => (detail.clone(), *silent),
        Judgement::Unsupported { detail } => (detail.clone(), false),
        Judgement::Inconclusive { reason } => (reason.clone(), false),
    };
    ProbeResult {
        id: probe.id.to_owned(),
        feature: probe.feature.to_owned(),
        status: Status::of(judgement, probe.expectation.basis),
        silent,
        expectation: probe.expectation,
        detail: remote.scrub(&detail),
        exchanges: exchanges.iter().map(|e| summary(e, remote)).collect(),
    }
}

/// Runs every probe in order. A ledger that cannot be written stops the
/// run: no further write may be sent, and the probes not run are
/// inconclusive.
fn run_probes(session: &mut Session, probes: &[&'static Probe]) -> Vec<ProbeResult> {
    let mut results = Vec::new();
    let mut stopped = None;
    for probe in probes {
        if let Some(why) = &stopped {
            let judgement = Judgement::Inconclusive {
                reason: format!("not run: {why}"),
            };
            results.push(result_of(probe, &judgement, &[], session.remote()));
            continue;
        }
        session.begin(probe.id);
        let outcome = (probe.run)(session);
        let exchanges = session.take_exchanges();
        let judgement = match outcome {
            Ok(()) => probe::judge(probe, &exchanges),
            Err(e) => {
                if matches!(e, ProbeError::Ledger(_)) {
                    stopped = Some(e.to_string());
                }
                Judgement::Inconclusive {
                    reason: e.to_string(),
                }
            }
        };
        results.push(result_of(probe, &judgement, &exchanges, session.remote()));
    }
    results
}

/// Cleans up from the ledger file, turning a ledger that cannot be read
/// into a leftover so the run reports it and exits 5.
fn clean(remote: &mut Remote, path: &Path, bucket: Option<&str>) -> Cleanup {
    safety::cleanup(remote, path, bucket).unwrap_or_else(|e| Cleanup {
        left: vec![format!("{e}; nothing was deleted")],
        ..Cleanup::default()
    })
}

/// The bucket the probes will use, its key prefix, and whether this run
/// must create it. Reads only: a taken name or a bucket that is not empty
/// is refused before anything is written.
fn choose_bucket(
    remote: &mut Remote,
    config: &RunConfig,
) -> Result<(String, String, bool), Refusal> {
    Ok(match &config.bucket {
        BucketMode::Own => {
            let name = safety::bucket_name(&config.run_id, "main").map_err(Refusal::start)?;
            let (_, response) = remote
                .send(&Call::new("HEAD", &name, None))
                .map_err(|e| Refusal::start(e.to_string()))?;
            if response.status() != 404 {
                return Err(Refusal::safety(format!(
                    "the bucket name {name} is taken: HeadBucket answered {}",
                    response.status()
                )));
            }
            (name, safety::key_prefix(&config.run_id), true)
        }
        BucketMode::Existing(name) => {
            match safety::check_empty(remote, name)
                .map_err(|e: HttpError| Refusal::start(e.to_string()))?
            {
                Emptiness::Empty => {}
                Emptiness::NotEmpty(why) | Emptiness::Unknown(why) => {
                    return Err(Refusal::safety(format!(
                        "refusing to work in {name}: {why}. proofmark only uses an existing bucket that it can show to be empty; without --use-existing-bucket it creates its own"
                    )));
                }
            }
            if let Some(why) = safety::check_unversioned(remote, name)
                .map_err(|e: HttpError| Refusal::start(e.to_string()))?
            {
                return Err(Refusal::safety(format!(
                    "refusing to work in {name}: {why}. Without --use-existing-bucket proofmark creates its own"
                )));
            }
            (name.clone(), safety::key_prefix(&config.run_id), false)
        }
    })
}

/// Runs `config` against the endpoint. `log`, if given, receives every
/// exchange with secrets redacted. Every secret the run uses, signatures
/// included, is added to `secrets`, for scrubbing the output.
///
/// # Errors
///
/// [`Refusal`] when the run stops before any probe: exit code 3 when the
/// safety rules refuse, 4 when it cannot start.
pub fn execute(
    config: &RunConfig,
    log: Option<Box<dyn Write + Send>>,
    secrets: &Secrets,
) -> Result<Report, Refusal> {
    let started = UtcTime::now();
    let client = client(&config.endpoint, config.ca_pem.as_deref(), config.timeout)?;
    let mut remote = Remote::new(
        client,
        config.endpoint.clone(),
        config.credentials.clone(),
        &config.region,
    )
    .with_secrets(secrets.clone());
    if let Some(log) = log {
        remote = remote.with_log(log);
    }
    preflight(&mut remote, &config.bucket)?;

    let (bucket, prefix, created) = choose_bucket(&mut remote, config)?;

    let ledger_path = config
        .ledger
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("proofmark-ledger-{}.jsonl", config.run_id)));
    let header = Header {
        run_id: config.run_id.clone(),
        endpoint: config.endpoint.to_string(),
        region: config.region.clone(),
    };
    let ledger = Ledger::create(&ledger_path, &header).map_err(|e| {
        Refusal::start(format!(
            "could not create the ledger {}: {e}",
            ledger_path.display()
        ))
    })?;
    let mut session = Session::new(
        remote,
        ledger,
        &config.run_id,
        &bucket,
        &prefix,
        config.seed,
    );

    if created {
        let made = session
            .send("create bucket", &Call::new("PUT", &bucket, None))
            .map(|r| (r.status(), status_text(r)));
        if !matches!(made, Ok((200, _))) {
            let (mut remote, ledger) = session.into_parts();
            drop(ledger);
            let cleanup = clean(&mut remote, &ledger_path, None);
            // 409 is BucketAlreadyExists or BucketAlreadyOwnedByYou: the
            // name is taken, which is a safety refusal.
            let code = if matches!(made, Ok((409, _))) { 3 } else { 4 };
            let why = match made {
                Ok((_, text)) => format!("CreateBucket answered {text}"),
                Err(e) => e.to_string(),
            };
            let mut message = format!("could not create {bucket}: {why}");
            if !cleanup.complete() {
                let _ = write!(
                    message,
                    "; the ledger {} is kept, run proofmark cleanup",
                    ledger_path.display()
                );
            }
            return Err(Refusal { code, message });
        }
    }

    let results = run_probes(&mut session, &config.probes);
    let (mut remote, ledger) = session.into_parts();
    // Closed before cleanup, which may remove it.
    drop(ledger);
    let existing = match &config.bucket {
        BucketMode::Own => None,
        BucketMode::Existing(name) => Some(name.as_str()),
    };
    let cleanup = clean(&mut remote, &ledger_path, existing);
    Ok(Report {
        endpoint: config.endpoint.to_string(),
        region: config.region.clone(),
        seed: config.seed,
        run_id: config.run_id.clone(),
        started,
        selection: config.selection.clone(),
        bucket: bucket.clone(),
        buckets_created: if created { vec![bucket] } else { Vec::new() },
        ledger: ledger_path.display().to_string(),
        results,
        cleanup,
        fail_on: config.fail_on.clone(),
    })
}

/// `proofmark cleanup`: deletes what the ledger at `path` records.
/// `bucket` is the existing bucket the run worked in, if it did. Every
/// secret it uses is added to `secrets`.
///
/// # Errors
///
/// [`Refusal`] with code 2 if the ledger cannot be read, names another
/// endpoint, or names anything proofmark would not have written; 4 if the
/// endpoint could not be reached at all.
#[expect(
    clippy::too_many_arguments,
    reason = "one parameter per option of the cleanup command, plus the shared secrets"
)]
pub fn cleanup_command(
    endpoint: &Endpoint,
    region: Option<&str>,
    credentials: &Credentials,
    path: &Path,
    bucket: Option<&str>,
    ca_pem: Option<&[u8]>,
    timeout: Duration,
    secrets: &Secrets,
) -> Result<Cleanup, Refusal> {
    let usage = |message: String| Refusal { code: 2, message };
    // Read here only for the signing region; cleanup reads it again, and
    // checks what it reads, before it deletes anything.
    let (header, _) = ledger::read(path).map_err(|e| usage(e.to_string()))?;
    let client = client(endpoint, ca_pem, timeout)?;
    let mut remote = Remote::new(
        client,
        endpoint.clone(),
        credentials.clone(),
        region.unwrap_or(&header.region),
    )
    .with_secrets(secrets.clone());
    let cleanup = safety::cleanup(&mut remote, path, bucket).map_err(|e| usage(e.to_string()))?;
    if !cleanup.complete() && cleanup.responses == 0 {
        return Err(Refusal::start(format!(
            "could not reach {endpoint}; nothing was deleted and the ledger is kept"
        )));
    }
    Ok(cleanup)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_http_date_the_fake_and_s3_send() {
        let time = UtcTime::from_unix(1_369_353_600);
        assert_eq!(parse_http_date(&time.http_date()), Some(time));
        assert_eq!(parse_http_date("Fri, 24 May 2013 00:00:00 GMT"), Some(time));
        assert_eq!(parse_http_date("Fri, 24 May 2013 00:00:00 UTC"), None);
        assert_eq!(parse_http_date("garbage"), None);
    }
}
