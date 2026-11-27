//! The command line: parsing by hand, the commands, and their exit codes.
//!
//! | Code | Meaning |
//! | --- | --- |
//! | 0 | every probe ended with a status not in `--fail-on`, and cleanup finished |
//! | 1 | a probe ended with a status in `--fail-on` |
//! | 2 | usage error |
//! | 3 | safety refusal; nothing was written |
//! | 4 | could not start |
//! | 5 | cleanup left something; the ledger is kept |

use std::ffi::OsString;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::fake::{self, FakeConfig, FakeServer, Fault};
use crate::http::Endpoint;
use crate::probe::{self, Probe, Status};
use crate::rng::SplitMix64;
use crate::run::{self, BucketMode, RunConfig};
use crate::safety::{self, Cleanup};
use crate::session::Secrets;
use crate::sigv4::Credentials;

const HELP: &str = "\
proofmark: probes an S3-compatible endpoint and reports, feature by feature,
whether it behaves the way S3 clients expect.

Usage:
  proofmark run      --endpoint URL [options]      run probes against an endpoint
  proofmark list     [--feature F]                 show the probes, no network
  proofmark explain  PROBE                         one probe in full
  proofmark cleanup  --endpoint URL --ledger FILE [--bucket NAME]
                                                   remove what an interrupted run left;
                                                   --bucket names the existing bucket it used
  proofmark fake     [--listen ADDR] [--fault F]   run the fake S3 server on loopback

run options:
  --endpoint URL            http:// or https://, with port (required)
  --region NAME             signing region (default us-east-1)
  --probe ID                run this probe; repeatable
  --feature NAME            run this feature's probes; repeatable
  --bucket NAME             with --use-existing-bucket: work in this empty bucket
  --use-existing-bucket     instead of creating a bucket
  --ledger PATH             where the write ledger goes
                            (default ./proofmark-ledger-<run id>.jsonl)
  --report FORMAT=PATH      also write json, junit or markdown; repeatable
  --fail-on LIST            statuses that make the exit code 1
                            (default violation,difference,unsupported,inconclusive)
  --ca-file PATH            extra trusted CA certificates, PEM
  --timeout SECONDS         per request (default 30)
  --seed N                  seed for payloads (default random)
  --verbose                 print every exchange to stderr, secrets redacted

Credentials come from AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and, if set,
AWS_SESSION_TOKEN. There is no option to skip TLS verification.

Exit codes: 0 all good, 1 a probe failed, 2 usage, 3 safety refusal,
4 could not start, 5 cleanup incomplete.
";

/// A usage error: a message, and exit code 2.
struct Usage(String);

fn usage(message: impl Into<String>) -> Usage {
    Usage(message.into())
}

/// The arguments after the command, as `--name value`, `--name=value`, or
/// plain words.
struct Args {
    rest: std::vec::IntoIter<String>,
}

enum Arg {
    Option(String, Option<String>),
    Word(String),
}

impl Args {
    fn next_arg(&mut self) -> Option<Arg> {
        let arg = self.rest.next()?;
        Some(match arg.strip_prefix("--") {
            Some(option) => match option.split_once('=') {
                Some((name, value)) => Arg::Option(name.to_owned(), Some(value.to_owned())),
                None => Arg::Option(option.to_owned(), None),
            },
            None => Arg::Word(arg),
        })
    }

    fn value(&mut self, name: &str, inline: Option<String>) -> Result<String, Usage> {
        inline
            .or_else(|| self.rest.next())
            .ok_or_else(|| usage(format!("--{name} needs a value")))
    }
}

/// Runs the command line `args` (without the program name), writing normal
/// output to `out` and errors to `err`, and returns the exit code.
///
/// Output is held until the command ends and then scrubbed of every secret
/// the command used, in each form a store could echo it in, as the last
/// step before it is written. The credentials in the environment are known
/// from the start, so even a usage error that repeats an argument is
/// scrubbed. `fake` writes as it goes, because it serves until stopped; it
/// prints only its own published key pair.
pub fn main(args: Vec<OsString>, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let args: Result<Vec<String>, _> = args.into_iter().map(OsString::into_string).collect();
    let secrets = Secrets::default();
    for name in [
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ] {
        if let Ok(value) = std::env::var(name) {
            secrets.add(&value);
        }
    }
    let serving = matches!(&args, Ok(args) if args.first().is_some_and(|c| c == "fake"));
    let (mut held_out, mut held_err) = (Vec::new(), Vec::new());
    let code = {
        let (out, err): (&mut dyn Write, &mut dyn Write) = if serving {
            (&mut *out, &mut *err)
        } else {
            (&mut held_out, &mut held_err)
        };
        let result = match args {
            Err(_) => Err(usage("arguments must be valid UTF-8")),
            Ok(args) => dispatch(args, out, err, &secrets),
        };
        match result {
            Ok(code) => code,
            Err(Usage(message)) => {
                let _ = writeln!(err, "proofmark: {message}\nRun `proofmark help` for usage.");
                2
            }
        }
    };
    let _ = emit(out, &secrets, &held_out);
    let _ = emit(err, &secrets, &held_err);
    code
}

/// Writes `held`, scrubbed of `secrets`, to `stream`.
fn emit(stream: &mut dyn Write, secrets: &Secrets, held: &[u8]) -> io::Result<()> {
    if held.is_empty() {
        return Ok(());
    }
    stream.write_all(secrets.scrub(&String::from_utf8_lossy(held)).as_bytes())?;
    stream.flush()
}

fn dispatch(
    args: Vec<String>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    secrets: &Secrets,
) -> Result<u8, Usage> {
    let mut args = args.into_iter();
    let command = args.next();
    let mut rest = Args { rest: args };
    match command.as_deref() {
        None => Err(usage("no command given")),
        Some("help" | "--help" | "-h") => {
            let _ = out.write_all(HELP.as_bytes());
            Ok(0)
        }
        Some("--version" | "-V") => {
            let _ = writeln!(out, "proofmark {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        Some("run") => run_command(&mut rest, out, err, secrets),
        Some("list") => list(&mut rest, out),
        Some("explain") => explain(&mut rest, out),
        Some("cleanup") => cleanup(&mut rest, out, err, secrets),
        Some("fake") => serve_fake(&mut rest, out, err),
        Some(other) => Err(usage(format!("unknown command {other:?}"))),
    }
}

fn credentials() -> Result<Credentials, Usage> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let (Some(id), Some(secret)) = (var("AWS_ACCESS_KEY_ID"), var("AWS_SECRET_ACCESS_KEY")) else {
        return Err(usage(
            "set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in the environment",
        ));
    };
    let credentials = Credentials::new(&id, &secret);
    Ok(match var("AWS_SESSION_TOKEN") {
        Some(token) => credentials.with_session_token(&token),
        None => credentials,
    })
}

fn read_ca(path: Option<String>) -> Result<Option<Vec<u8>>, Usage> {
    path.map(|path| std::fs::read(&path).map_err(|e| usage(format!("--ca-file {path}: {e}"))))
        .transpose()
}

fn parse_timeout(value: Option<String>) -> Result<Duration, Usage> {
    match value {
        None => Ok(Duration::from_secs(30)),
        Some(text) => match text.parse::<u64>() {
            Ok(seconds) if seconds > 0 => Ok(Duration::from_secs(seconds)),
            _ => Err(usage(format!(
                "--timeout {text:?} is not a whole number of seconds above 0"
            ))),
        },
    }
}

/// A random source for the run id and the default seed. Neither is a
/// secret; they only need to differ between runs.
fn fresh_rng() -> SplitMix64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let low = u64::try_from(nanos & u128::from(u64::MAX)).unwrap_or(0);
    SplitMix64::new(low ^ (u64::from(std::process::id()) << 32))
}

fn select(ids: &[String], features: &[String]) -> Result<Vec<&'static Probe>, Usage> {
    for id in ids {
        if probe::find(id).is_none() {
            return Err(usage(format!(
                "unknown probe {id:?}; `proofmark list` shows them"
            )));
        }
    }
    let known = probe::features();
    for feature in features {
        if !known.contains(&feature.as_str()) {
            return Err(usage(format!(
                "unknown feature {feature:?}; the features are {}",
                known.join(", ")
            )));
        }
    }
    let everything = ids.is_empty() && features.is_empty();
    Ok(probe::all()
        .iter()
        .filter(|p| {
            everything || ids.iter().any(|id| id == p.id) || features.iter().any(|f| f == p.feature)
        })
        .collect())
}

#[derive(Debug, Clone, Copy)]
enum Format {
    Json,
    Junit,
    Markdown,
}

struct RunOptions {
    config: RunConfig,
    reports: Vec<(Format, PathBuf)>,
    verbose: bool,
}

fn parse_run(args: &mut Args) -> Result<Result<RunOptions, String>, Usage> {
    let (mut endpoint, mut region, mut bucket, mut ledger) = (None, None, None, None);
    let (mut ca_file, mut timeout, mut seed, mut fail_on) = (None, None, None, None);
    let (mut ids, mut features, mut reports) = (Vec::new(), Vec::new(), Vec::new());
    let (mut existing, mut verbose) = (false, false);
    while let Some(arg) = args.next_arg() {
        let Arg::Option(name, inline) = arg else {
            return Err(usage("run takes options only"));
        };
        match name.as_str() {
            "use-existing-bucket" => existing = true,
            "verbose" => verbose = true,
            "endpoint" => endpoint = Some(args.value(&name, inline)?),
            "region" => region = Some(args.value(&name, inline)?),
            "probe" => ids.push(args.value(&name, inline)?),
            "feature" => features.push(args.value(&name, inline)?),
            "bucket" => bucket = Some(args.value(&name, inline)?),
            "ledger" => ledger = Some(PathBuf::from(args.value(&name, inline)?)),
            "report" => reports.push(args.value(&name, inline)?),
            "fail-on" => fail_on = Some(args.value(&name, inline)?),
            "ca-file" => ca_file = Some(args.value(&name, inline)?),
            "timeout" => timeout = Some(args.value(&name, inline)?),
            "seed" => seed = Some(args.value(&name, inline)?),
            other => return Err(usage(format!("unknown option --{other} for run"))),
        }
    }
    let endpoint = Endpoint::parse(&endpoint.ok_or_else(|| usage("run needs --endpoint"))?)
        .map_err(|e| usage(e.to_string()))?;
    let probes = select(&ids, &features)?;
    let fail_on = match fail_on {
        None => Status::ALL[1..].to_vec(),
        Some(list) => list
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                Status::from_name(s.trim())
                    .ok_or_else(|| usage(format!("unknown status {s:?} in --fail-on")))
            })
            .collect::<Result<_, _>>()?,
    };
    let reports = reports
        .iter()
        .map(|spec| {
            let (format, path) = spec
                .split_once('=')
                .ok_or_else(|| usage(format!("--report {spec:?} must be FORMAT=PATH")))?;
            let format = match format {
                "json" => Format::Json,
                "junit" => Format::Junit,
                "markdown" => Format::Markdown,
                other => return Err(usage(format!("unknown report format {other:?}"))),
            };
            Ok((format, PathBuf::from(path)))
        })
        .collect::<Result<_, _>>()?;
    let mut rng = fresh_rng();
    let seed = match seed {
        None => rng.next_u64(),
        Some(text) => text
            .parse()
            .map_err(|_| usage(format!("--seed {text:?} is not a number")))?,
    };
    let bucket = match (bucket, existing) {
        (None, false) => BucketMode::Own,
        (Some(name), true) => BucketMode::Existing(name),
        (None, true) => return Err(usage("--use-existing-bucket needs --bucket NAME")),
        (Some(name), false) => {
            // A safety refusal, not a usage error: proofmark never works
            // in a named bucket unless told twice.
            return Ok(Err(format!(
                "--bucket {name} was given without --use-existing-bucket; proofmark creates its own buckets unless both are given, and then only works in an empty bucket"
            )));
        }
    };
    let config = RunConfig {
        endpoint,
        region: region.unwrap_or_else(|| fake::DEFAULT_REGION.to_owned()),
        credentials: credentials()?,
        probes,
        selection: (ids, features),
        bucket,
        ledger,
        ca_pem: read_ca(ca_file)?,
        timeout: parse_timeout(timeout)?,
        seed,
        run_id: safety::run_id(&mut rng),
        fail_on,
    };
    Ok(Ok(RunOptions {
        config,
        reports,
        verbose,
    }))
}

fn run_command(
    args: &mut Args,
    out: &mut dyn Write,
    err: &mut dyn Write,
    secrets: &Secrets,
) -> Result<u8, Usage> {
    let options = match parse_run(args)? {
        Ok(options) => options,
        Err(refusal) => {
            let _ = writeln!(err, "proofmark: {refusal}");
            return Ok(3);
        }
    };
    let log: Option<Box<dyn Write + Send>> = options
        .verbose
        .then(|| Box::new(io::stderr()) as Box<dyn Write + Send>);
    let report = match run::execute(&options.config, log, secrets) {
        Ok(report) => report,
        Err(refusal) => {
            let _ = writeln!(err, "proofmark: {refusal}");
            return Ok(refusal.code);
        }
    };
    let _ = out.write_all(report.terminal().as_bytes());
    for (format, path) in &options.reports {
        let text = match format {
            Format::Json => report.json(),
            Format::Junit => report.junit(),
            Format::Markdown => report.markdown(),
        };
        if let Err(e) = std::fs::write(path, secrets.scrub(&text)) {
            let _ = writeln!(err, "proofmark: could not write {}: {e}", path.display());
        }
    }
    Ok(report.exit_code())
}

fn list(args: &mut Args, out: &mut dyn Write) -> Result<u8, Usage> {
    let mut features = Vec::new();
    while let Some(arg) = args.next_arg() {
        match arg {
            Arg::Option(name, inline) if name == "feature" => {
                features.push(args.value(&name, inline)?);
            }
            Arg::Option(name, _) => return Err(usage(format!("unknown option --{name} for list"))),
            Arg::Word(word) => return Err(usage(format!("unexpected {word:?}"))),
        }
    }
    let probes = select(&[], &features)?;
    let width = probes.iter().map(|p| p.id.len()).max().unwrap_or(0);
    let _ = writeln!(
        out,
        "{:width$}  {:8}  {:10}  expectation",
        "id", "feature", "basis"
    );
    for p in probes {
        let _ = writeln!(
            out,
            "{:width$}  {:8}  {:10}  {}",
            p.id,
            p.feature,
            p.expectation.basis.as_str(),
            p.expectation.statement
        );
    }
    Ok(0)
}

fn explain(args: &mut Args, out: &mut dyn Write) -> Result<u8, Usage> {
    let Some(Arg::Word(id)) = args.next_arg() else {
        return Err(usage("explain needs a probe id"));
    };
    if args.next_arg().is_some() {
        return Err(usage("explain takes one probe id"));
    }
    let probe = probe::find(&id).ok_or_else(|| usage(format!("unknown probe {id:?}")))?;
    let e = probe.expectation;
    let catches: Vec<String> = probe
        .catches
        .iter()
        .map(|c| {
            if c.silent {
                format!("{} (reported as silent)", c.fault)
            } else {
                c.fault.to_string()
            }
        })
        .collect();
    let _ = write!(
        out,
        "{}  (feature: {})\n\nRequests:\n  {}\n\nExpected: {}\nBasis: {}. {}, section \"{}\" (read {})\n\nCatches: {}\n",
        probe.id,
        probe.feature,
        probe.requests,
        e.statement,
        e.basis.as_str(),
        e.citation.url,
        e.citation.section,
        e.citation.read,
        catches.join(", ")
    );
    Ok(0)
}

fn cleanup(
    args: &mut Args,
    out: &mut dyn Write,
    err: &mut dyn Write,
    secrets: &Secrets,
) -> Result<u8, Usage> {
    let (mut endpoint, mut ledger, mut region, mut ca_file, mut timeout, mut bucket) =
        (None, None, None, None, None, None);
    while let Some(arg) = args.next_arg() {
        let Arg::Option(name, inline) = arg else {
            return Err(usage("cleanup takes options only"));
        };
        match name.as_str() {
            "endpoint" => endpoint = Some(args.value(&name, inline)?),
            "ledger" => ledger = Some(PathBuf::from(args.value(&name, inline)?)),
            "region" => region = Some(args.value(&name, inline)?),
            "ca-file" => ca_file = Some(args.value(&name, inline)?),
            "timeout" => timeout = Some(args.value(&name, inline)?),
            "bucket" => bucket = Some(args.value(&name, inline)?),
            other => return Err(usage(format!("unknown option --{other} for cleanup"))),
        }
    }
    let endpoint = Endpoint::parse(&endpoint.ok_or_else(|| usage("cleanup needs --endpoint"))?)
        .map_err(|e| usage(e.to_string()))?;
    let ledger = ledger.ok_or_else(|| usage("cleanup needs --ledger"))?;
    let result = run::cleanup_command(
        &endpoint,
        region.as_deref(),
        &credentials()?,
        &ledger,
        bucket.as_deref(),
        read_ca(ca_file)?.as_deref(),
        parse_timeout(timeout)?,
        secrets,
    );
    let done: Cleanup = match result {
        Ok(done) => done,
        Err(refusal) => {
            let _ = writeln!(err, "proofmark: {refusal}");
            return Ok(refusal.code);
        }
    };
    let _ = writeln!(
        out,
        "cleanup: {} bucket(s), {} object(s) removed",
        done.buckets_removed, done.objects_removed
    );
    if done.complete() {
        let _ = writeln!(out, "nothing left; the ledger is removed");
        Ok(0)
    } else {
        for left in &done.left {
            let _ = writeln!(out, "  left: {left}");
        }
        let _ = writeln!(out, "the ledger is kept at {}", ledger.display());
        Ok(5)
    }
}

fn serve_fake(args: &mut Args, out: &mut dyn Write, err: &mut dyn Write) -> Result<u8, Usage> {
    let mut listen = "127.0.0.1:9000".to_owned();
    let mut config = FakeConfig::new();
    while let Some(arg) = args.next_arg() {
        let Arg::Option(name, inline) = arg else {
            return Err(usage("fake takes options only"));
        };
        match name.as_str() {
            "listen" => listen = args.value(&name, inline)?,
            "region" => config = config.with_region(&args.value(&name, inline)?),
            "fault" => {
                let value = args.value(&name, inline)?;
                let fault = Fault::from_name(&value).ok_or_else(|| {
                    let names: Vec<&str> = Fault::all().map(Fault::name).collect();
                    usage(format!(
                        "unknown fault {value:?}; the faults are {}",
                        names.join(", ")
                    ))
                })?;
                config = config.with_fault(fault);
            }
            other => return Err(usage(format!("unknown option --{other} for fake"))),
        }
    }
    let addr: SocketAddr = listen
        .parse()
        .map_err(|_| usage(format!("--listen {listen:?} is not an IP address and port")))?;
    let server = match FakeServer::bind(addr, config) {
        Ok(server) => server,
        Err(e) if e.kind() == io::ErrorKind::InvalidInput => return Err(usage(e.to_string())),
        Err(e) => {
            let _ = writeln!(err, "proofmark: could not listen on {addr}: {e}");
            return Ok(4);
        }
    };
    let _ = writeln!(
        out,
        "proofmark fake listening on {} (region {})\nThis fake accepts one published test key pair:\n  AWS_ACCESS_KEY_ID={}\n  AWS_SECRET_ACCESS_KEY={}\nStop it with Ctrl-C.",
        server.endpoint(),
        server.region(),
        fake::ACCESS_KEY_ID,
        fake::SECRET_ACCESS_KEY
    );
    let _ = out.flush();
    loop {
        std::thread::park();
    }
}
