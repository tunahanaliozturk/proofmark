//! The mutation test (ADR 0005): every probe passes against the correct
//! fake, and against each fault it declares it reports the status and the
//! silence it should. Runs in process, through the same `run::execute`
//! the binary uses, on 127.0.0.1 with a port the system picks.
#![cfg(test)]

use std::path::PathBuf;
use std::time::Duration;

use proofmark::fake::{self, FakeConfig, FakeServer};
use proofmark::probe::{self, Basis, Probe, Status};
use proofmark::report::Report;
use proofmark::run::{self, BucketMode, RunConfig};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("proofmark-probes-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

fn run_against(server: &FakeServer, probes: Vec<&'static Probe>, ledger: PathBuf) -> Report {
    let config = RunConfig {
        endpoint: server.endpoint(),
        region: server.region().to_owned(),
        credentials: fake::credentials(),
        probes,
        selection: (Vec::new(), Vec::new()),
        bucket: BucketMode::Own,
        ledger: Some(ledger),
        ca_pem: None,
        timeout: Duration::from_secs(10),
        seed: 20_261_125,
        run_id: "mutest".to_owned(),
        fail_on: Status::ALL[1..].to_vec(),
    };
    run::execute(&config, None).expect("the run starts")
}

#[test]
fn every_basic_probe_passes_on_the_correct_fake_and_cleans_up() {
    let server = FakeServer::start(FakeConfig::new()).expect("fake starts");
    let dir = temp_dir("correct");
    let report = run_against(
        &server,
        probe::all().iter().collect(),
        dir.join("ledger.jsonl"),
    );
    let failed: Vec<String> = report
        .results
        .iter()
        .filter(|r| r.status != Status::Pass)
        .map(|r| format!("{}: {} {}", r.id, r.status, r.detail))
        .collect();
    assert!(failed.is_empty(), "failed on the correct fake: {failed:#?}");
    assert_eq!(report.results.len(), 14);
    assert!(report.cleanup.complete(), "{:?}", report.cleanup.left);
    assert!(
        server.snapshot().is_empty(),
        "left behind: {:?}",
        server.snapshot()
    );
    assert!(
        !dir.join("ledger.jsonl").exists(),
        "a complete cleanup removes the ledger"
    );
    assert_eq!(report.exit_code(), 0);
}

#[test]
fn every_basic_probe_reports_each_of_its_faults() {
    let dir = temp_dir("faults");
    let mut wrong = Vec::new();
    let mut checked = 0;
    for probe in probe::all() {
        for catch in probe.catches {
            let server =
                FakeServer::start(FakeConfig::new().with_fault(catch.fault)).expect("fake starts");
            let ledger = dir.join(format!("{}-{}.jsonl", probe.id, catch.fault));
            let report = run_against(&server, vec![probe], ledger);
            let result = &report.results[0];
            let want = match probe.expectation.basis {
                Basis::Documented => Status::Violation,
                Basis::Observed => Status::Difference,
            };
            if (result.status, result.silent) != (want, catch.silent) {
                wrong.push(format!(
                    "{} with {}: got {} silent={} ({}), want {want} silent={}",
                    probe.id,
                    catch.fault,
                    result.status,
                    result.silent,
                    result.detail,
                    catch.silent
                ));
            }
            assert!(report.cleanup.complete(), "{:?}", report.cleanup.left);
            checked += 1;
        }
    }
    assert!(
        wrong.is_empty(),
        "probes that missed their fault: {wrong:#?}"
    );
    assert_eq!(checked, 15, "one run per declared fault");
}

#[test]
fn a_taken_bucket_name_is_refused_before_anything_is_written() {
    use proofmark::http::{Client, Request};
    use proofmark::session::{Call, Remote};
    use std::sync::{Arc, Mutex, PoisonError};

    let methods: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen = Arc::clone(&methods);
    let server = FakeServer::start(FakeConfig::new().with_request_hook(Arc::new(
        move |_, request: &Request| {
            seen.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(request.method().to_owned());
        },
    )))
    .expect("fake starts");
    let mut someone = Remote::new(
        Client::new(),
        server.endpoint(),
        fake::credentials(),
        fake::DEFAULT_REGION,
    );
    // The name this run would pick, already someone's.
    let (_, made) = someone
        .send(&Call::new("PUT", "proofmark-mutest-main", None))
        .expect("create");
    assert_eq!(made.status(), 200);
    methods
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();

    let dir = temp_dir("taken");
    let config = RunConfig {
        endpoint: server.endpoint(),
        region: server.region().to_owned(),
        credentials: fake::credentials(),
        probes: probe::all().iter().collect(),
        selection: (Vec::new(), Vec::new()),
        bucket: BucketMode::Own,
        ledger: Some(dir.join("ledger.jsonl")),
        ca_pem: None,
        timeout: Duration::from_secs(10),
        seed: 1,
        run_id: "mutest".to_owned(),
        fail_on: Status::ALL[1..].to_vec(),
    };
    let refusal = run::execute(&config, None).expect_err("refused");
    assert_eq!(refusal.code, 3, "{refusal}");
    let methods = methods
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert_eq!(
        methods,
        vec!["GET", "HEAD"],
        "preflight and the name check only"
    );
    assert!(server.snapshot().contains_key("proofmark-mutest-main"));
    assert!(!dir.join("ledger.jsonl").exists());
}
