//! The real binary against the in-process fake: the safety rules of
//! ADR 0004, one test per exit code, and a search of every output for
//! planted secrets. Everything binds 127.0.0.1 on a port the system picks.
#![cfg(test)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use proofmark::fake::{self, FakeConfig, FakeServer, Fault, Snapshot};
use proofmark::http::{Client, Request};
use proofmark::session::{Call, Remote};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("proofmark-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// `proofmark` with the fake's credentials, working in `dir`.
fn proofmark(dir: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_proofmark"));
    command
        .current_dir(dir)
        .env("AWS_ACCESS_KEY_ID", fake::ACCESS_KEY_ID)
        .env("AWS_SECRET_ACCESS_KEY", fake::SECRET_ACCESS_KEY)
        .env_remove("AWS_SESSION_TOKEN")
        .stdin(Stdio::null());
    command
}

fn run(command: &mut Command) -> Output {
    command.output().expect("proofmark starts")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Exit code, with stdout and stderr in the message if it is not `want`.
fn assert_exit(output: &Output, want: i32) {
    assert_eq!(
        output.status.code(),
        Some(want),
        "stdout:\n{}\nstderr:\n{}",
        text(&output.stdout),
        text(&output.stderr)
    );
}

/// Another client writing to the fake: what proofmark must never touch.
fn foreign_put(endpoint: &proofmark::http::Endpoint, bucket: &str, key: Option<&str>) {
    let mut remote = Remote::new(
        Client::new(),
        endpoint.clone(),
        fake::credentials(),
        fake::DEFAULT_REGION,
    );
    let call = Call::new("PUT", bucket, key).body(if key.is_some() {
        b"someone else's data".to_vec()
    } else {
        Vec::new()
    });
    let (_, response) = remote.send(&call).expect("foreign write");
    assert_eq!(response.status(), 200);
}

/// Every request the fake receives: number, method, path.
type Seen = Arc<Mutex<Vec<(u64, String, String)>>>;

fn recording(config: FakeConfig) -> (FakeServer, Seen) {
    let seen: Seen = Arc::default();
    let for_hook = Arc::clone(&seen);
    let config = config.with_request_hook(Arc::new(move |n, request: &Request| {
        for_hook
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((n, request.method().to_owned(), request.path().to_owned()));
    }));
    (FakeServer::start(config).expect("fake starts"), seen)
}

fn writes(seen: &Seen) -> Vec<(u64, String, String)> {
    seen.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|(_, method, _)| matches!(method.as_str(), "PUT" | "POST" | "DELETE"))
        .cloned()
        .collect()
}

type Watch = Arc<dyn Fn(&Request) + Send + Sync>;

/// A fake that, when the `at`-th object `PUT` under a `proofmark-` name
/// arrives, first writes a foreign object into the same bucket, as another
/// client might in the middle of a run. `watch` sees every request.
fn interfering(at: u64, watch: Option<Watch>) -> FakeServer {
    let endpoint: Arc<Mutex<Option<proofmark::http::Endpoint>>> = Arc::default();
    let count = Arc::new(AtomicU64::new(0));
    let for_hook = Arc::clone(&endpoint);
    let config = FakeConfig::new().with_request_hook(Arc::new(move |_, request: &Request| {
        if let Some(watch) = &watch {
            watch(request);
        }
        let mut segments = request.path()[1..].splitn(2, '/');
        let (Some(bucket), Some(key)) = (segments.next(), segments.next()) else {
            return;
        };
        let ours = bucket.starts_with("proofmark-") || key.starts_with("proofmark-");
        if request.method() != "PUT" || !ours || key.is_empty() {
            return;
        }
        if count.fetch_add(1, Ordering::SeqCst) + 1 == at {
            let endpoint = for_hook
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
                .expect("endpoint set");
            foreign_put(&endpoint, bucket, Some("not-proofmark/foreign.txt"));
        }
    }));
    let server = FakeServer::start(config).expect("fake starts");
    *endpoint.lock().unwrap_or_else(PoisonError::into_inner) = Some(server.endpoint());
    server
}

// Exit codes, one test each.

#[test]
fn exit_0_when_every_probe_passes_and_cleanup_finishes() {
    let server = FakeServer::start(FakeConfig::new()).expect("fake starts");
    let dir = temp_dir("exit0");
    let output = run(proofmark(&dir).args(["run", "--endpoint", &server.endpoint().to_string()]));
    assert_exit(&output, 0);
    assert!(text(&output.stdout).contains("result: all 14 passed (exit 0)"));
    assert!(server.snapshot().is_empty(), "{:?}", server.snapshot());
}

#[test]
fn exit_1_when_a_probe_fails() {
    let server = FakeServer::start(FakeConfig::new().with_fault(Fault::IgnoreOverwrite))
        .expect("fake starts");
    let dir = temp_dir("exit1");
    let output = run(proofmark(&dir).args(["run", "--endpoint", &server.endpoint().to_string()]));
    assert_exit(&output, 1);
    assert!(text(&output.stdout).contains("violation    silent  basic.overwrite"));

    // The same failure is not counted when --fail-on leaves violations out.
    let output = run(proofmark(&dir).args([
        "run",
        "--endpoint",
        &server.endpoint().to_string(),
        "--fail-on",
        "inconclusive",
    ]));
    assert_exit(&output, 0);
}

#[test]
fn exit_2_on_a_usage_error() {
    let dir = temp_dir("exit2");
    let output =
        run(proofmark(&dir).args(["run", "--endpoint", "http://127.0.0.1:1", "--frobnicate"]));
    assert_exit(&output, 2);
    let output = run(proofmark(&dir).env_remove("AWS_SECRET_ACCESS_KEY").args([
        "run",
        "--endpoint",
        "http://127.0.0.1:1",
    ]));
    assert_exit(&output, 2);
    assert!(text(&output.stderr).contains("AWS_SECRET_ACCESS_KEY"));
    let output = run(proofmark(&dir).args([
        "run",
        "--endpoint",
        "http://127.0.0.1:1",
        "--probe",
        "basic.nope",
    ]));
    assert_exit(&output, 2);
    let output = run(proofmark(&dir).args(["explain", "basic.nope"]));
    assert_exit(&output, 2);
}

#[test]
fn exit_3_when_a_bucket_is_named_without_use_existing_bucket() {
    let (server, seen) = recording(FakeConfig::new());
    let dir = temp_dir("exit3");
    let output = run(proofmark(&dir).args([
        "run",
        "--endpoint",
        &server.endpoint().to_string(),
        "--bucket",
        "data",
    ]));
    assert_exit(&output, 3);
    assert!(
        seen.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty(),
        "sent nothing at all"
    );
}

#[test]
fn exit_4_when_the_endpoint_cannot_be_reached_or_refuses_the_credentials() {
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("addr").port()
    };
    let dir = temp_dir("exit4");
    let output = run(proofmark(&dir).args([
        "run",
        "--endpoint",
        &format!("http://127.0.0.1:{closed}"),
        "--timeout",
        "5",
    ]));
    assert_exit(&output, 4);

    let (server, seen) = recording(FakeConfig::new());
    let output = run(proofmark(&dir)
        .env("AWS_SECRET_ACCESS_KEY", "not-the-secret")
        .args(["run", "--endpoint", &server.endpoint().to_string()]));
    assert_exit(&output, 4);
    assert!(
        text(&output.stderr).contains("SignatureDoesNotMatch"),
        "{}",
        text(&output.stderr)
    );
    assert_eq!(writes(&seen), Vec::new());
    assert_eq!(
        std::fs::read_dir(&dir).expect("dir").count(),
        0,
        "no ledger"
    );
}

#[test]
fn exit_5_when_cleanup_leaves_something() {
    let server = interfering(3, None);
    let dir = temp_dir("exit5");
    let output = run(proofmark(&dir).args(["run", "--endpoint", &server.endpoint().to_string()]));
    assert_exit(&output, 5);
    assert!(
        text(&output.stdout).contains("BucketNotEmpty"),
        "{}",
        text(&output.stdout)
    );
}

// The safety rules.

#[test]
fn a_non_empty_existing_bucket_makes_run_exit_3_with_zero_writes() {
    let (server, seen) = recording(FakeConfig::new());
    foreign_put(&server.endpoint(), "data", None);
    foreign_put(&server.endpoint(), "data", Some("precious.txt"));
    let before = server.snapshot();
    let writes_before = writes(&seen).len();
    let dir = temp_dir("non-empty");
    let output = run(proofmark(&dir).args([
        "run",
        "--endpoint",
        &server.endpoint().to_string(),
        "--bucket",
        "data",
        "--use-existing-bucket",
    ]));
    assert_exit(&output, 3);
    assert!(
        text(&output.stderr).contains("not empty") || text(&output.stderr).contains("has object")
    );
    assert_eq!(writes(&seen).len(), writes_before, "proofmark sent a write");
    assert_eq!(server.snapshot(), before);
    assert_eq!(
        std::fs::read_dir(&dir).expect("dir").count(),
        0,
        "no ledger"
    );
}

#[test]
fn a_foreign_object_written_mid_run_survives_cleanup_of_an_own_bucket() {
    let server = interfering(5, None);
    let dir = temp_dir("foreign-own");
    let output = run(proofmark(&dir).args([
        "run",
        "--endpoint",
        &server.endpoint().to_string(),
        "--ledger",
        "ledger.jsonl",
    ]));
    // The bucket cannot be deleted with someone else's object in it, so
    // cleanup is incomplete, the ledger is kept, and the object survives.
    assert_exit(&output, 5);
    let snapshot = server.snapshot();
    let only: Vec<(&String, Vec<&String>)> = snapshot
        .iter()
        .map(|(bucket, objects)| (bucket, objects.keys().collect()))
        .collect();
    assert_eq!(only.len(), 1, "{snapshot:?}");
    assert_eq!(only[0].1, vec!["not-proofmark/foreign.txt"], "{snapshot:?}");
    assert!(dir.join("ledger.jsonl").exists());

    // A later cleanup still leaves it alone, and still says what is left.
    let output = run(proofmark(&dir).args([
        "cleanup",
        "--endpoint",
        &server.endpoint().to_string(),
        "--ledger",
        "ledger.jsonl",
    ]));
    assert_exit(&output, 5);
    assert_eq!(server.snapshot(), snapshot);
}

#[test]
fn a_foreign_object_written_mid_run_survives_cleanup_of_an_existing_bucket() {
    let server = interfering(4, None);
    foreign_put(&server.endpoint(), "shared", None);
    let dir = temp_dir("foreign-existing");
    let output = run(proofmark(&dir).args([
        "run",
        "--endpoint",
        &server.endpoint().to_string(),
        "--bucket",
        "shared",
        "--use-existing-bucket",
    ]));
    assert_exit(&output, 0);
    let snapshot = server.snapshot();
    let keys: Vec<&String> = snapshot["shared"].keys().collect();
    assert_eq!(keys, vec!["not-proofmark/foreign.txt"], "{snapshot:?}");
}

#[test]
fn cleanup_refuses_a_ledger_written_for_another_endpoint() {
    let dir = temp_dir("other-endpoint");
    std::fs::write(
        dir.join("ledger.jsonl"),
        "{\"proofmark_ledger\":1,\"run_id\":\"abcdef\",\"endpoint\":\"http://127.0.0.1:9\",\"region\":\"us-east-1\"}\n{\"op\":\"create_bucket\",\"bucket\":\"proofmark-abcdef-main\"}\n",
    )
    .expect("write ledger");
    let server = FakeServer::start(FakeConfig::new()).expect("fake starts");
    let output = run(proofmark(&dir).args([
        "cleanup",
        "--endpoint",
        &server.endpoint().to_string(),
        "--ledger",
        "ledger.jsonl",
    ]));
    assert_exit(&output, 2);
    assert!(dir.join("ledger.jsonl").exists());
}

/// Cleanup records each delete in the ledger it keeps. A key it removed
/// that someone writes again before the next cleanup is someone else's now,
/// and the next cleanup leaves it alone.
#[test]
fn a_second_cleanup_leaves_a_key_someone_wrote_after_the_first() {
    let server = interfering(5, None);
    let dir = temp_dir("replay");
    let endpoint = server.endpoint().to_string();
    let args = ["--endpoint", &endpoint, "--ledger", "ledger.jsonl"];
    let output = run(proofmark(&dir).arg("run").args(args));
    assert_exit(&output, 5);
    let ledger = std::fs::read_to_string(dir.join("ledger.jsonl")).expect("ledger kept");
    let put: serde_json::Value = ledger
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|v| v["op"] == "put_object" && v["status"] == 200)
        .expect("a recorded write");
    let (bucket, key) = (
        put["bucket"].as_str().expect("bucket"),
        put["key"].as_str().expect("key"),
    );
    assert!(
        !server.snapshot()[bucket].contains_key(key),
        "the run's cleanup removed {key}"
    );
    foreign_put(&server.endpoint(), bucket, Some(key));

    let output = run(proofmark(&dir).arg("cleanup").args(args));
    assert_exit(&output, 5);
    assert!(
        server.snapshot()[bucket].contains_key(key),
        "the second cleanup deleted {key}, written by someone else after the first"
    );
}

/// A ledger is trusted only where it names what proofmark itself writes:
/// buckets `proofmark-<run id>-*`, and keys under `proofmark-<run id>/` in
/// those or in the bucket given with `--bucket`. Anything else is refused
/// before a single request is sent.
#[test]
fn cleanup_refuses_a_ledger_that_names_data_proofmark_does_not_write() {
    let (server, seen) = recording(FakeConfig::new());
    foreign_put(&server.endpoint(), "customer-data", None);
    foreign_put(&server.endpoint(), "customer-data", Some("payroll.csv"));
    foreign_put(&server.endpoint(), "proofmark-abcdef-main", None);
    foreign_put(
        &server.endpoint(),
        "proofmark-abcdef-main",
        Some("payroll.csv"),
    );
    let before = server.snapshot();
    let sent_before = seen.lock().unwrap_or_else(PoisonError::into_inner).len();
    let endpoint = server.endpoint().to_string();
    let dir = temp_dir("foreign-ledger");
    let header = format!(
        "{{\"proofmark_ledger\":1,\"run_id\":\"abcdef\",\"endpoint\":\"{endpoint}\",\"region\":\"us-east-1\"}}\n"
    );
    for (entry, bucket) in [
        (
            r#"{"op":"put_object","bucket":"customer-data","key":"payroll.csv"}"#,
            None,
        ),
        (
            r#"{"op":"put_object","bucket":"customer-data","key":"payroll.csv"}"#,
            Some("customer-data"),
        ),
        (
            r#"{"op":"put_object","bucket":"customer-data","key":"proofmark-abcdef/x"}"#,
            None,
        ),
        (
            r#"{"op":"put_object","bucket":"proofmark-abcdef-main","key":"payroll.csv"}"#,
            None,
        ),
        (r#"{"op":"create_bucket","bucket":"customer-data"}"#, None),
        (
            r#"{"op":"create_bucket","bucket":"customer-data"}"#,
            Some("customer-data"),
        ),
    ] {
        std::fs::write(dir.join("ledger.jsonl"), format!("{header}{entry}\n")).expect("ledger");
        let mut command = proofmark(&dir);
        command.args([
            "cleanup",
            "--endpoint",
            &endpoint,
            "--ledger",
            "ledger.jsonl",
        ]);
        if let Some(bucket) = bucket {
            command.args(["--bucket", bucket]);
        }
        let output = run(&mut command);
        assert_exit(&output, 2);
        assert!(
            text(&output.stderr).contains("not proofmark's"),
            "{entry}: {}",
            text(&output.stderr)
        );
        assert!(dir.join("ledger.jsonl").exists());
    }
    assert_eq!(
        seen.lock().unwrap_or_else(PoisonError::into_inner).len(),
        sent_before,
        "cleanup sent a request"
    );
    assert_eq!(server.snapshot(), before);
}

/// Kills the child process at the moment the fake has received request
/// number `kill_at` (counted from the first request the run sends), before
/// the fake answers it. The fake then carries the request out anyway, so
/// the write happened and the run never learnt it did.
/// Returns the store before the run, the store after the run and cleanup,
/// whether the run was killed, and whether the run left anything in the
/// store for cleanup to remove.
fn run_killed_at(kill_at: u64, dir: &Path) -> (Snapshot, Snapshot, bool, bool) {
    let child: Arc<Mutex<Option<Child>>> = Arc::default();
    let base = Arc::new(AtomicU64::new(u64::MAX));
    let killed = Arc::new(AtomicU64::new(0));
    let (for_hook, base_hook, killed_hook) =
        (Arc::clone(&child), Arc::clone(&base), Arc::clone(&killed));
    let config = FakeConfig::new().with_request_hook(Arc::new(move |n, _: &Request| {
        let base = base_hook.load(Ordering::SeqCst);
        if base != u64::MAX && n == base + kill_at {
            let mut slot = for_hook.lock().unwrap_or_else(PoisonError::into_inner);
            // Marked before the kill and under the lock, so the test cannot
            // see the child gone without also seeing that it was killed.
            killed_hook.store(1, Ordering::SeqCst);
            if let Some(child) = slot.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }));
    let server = FakeServer::start(config).expect("fake starts");
    // Someone else's data, which must be there afterwards, unchanged.
    foreign_put(&server.endpoint(), "foreign", None);
    foreign_put(&server.endpoint(), "foreign", Some("keep.txt"));
    let before = server.snapshot();
    base.store(2, Ordering::SeqCst);

    // Held across the spawn, so the hook cannot look before the child is in.
    let mut slot = child.lock().unwrap_or_else(PoisonError::into_inner);
    let spawned = proofmark(dir)
        .args([
            "run",
            "--endpoint",
            &server.endpoint().to_string(),
            "--ledger",
            "ledger.jsonl",
            "--seed",
            "3",
        ])
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(dir.join("stderr.txt")).expect("stderr file"))
        .spawn()
        .expect("spawn");
    *slot = Some(spawned);
    drop(slot);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let done = child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
            .is_some_and(|c| c.try_wait().ok().flatten().is_some());
        if done {
            break;
        }
        assert!(Instant::now() < deadline, "the run did not end");
        thread::sleep(Duration::from_millis(2));
    }
    let was_killed = killed.load(Ordering::SeqCst) == 1;
    if !was_killed {
        // It ran to the end on its own, which must be a whole, clean run.
        let status = child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_mut()
            .and_then(|c| c.try_wait().ok().flatten());
        assert_eq!(
            status.and_then(|s| s.code()),
            Some(0),
            "the run was not killed at request {kill_at} and did not succeed: {}",
            std::fs::read_to_string(dir.join("stderr.txt")).unwrap_or_default()
        );
    }
    // The fake carries out the request it was handling when the kill came
    // on its own thread; wait for that, or cleanup could race the write.
    if was_killed {
        while server.handled() < base.load(Ordering::SeqCst) + kill_at {
            assert!(Instant::now() < deadline, "the fake did not finish");
            thread::sleep(Duration::from_millis(2));
        }
    }
    let left_something = server.snapshot() != before;
    let ledger = dir.join("ledger.jsonl");
    assert!(
        ledger.exists() || !left_something,
        "killed at request {kill_at}: the run left data and no ledger"
    );
    if ledger.exists() {
        let output = run(proofmark(dir).args([
            "cleanup",
            "--endpoint",
            &server.endpoint().to_string(),
            "--ledger",
            "ledger.jsonl",
        ]));
        assert_exit(&output, 0);
        assert!(!ledger.exists(), "a complete cleanup removes the ledger");
    }
    (before, server.snapshot(), was_killed, left_something)
}

#[test]
#[expect(
    clippy::print_stderr,
    reason = "the test reports how many kill points it covered"
)]
fn a_run_killed_after_any_number_of_requests_leaves_a_ledger_that_cleanup_finishes() {
    let mut kill_at = 1;
    let mut recovered = 0;
    loop {
        let dir = temp_dir(&format!("killed-{kill_at}"));
        let (before, after, killed, left_something) = run_killed_at(kill_at, &dir);
        assert_eq!(
            before, after,
            "killed at request {kill_at}: the store is not back to how it was"
        );
        recovered += usize::from(killed && left_something);
        if !killed {
            // The run finished before that request: every point is covered.
            break;
        }
        kill_at += 1;
    }
    let requests = kill_at - 1;
    eprintln!("killed at each of {requests} requests; {recovered} left something for cleanup");
    assert!(requests > 40, "the run had only {requests} requests");
    // Most kill points leave a bucket or objects behind; those are the ones
    // where cleanup from the ledger has real work to do.
    assert!(
        recovered > 30,
        "only {recovered} kills left anything for cleanup"
    );
}

// Secrets.

#[test]
fn a_planted_secret_appears_in_no_output() {
    let signatures: Arc<Mutex<Vec<String>>> = Arc::default();
    let for_hook = Arc::clone(&signatures);
    let token = "PLANTED-session-token-6f1d0c";
    let watch: Watch = Arc::new(move |request: &Request| {
        if let Some(sig) = request
            .header("authorization")
            .and_then(|a| a.rsplit_once("Signature="))
            .map(|(_, s)| s.to_owned())
        {
            for_hook
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(sig);
        }
    });
    // A foreign object keeps the bucket, so cleanup is incomplete and the
    // ledger is kept to be searched too.
    let server = interfering(6, Some(watch));
    let dir = temp_dir("secrets");
    let output = run(proofmark(&dir).env("AWS_SESSION_TOKEN", token).args([
        "run",
        "--endpoint",
        &server.endpoint().to_string(),
        "--verbose",
        "--ledger",
        "ledger.jsonl",
        "--report",
        "json=report.json",
        "--report",
        "junit=report.xml",
        "--report",
        "markdown=report.md",
    ]));
    assert_exit(&output, 5);
    let mut outputs = vec![
        ("stdout", text(&output.stdout)),
        ("stderr", text(&output.stderr)),
    ];
    for file in ["report.json", "report.xml", "report.md", "ledger.jsonl"] {
        let content = std::fs::read_to_string(dir.join(file)).expect(file);
        assert!(!content.is_empty(), "{file} is empty");
        outputs.push((file, content));
    }
    assert!(
        outputs[1].1.contains("> PUT /proofmark-"),
        "verbose output was written"
    );
    let signatures = signatures
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert!(signatures.len() > 40, "saw {} signatures", signatures.len());
    let mut secrets = vec![token.to_owned(), fake::SECRET_ACCESS_KEY.to_owned()];
    secrets.extend(signatures);
    for (name, content) in &outputs {
        for secret in &secrets {
            assert!(
                !content.contains(secret.as_str()),
                "{name} contains a secret ({}...)",
                &secret[..8]
            );
        }
    }
}
