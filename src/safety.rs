//! The rules that keep proofmark away from data it did not write
//! ([ADR 0004](../docs/adr/0004-only-touch-what-it-wrote.md)): bucket
//! names, the empty-bucket check, and cleanup from the ledger.

use std::path::Path;

use crate::http::{Endpoint, HttpError};
use crate::ledger::{self, Entry, Header, Ledger, ReadError};
use crate::rng::SplitMix64;
use crate::s3;
use crate::session::{Call, Remote};

/// A run id: six characters from `a-z0-9`, so that a bucket name made from
/// it is valid and does not collide with another run's.
#[must_use]
pub fn run_id(rng: &mut SplitMix64) -> String {
    const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..6)
        .map(|_| char::from(ALPHABET[rng.below(ALPHABET.len())]))
        .collect()
}

/// Whether `id` is shaped like a run id from [`run_id`].
#[must_use]
pub fn is_run_id(id: &str) -> bool {
    id.len() == 6
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// `proofmark-<run id>/`, the prefix of every key a run writes, in its own
/// bucket or in an existing one.
#[must_use]
pub fn key_prefix(run_id: &str) -> String {
    format!("proofmark-{run_id}/")
}

/// `proofmark-<run id>-<purpose>`, the name of a bucket this run creates.
///
/// # Errors
///
/// A description, if the result would break the S3 naming rules for
/// general purpose buckets.
pub fn bucket_name(run_id: &str, purpose: &str) -> Result<String, String> {
    let name = format!("proofmark-{run_id}-{purpose}");
    if is_valid_bucket_name(&name) {
        Ok(name)
    } else {
        Err(format!("{name:?} is not a valid bucket name"))
    }
}

/// The naming rules for general purpose buckets, from "General purpose
/// bucket naming rules" in the S3 User Guide (read 2026-11-25): 3 to 63
/// characters of `a-z`, `0-9`, `.` and `-`, starting and ending with a
/// letter or digit, no `..`, not shaped like an IP address, and none of the
/// reserved prefixes and suffixes (`-an` is kept for account regional
/// namespaces).
#[must_use]
pub fn is_valid_bucket_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    let edge = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let ip_like = name.split('.').count() == 4
        && name
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    (3..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.' || *b == b'-')
        && edge(bytes.first())
        && edge(bytes.last())
        && !name.contains("..")
        && !ip_like
        && !["xn--", "sthree-", "amzn-s3-demo-"]
            .iter()
            .any(|p| name.starts_with(p))
        && ![
            "-s3alias",
            "--ol-s3",
            ".mrap",
            "--x-s3",
            "--table-s3",
            "-an",
        ]
        .iter()
        .any(|s| name.ends_with(s))
}

/// What the empty-bucket check found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Emptiness {
    /// Every listing came back empty.
    Empty,
    /// A listing named something; the string says which listing.
    NotEmpty(String),
    /// The listings did not show the bucket empty or not: an error status,
    /// or a body that is not a listing. Treated like `NotEmpty`.
    Unknown(String),
}

/// Lists the bucket's object versions and its multipart uploads, and says
/// whether both are empty. It reads only.
///
/// Only a whole listing of the right kind that names nothing counts as
/// empty. Anything else, including a store that does not implement one of
/// the listings (`501`), leaves the bucket not shown to be empty: the
/// current objects say nothing of old versions and delete markers, and a
/// store that cannot list uploads may still hold some.
///
/// # Errors
///
/// [`HttpError`] if a listing gets no response.
pub fn check_empty(remote: &mut Remote, bucket: &str) -> Result<Emptiness, HttpError> {
    for (query, root, what) in [
        ("versions", "ListVersionsResult", "object versions"),
        ("uploads", "ListMultipartUploadsResult", "multipart uploads"),
    ] {
        let (_, response) = remote.send(&Call::new("GET", bucket, None).query(query, ""))?;
        if let Some(found) = judge_listing(what, root, &response) {
            return Ok(found);
        }
    }
    Ok(Emptiness::Empty)
}

/// Why `bucket` may have had versioning turned on, or `None` if
/// `GetBucketVersioning` shows it never was. Plain deletes in a bucket that
/// has had versioning on leave versions or delete markers behind, so such a
/// bucket is refused like one that is not empty. It reads only.
///
/// # Errors
///
/// [`HttpError`] if the request gets no response.
pub fn check_unversioned(remote: &mut Remote, bucket: &str) -> Result<Option<String>, HttpError> {
    let (_, response) = remote.send(&Call::new("GET", bucket, None).query("versioning", ""))?;
    if response.status() != 200 {
        let code = s3::error_code(response.body()).unwrap_or_default();
        return Ok(Some(
            format!(
                "reading its versioning answered {} {code}",
                response.status()
            )
            .trim_end()
            .to_owned(),
        ));
    }
    Ok(match s3::versioning_status(response.body()) {
        Ok(None) => None,
        Ok(Some(status)) => Some(format!(
            "its versioning is {status:?}; proofmark does not yet work in a bucket that has had versioning on"
        )),
        Err(why) => Some(format!("reading its versioning: {why}")),
    })
}

fn judge_listing(what: &str, root: &str, response: &crate::http::Response) -> Option<Emptiness> {
    if response.status() != 200 {
        let code = s3::error_code(response.body()).unwrap_or_default();
        return Some(Emptiness::Unknown(
            format!("listing {what} answered {} {code}", response.status())
                .trim_end()
                .to_owned(),
        ));
    }
    match s3::listing_is_empty(response.body(), root) {
        Ok(true) => None,
        Ok(false) => Some(Emptiness::NotEmpty(format!("the bucket has {what}"))),
        Err(why) => Some(Emptiness::Unknown(format!("listing {what}: {why}"))),
    }
}

/// What cleanup did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cleanup {
    /// Object deletes that succeeded or found nothing.
    pub objects_removed: usize,
    /// Buckets deleted or already gone.
    pub buckets_removed: usize,
    /// Everything that is still there, with the reason.
    pub left: Vec<String>,
    /// How many deletes got a response at all. Zero with something to
    /// delete means the endpoint could not be reached.
    pub responses: usize,
}

impl Cleanup {
    /// Whether nothing the run wrote is left.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.left.is_empty()
    }
}

/// Checks that a ledger names only what proofmark itself writes, for
/// `endpoint`: buckets `proofmark-<run id>-*`, and keys under
/// `proofmark-<run id>/` in those or in `bucket`, the existing bucket the
/// user named. A ledger is a file anyone can edit, and cleanup deletes what
/// it names, so nothing else in it is trusted.
fn trust(
    header: &Header,
    entries: &[Entry],
    endpoint: &Endpoint,
    bucket: Option<&str>,
) -> Result<(), String> {
    let recorded = Endpoint::parse(&header.endpoint).map_err(|e| e.to_string())?;
    if &recorded != endpoint {
        return Err(format!(
            "the ledger was written for {recorded}, not {endpoint}; refusing to delete its keys elsewhere"
        ));
    }
    let id = &header.run_id;
    if !is_run_id(id) {
        return Err(format!(
            "the ledger's run id {id:?} is not one proofmark makes; refusing to delete anything from it"
        ));
    }
    let own =
        |name: &str| name.starts_with(&format!("proofmark-{id}-")) && is_valid_bucket_name(name);
    let prefix = key_prefix(id);
    for (i, entry) in entries.iter().enumerate() {
        let (ok, what) = match &entry.key {
            None => (own(&entry.bucket), format!("bucket {}", entry.bucket)),
            Some(key) => (
                key.starts_with(&prefix)
                    && (own(&entry.bucket) || bucket == Some(entry.bucket.as_str())),
                format!("{}/{key}", entry.bucket),
            ),
        };
        if !ok {
            return Err(format!(
                "line {} of the ledger names {what}, which is not proofmark's: run {id} only creates buckets proofmark-{id}-* and writes keys under {prefix}, in those or in the bucket given with --bucket; refusing to delete anything from this ledger",
                i + 2
            ));
        }
    }
    Ok(())
}

/// Deletes exactly what the ledger at `path` records, one request per
/// key, version and bucket: objects first, then buckets. It never lists
/// and never deletes anything the ledger does not name. The ledger is read
/// once, and refused unless it was written for this remote's endpoint and
/// names only proofmark's own buckets and keys, `bucket` being the existing
/// bucket a run worked in, if any. When nothing is left the ledger file is
/// removed; otherwise it is kept for another try.
///
/// # Errors
///
/// [`ReadError`] if the ledger cannot be read or is refused. Nothing is
/// deleted then.
pub fn cleanup(
    remote: &mut Remote,
    path: &Path,
    bucket: Option<&str>,
) -> Result<Cleanup, ReadError> {
    let (header, entries) = ledger::read(path)?;
    trust(&header, &entries, remote.endpoint(), bucket).map_err(ReadError::Refused)?;
    let plan = ledger::plan(&entries);
    // Each delete is recorded as it succeeds, so that a later cleanup from
    // a kept ledger does not delete a key someone has written since.
    let mut ledger = Ledger::append(path).map_err(ReadError::Io)?;
    let mut done = Cleanup::default();
    for object in &plan.objects {
        let record = Entry::delete_object(&object.bucket, &object.key);
        let unversioned = object.plain_delete.then_some(None);
        let mut all = true;
        for version in object
            .version_ids
            .iter()
            .map(|id| Some(id.as_str()))
            .chain(unversioned)
        {
            let mut call = Call::new("DELETE", &object.bucket, Some(&object.key));
            if let Some(id) = version {
                call = call.query("versionId", id);
            }
            let deleted = gone(remote, &call, &mut done.responses).and_then(|status| {
                ledger
                    .record(&record.outcome(status, version))
                    .map_err(|e| format!("deleted, but the ledger could not record it: {e}"))
            });
            if let Err(why) = deleted {
                all = false;
                done.left
                    .push(remote.scrub(&format!("object {}/{}: {why}", object.bucket, object.key)));
            }
        }
        if all {
            done.objects_removed += 1;
        }
    }
    for bucket in &plan.buckets {
        let call = Call::new("DELETE", bucket, None);
        let deleted = gone(remote, &call, &mut done.responses).and_then(|status| {
            ledger
                .record(&Entry::delete_bucket(bucket).outcome(status, None))
                .map_err(|e| format!("deleted, but the ledger could not record it: {e}"))
        });
        match deleted {
            Ok(()) => done.buckets_removed += 1,
            Err(why) => done
                .left
                .push(remote.scrub(&format!("bucket {bucket}: {why}"))),
        }
    }
    drop(ledger);
    if done.complete() {
        // Everything is gone; a ledger that cannot be removed only names
        // things that no longer exist.
        let _ = std::fs::remove_file(path);
    }
    Ok(done)
}

/// Sends a delete; the status if the thing is gone afterwards (2xx, or 404).
fn gone(remote: &mut Remote, call: &Call, responses: &mut usize) -> Result<u16, String> {
    let sent = remote.send(call);
    if sent.is_ok() {
        *responses += 1;
    }
    match sent {
        Ok((_, response)) if ledger::gone(response.status()) => Ok(response.status()),
        Ok((_, response)) => Err(format!(
            "{} {}",
            response.status(),
            s3::error_code(response.body()).unwrap_or_default()
        )
        .trim_end()
        .to_owned()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Client;
    use std::io::{Read, Write};

    /// A server on loopback that answers every request with what `answer`
    /// makes of its request line.
    type Answer = fn(&str) -> String;

    fn scripted(answer: Answer) -> Endpoint {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut seen = Vec::new();
                let mut buf = [0_u8; 4096];
                while let Ok(n @ 1..) = stream.read(&mut buf) {
                    seen.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&seen).into_owned();
                    let Some(end) = text.find("\r\n\r\n") else {
                        continue;
                    };
                    let length = text[..end]
                        .lines()
                        .find_map(|l| {
                            let l = l.to_ascii_lowercase();
                            l.strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if seen.len() >= end + 4 + length {
                        let line = text.lines().next().unwrap_or_default().to_owned();
                        let _ = stream.write_all(answer(&line).as_bytes());
                        break;
                    }
                }
            }
        });
        Endpoint::parse(&format!("http://127.0.0.1:{port}")).expect("endpoint")
    }

    fn reply(status: u16, body: &str) -> String {
        format!(
            "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    const VERSIONS: &str = "<ListVersionsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>b</Name><IsTruncated>false</IsTruncated></ListVersionsResult>";
    const UPLOADS: &str = "<ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>b</Bucket><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>";
    const OBJECTS: &str = "<ListBucketResult><Name>b</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>";

    fn emptiness(answer: fn(&str) -> String) -> Emptiness {
        let mut remote = Remote::new(
            Client::new(),
            scripted(answer),
            crate::fake::credentials(),
            "us-east-1",
        );
        check_empty(&mut remote, "b").expect("answered")
    }

    /// ADR 0004 and the decision that anything the check cannot read as
    /// empty is not empty: an unsupported listing, a listing that lacks
    /// what a complete one has, and a listing of the wrong kind each
    /// refuse the bucket.
    #[test]
    fn the_empty_check_counts_what_it_cannot_read_as_empty_as_not_empty() {
        assert_eq!(
            emptiness(|line| reply(
                200,
                if line.contains("versions") {
                    VERSIONS
                } else {
                    UPLOADS
                }
            )),
            Emptiness::Empty
        );
        let refused: [fn(&str) -> String; 5] = [
            // No version listing: the current objects say nothing of old
            // versions and delete markers.
            |line| match line {
                l if l.contains("versions") => {
                    reply(501, "<Error><Code>NotImplemented</Code></Error>")
                }
                l if l.contains("list-type") => reply(200, OBJECTS),
                _ => reply(501, "<Error><Code>NotImplemented</Code></Error>"),
            },
            // No upload listing: uploads may exist all the same.
            |line| match line {
                l if l.contains("versions") => reply(200, VERSIONS),
                _ => reply(501, "<Error><Code>NotImplemented</Code></Error>"),
            },
            // A versions listing without IsTruncated is not a whole one.
            |line| match line {
                l if l.contains("versions") => reply(200, "<ListVersionsResult/>"),
                _ => reply(200, UPLOADS),
            },
            // The same empty listing whatever was asked: one of the two
            // answers is a listing of the wrong kind.
            |_| reply(200, UPLOADS),
            |_| reply(200, VERSIONS),
        ];
        for (i, answer) in refused.into_iter().enumerate() {
            let found = emptiness(answer);
            assert!(
                matches!(found, Emptiness::NotEmpty(_) | Emptiness::Unknown(_)),
                "case {i}: {found:?}"
            );
        }
    }

    /// A bucket that has had versioning on keeps the versions and delete
    /// markers that plain deletes leave, so an existing bucket is used only
    /// when `GetBucketVersioning` shows versioning was never turned on.
    #[test]
    fn an_existing_bucket_that_may_be_versioned_is_refused_before_any_write() {
        let cases: [fn(&str) -> String; 3] = [
            |_| {
                reply(
                    200,
                    "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
                )
            },
            |_| {
                reply(
                    200,
                    "<VersioningConfiguration><Status>Suspended</Status></VersioningConfiguration>",
                )
            },
            |_| reply(501, "<Error><Code>NotImplemented</Code></Error>"),
        ];
        let dir = std::env::temp_dir().join(format!("proofmark-safety-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        for (i, versioning) in cases.into_iter().enumerate() {
            static VERSIONING: std::sync::Mutex<Option<Answer>> = std::sync::Mutex::new(None);
            *VERSIONING.lock().expect("lock") = Some(versioning);
            let endpoint = scripted(|line| match line {
                l if l.starts_with("PUT") || l.starts_with("DELETE") => {
                    reply(500, "<Error><Code>NotExpected</Code></Error>")
                }
                l if l.contains("versioning") => VERSIONING.lock().expect("lock").expect("set")(l),
                l if l.contains("versions") => reply(200, VERSIONS),
                l if l.contains("uploads") => reply(200, UPLOADS),
                _ => reply(200, ""),
            });
            let ledger = dir.join(format!("versioned-{i}.jsonl"));
            let _ = std::fs::remove_file(&ledger);
            let config = crate::run::RunConfig {
                endpoint,
                region: "us-east-1".to_owned(),
                credentials: crate::fake::credentials(),
                probes: crate::probe::all().iter().collect(),
                selection: (Vec::new(), Vec::new()),
                bucket: crate::run::BucketMode::Existing("b".to_owned()),
                ledger: Some(ledger.clone()),
                ca_pem: None,
                timeout: std::time::Duration::from_secs(5),
                seed: 1,
                run_id: "abc123".to_owned(),
                fail_on: Vec::new(),
            };
            let secrets = crate::session::Secrets::default();
            match crate::run::execute(&config, None, &secrets) {
                Ok(report) => panic!("case {i}: ran {} probes", report.results.len()),
                Err(refusal) => assert_eq!(refusal.code, 3, "case {i}: {refusal}"),
            }
            assert!(
                !ledger.exists(),
                "case {i}: a ledger means a write could follow"
            );
        }
    }

    #[test]
    fn run_ids_make_valid_bucket_names() {
        let mut rng = SplitMix64::new(7);
        for _ in 0..1000 {
            let id = run_id(&mut rng);
            assert_eq!(id.len(), 6);
            assert!(bucket_name(&id, "main").is_ok(), "{id}");
            assert!(bucket_name(&id, "absent").is_ok(), "{id}");
        }
    }

    #[test]
    fn applies_the_general_purpose_naming_rules() {
        for good in ["abc", "my-bucket.logs", "a1", "proofmark-abc123-main"]
            .iter()
            .filter(|n| n.len() >= 3)
        {
            assert!(is_valid_bucket_name(good), "{good}");
        }
        for bad in [
            "ab",
            "Upper",
            "under_score",
            "-start",
            "end-",
            "a..b",
            "192.168.5.4",
            "xn--abc",
            "abc-s3alias",
            &"a".repeat(64),
        ] {
            assert!(!is_valid_bucket_name(bad), "{bad}");
        }
    }
}
