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

/// Lists the bucket's object versions (or its objects, if the store does
/// not implement version listing) and its multipart uploads, and says
/// whether all are empty. It reads only.
///
/// A store that answers `501` to the upload listing cannot hold an upload
/// proofmark could disturb, so that counts as no uploads.
///
/// # Errors
///
/// [`HttpError`] if a listing gets no response.
pub fn check_empty(remote: &mut Remote, bucket: &str) -> Result<Emptiness, HttpError> {
    let versions = Call::new("GET", bucket, None).query("versions", "");
    let (_, response) = remote.send(&versions)?;
    let (what, response) = if response.status() == 501 {
        let objects = Call::new("GET", bucket, None).query("list-type", "2");
        ("objects", remote.send(&objects)?.1)
    } else {
        ("object versions", response)
    };
    if let Some(found) = judge_listing(what, &response) {
        return Ok(found);
    }
    let uploads = Call::new("GET", bucket, None).query("uploads", "");
    let (_, response) = remote.send(&uploads)?;
    if response.status() == 501 {
        return Ok(Emptiness::Empty);
    }
    Ok(judge_listing("multipart uploads", &response).unwrap_or(Emptiness::Empty))
}

fn judge_listing(what: &str, response: &crate::http::Response) -> Option<Emptiness> {
    if response.status() != 200 {
        let code = s3::error_code(response.body()).unwrap_or_default();
        return Some(Emptiness::Unknown(
            format!("listing {what} answered {} {code}", response.status())
                .trim_end()
                .to_owned(),
        ));
    }
    match s3::listing_is_empty(response.body()) {
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
