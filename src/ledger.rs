//! The write ledger ([ADR 0004](../docs/adr/0004-only-touch-what-it-wrote.md)):
//! a JSON-lines file that records every bucket creation and object write
//! before the request is sent, and its outcome after.
//!
//! The first line names the run. Each later line is one entry:
//!
//! ```text
//! {"proofmark_ledger":1,"run_id":"k3x9q2","endpoint":"http://127.0.0.1:9000","region":"us-east-1"}
//! {"op":"create_bucket","bucket":"proofmark-k3x9q2-main"}
//! {"op":"create_bucket","bucket":"proofmark-k3x9q2-main","status":200}
//! {"op":"put_object","bucket":"proofmark-k3x9q2-main","key":"basic.put-get/object"}
//! {"op":"put_object","bucket":"proofmark-k3x9q2-main","key":"basic.put-get/object","status":200,"version_id":null}
//! ```
//!
//! An entry without `status` is an intent; one with it is the outcome.
//! Each line is written with one call and flushed before the request goes
//! out, so a crash leaves at worst a cut-off last line, which the reader
//! skips: the request it was about to announce was never sent.
//!
//! The ledger holds bucket names, keys and version ids. Nothing secret.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

const FORMAT: u64 = 1;

/// What the ledger is about: written once, as its first line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The run that wrote it.
    pub run_id: String,
    /// The endpoint, as `http://host:port`.
    pub endpoint: String,
    /// The signing region.
    pub region: String,
}

/// The kind of write an entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Op {
    /// `CreateBucket`.
    CreateBucket,
    /// `PutObject`.
    PutObject,
}

impl Op {
    fn as_str(self) -> &'static str {
        match self {
            Self::CreateBucket => "create_bucket",
            Self::PutObject => "put_object",
        }
    }
}

/// One line after the header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// What was written.
    pub op: Op,
    /// The bucket.
    pub bucket: String,
    /// The key, for an object write.
    pub key: Option<String>,
    /// `None` for an intent; the response status for an outcome.
    pub status: Option<u16>,
    /// The version id the response gave, if any.
    pub version_id: Option<String>,
}

impl Entry {
    /// An intent to create `bucket`.
    #[must_use]
    pub fn create_bucket(bucket: &str) -> Self {
        Self {
            op: Op::CreateBucket,
            bucket: bucket.to_owned(),
            key: None,
            status: None,
            version_id: None,
        }
    }

    /// An intent to write `key` in `bucket`.
    #[must_use]
    pub fn put_object(bucket: &str, key: &str) -> Self {
        Self {
            op: Op::PutObject,
            bucket: bucket.to_owned(),
            key: Some(key.to_owned()),
            status: None,
            version_id: None,
        }
    }

    /// The outcome of this intent.
    #[must_use]
    pub fn outcome(&self, status: u16, version_id: Option<&str>) -> Self {
        Self {
            status: Some(status),
            version_id: version_id.map(str::to_owned),
            ..self.clone()
        }
    }

    fn to_json(&self) -> Value {
        let mut line = Map::new();
        line.insert("op".to_owned(), json!(self.op.as_str()));
        line.insert("bucket".to_owned(), json!(self.bucket));
        if let Some(key) = &self.key {
            line.insert("key".to_owned(), json!(key));
        }
        if let Some(status) = self.status {
            line.insert("status".to_owned(), json!(status));
            line.insert("version_id".to_owned(), json!(self.version_id));
        }
        Value::Object(line)
    }

    fn from_json(value: &Value) -> Option<Self> {
        let text = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_owned);
        let op = match value.get("op")?.as_str()? {
            "create_bucket" => Op::CreateBucket,
            "put_object" => Op::PutObject,
            _ => return None,
        };
        let key = text("key");
        if (op == Op::PutObject) != key.is_some() {
            return None;
        }
        let status = match value.get("status") {
            None => None,
            Some(status) => Some(u16::try_from(status.as_u64()?).ok()?),
        };
        Some(Self {
            op,
            bucket: text("bucket")?,
            key,
            status,
            version_id: text("version_id"),
        })
    }
}

/// An open ledger, appended to as the run writes.
#[derive(Debug)]
pub struct Ledger {
    file: File,
    path: PathBuf,
}

impl Ledger {
    /// Creates the ledger at `path` and writes its header. Refuses to
    /// overwrite an existing file, which could be another run's ledger.
    ///
    /// # Errors
    ///
    /// The I/O error, including `AlreadyExists`.
    pub fn create(path: &Path, header: &Header) -> io::Result<Self> {
        let file = OpenOptions::new().write(true).create_new(true).open(path)?;
        let mut ledger = Self {
            file,
            path: path.to_owned(),
        };
        let line = json!({
            "proofmark_ledger": FORMAT,
            "run_id": header.run_id,
            "endpoint": header.endpoint,
            "region": header.region,
        });
        ledger.write_line(&line)?;
        Ok(ledger)
    }

    /// Appends `entry` and flushes it.
    ///
    /// # Errors
    ///
    /// The I/O error. The caller must not send the write it announces.
    pub fn record(&mut self, entry: &Entry) -> io::Result<()> {
        self.write_line(&entry.to_json())
    }

    fn write_line(&mut self, value: &Value) -> io::Result<()> {
        let mut line = value.to_string();
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.flush()
    }

    /// Where the ledger is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Why a ledger could not be read.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReadError {
    /// The file could not be read.
    Io(io::Error),
    /// A line other than a cut-off last one is not a ledger line.
    Malformed {
        /// The line number, from 1.
        line: usize,
    },
    /// The ledger reads, but names something proofmark would not have
    /// written there, or was written for another endpoint.
    Refused(String),
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "could not read the ledger: {e}"),
            Self::Malformed { line } => {
                write!(f, "line {line} of the ledger is not a ledger entry")
            }
            Self::Refused(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for ReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Malformed { .. } | Self::Refused(_) => None,
        }
    }
}

/// Reads a ledger back: its header and its entries in order.
///
/// A last line with no line break that does not parse is the line a crash
/// cut off, and is skipped. Any other line that does not parse is an
/// error, because guessing what a damaged ledger meant could delete the
/// wrong thing.
///
/// # Errors
///
/// [`ReadError`] if the file cannot be read or is not a ledger.
pub fn read(path: &Path) -> Result<(Header, Vec<Entry>), ReadError> {
    let text = std::fs::read(path).map_err(ReadError::Io)?;
    let text = String::from_utf8_lossy(&text);
    let ends_cleanly = text.ends_with('\n');
    let lines: Vec<&str> = text.lines().collect();
    let mut header = None;
    let mut entries = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let cut_off = i + 1 == lines.len() && !ends_cleanly;
        let value: Option<Value> = serde_json::from_str(line).ok();
        if i == 0 {
            let parsed = value.as_ref().and_then(|v| {
                (v.get("proofmark_ledger")?.as_u64()? == FORMAT).then_some(())?;
                let text = |name: &str| Some(v.get(name)?.as_str()?.to_owned());
                Some(Header {
                    run_id: text("run_id")?,
                    endpoint: text("endpoint")?,
                    region: text("region")?,
                })
            });
            header = Some(parsed.ok_or(ReadError::Malformed { line: 1 })?);
            continue;
        }
        match value.as_ref().and_then(Entry::from_json) {
            Some(entry) => entries.push(entry),
            None if cut_off => {}
            None => return Err(ReadError::Malformed { line: i + 1 }),
        }
    }
    let header = header.ok_or(ReadError::Malformed { line: 1 })?;
    Ok((header, entries))
}

/// What cleanup must remove, worked out from a ledger's entries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Each object written: bucket, key, and the version ids its writes
    /// returned. A plain delete is also needed when any write of the key
    /// returned no version id, or its outcome was never recorded.
    pub objects: Vec<PlannedObject>,
    /// Buckets this run created, or may have created. A bucket whose
    /// creation was answered with an error is not this run's and is left.
    pub buckets: Vec<String>,
}

/// One key cleanup must remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedObject {
    /// The bucket.
    pub bucket: String,
    /// The key.
    pub key: String,
    /// Version ids to delete one by one.
    pub version_ids: Vec<String>,
    /// Whether to send a delete without a version id.
    pub plain_delete: bool,
}

/// Works out the cleanup plan. Every intent counts, whether or not its
/// outcome was recorded: a crash between request and response leaves an
/// intent alone, and that write may well have happened.
#[must_use]
pub fn plan(entries: &[Entry]) -> Plan {
    let mut plan = Plan::default();
    for entry in entries {
        match (entry.op, &entry.key) {
            (Op::PutObject, Some(key)) => {
                let index = plan
                    .objects
                    .iter()
                    .position(|o| o.bucket == entry.bucket && &o.key == key)
                    .unwrap_or_else(|| {
                        plan.objects.push(PlannedObject {
                            bucket: entry.bucket.clone(),
                            key: key.clone(),
                            version_ids: Vec::new(),
                            plain_delete: false,
                        });
                        plan.objects.len() - 1
                    });
                let object = &mut plan.objects[index];
                if let (Some(_), Some(id)) = (entry.status, entry.version_id.as_deref())
                    && id != "null"
                    && !object.version_ids.iter().any(|v| v == id)
                {
                    object.version_ids.push(id.to_owned());
                }
            }
            (Op::CreateBucket, _) => match entry.status {
                None => {
                    if !plan.buckets.contains(&entry.bucket) {
                        plan.buckets.push(entry.bucket.clone());
                    }
                }
                Some(status) if !(200..300).contains(&status) => {
                    plan.buckets.retain(|b| b != &entry.bucket);
                }
                Some(_) => {}
            },
            (Op::PutObject, None) => {}
        }
    }
    // A key needs a plain delete unless every write of it is known to have
    // returned a version id: an intent with no recorded outcome may have
    // been written, and an outcome without a version id was written to an
    // unversioned bucket. In a versioned bucket a plain delete would only
    // add a delete marker, so it is not sent when it is not needed.
    for object in &mut plan.objects {
        let of_key = |e: &&Entry| e.bucket == object.bucket && e.key.as_ref() == Some(&object.key);
        let intents = entries
            .iter()
            .filter(of_key)
            .filter(|e| e.status.is_none())
            .count();
        let versioned = entries
            .iter()
            .filter(of_key)
            .filter(|e| e.status.is_some() && e.version_id.as_deref().is_some_and(|v| v != "null"))
            .count();
        object.plain_delete = intents > versioned;
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("proofmark-ledger-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        path
    }

    fn header() -> Header {
        Header {
            run_id: "abc123".to_owned(),
            endpoint: "http://127.0.0.1:9000".to_owned(),
            region: "us-east-1".to_owned(),
        }
    }

    #[test]
    fn round_trips_entries_with_any_key() {
        let path = temp("round-trip.jsonl");
        let mut ledger = Ledger::create(&path, &header()).expect("create");
        let key = "a \"quoted\" key\n with a line break, \u{e9} and \\";
        let intent = Entry::put_object("b", key);
        ledger.record(&Entry::create_bucket("b")).expect("record");
        ledger.record(&intent).expect("record");
        ledger
            .record(&intent.outcome(200, Some("v1")))
            .expect("record");
        let (read_header, entries) = read(&path).expect("read");
        assert_eq!(read_header, header());
        assert_eq!(
            entries,
            vec![
                Entry::create_bucket("b"),
                intent.clone(),
                intent.outcome(200, Some("v1"))
            ]
        );
        assert!(
            Ledger::create(&path, &header()).is_err(),
            "never overwrites"
        );
    }

    #[test]
    fn skips_a_cut_off_last_line_and_refuses_damage_elsewhere() {
        let path = temp("cut.jsonl");
        let mut ledger = Ledger::create(&path, &header()).expect("create");
        ledger.record(&Entry::create_bucket("b")).expect("record");
        drop(ledger);
        let mut text = std::fs::read_to_string(&path).expect("read");
        text.push_str("{\"op\":\"put_obj");
        std::fs::write(&path, &text).expect("write");
        assert_eq!(
            read(&path).expect("read").1,
            vec![Entry::create_bucket("b")]
        );

        text.push('\n');
        std::fs::write(&path, &text).expect("write");
        assert!(matches!(read(&path), Err(ReadError::Malformed { line: 3 })));
    }

    #[test]
    fn plans_every_intent_and_skips_buckets_it_was_refused() {
        let put = Entry::put_object("mine", "k");
        let taken = Entry::create_bucket("taken");
        let entries = vec![
            Entry::create_bucket("mine"),
            Entry::create_bucket("mine").outcome(200, None),
            taken.clone(),
            taken.outcome(409, None),
            Entry::create_bucket("crashed"),
            put.clone(),
            put.outcome(200, None),
            Entry::put_object("mine", "lost-response"),
        ];
        let plan = plan(&entries);
        assert_eq!(plan.buckets, vec!["mine".to_owned(), "crashed".to_owned()]);
        let keys: Vec<(&str, bool)> = plan
            .objects
            .iter()
            .map(|o| (o.key.as_str(), o.plain_delete))
            .collect();
        assert_eq!(keys, vec![("k", true), ("lost-response", true)]);
    }

    #[test]
    fn deletes_versions_by_id_and_adds_no_plain_delete_when_all_are_known() {
        let put = Entry::put_object("b", "k");
        let entries = vec![
            put.clone(),
            put.outcome(200, Some("v1")),
            put.clone(),
            put.outcome(200, Some("v2")),
        ];
        let plan = plan(&entries);
        assert_eq!(plan.objects[0].version_ids, vec!["v1", "v2"]);
        assert!(!plan.objects[0].plain_delete);
    }
}
