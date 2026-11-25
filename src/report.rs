//! A run's results and the four ways of writing them: the terminal matrix,
//! JSON, JUnit and Markdown.
//!
//! Everything in a [`Report`] has already been scrubbed of secrets by the
//! runner. Details are built from status codes, error codes and counts, and
//! no response body is copied into a report.

use std::fmt::Write as _;

use serde_json::{Value, json};

use crate::probe::{EXPECTATIONS_VERSION, Expectation, Status};
use crate::s3::xml_escape;
use crate::safety::Cleanup;
use crate::time::UtcTime;

/// The version of the JSON report's shape.
pub const SCHEMA_VERSION: u32 = 1;

/// One exchange as a report shows it: no headers, no bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeSummary {
    /// The probe's name for the step.
    pub label: String,
    /// The method.
    pub method: String,
    /// The request target, with secret query values redacted.
    pub target: String,
    /// The response status.
    pub status: u16,
    /// The store's request id, if it sent one.
    pub request_id: Option<String>,
}

/// One probe's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    /// The probe id.
    pub id: String,
    /// Its feature.
    pub feature: String,
    /// The status.
    pub status: Status,
    /// The store answered success and ignored part of the request.
    pub silent: bool,
    /// What it expected, and the evidence.
    pub expectation: Expectation,
    /// What happened, if it was not a pass.
    pub detail: String,
    /// The requests it made.
    pub exchanges: Vec<ExchangeSummary>,
}

/// Everything about one run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The endpoint, as `http://host:port`.
    pub endpoint: String,
    /// The signing region.
    pub region: String,
    /// The seed for payloads, so the run can be repeated.
    pub seed: u64,
    /// The run id in bucket names and key prefixes.
    pub run_id: String,
    /// When the run started.
    pub started: UtcTime,
    /// The probe ids and features selected; both empty for all.
    pub selection: (Vec<String>, Vec<String>),
    /// The bucket the probes worked in.
    pub bucket: String,
    /// Buckets this run created.
    pub buckets_created: Vec<String>,
    /// Where the ledger was written.
    pub ledger: String,
    /// One result per probe, in run order.
    pub results: Vec<ProbeResult>,
    /// What cleanup did.
    pub cleanup: Cleanup,
    /// The statuses that make the exit code 1.
    pub fail_on: Vec<Status>,
}

impl Report {
    /// The exit code the design gives this outcome: 5 when cleanup left
    /// something, else 1 when a status is in `fail_on`, else 0.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.cleanup.complete() {
            u8::from(
                self.results
                    .iter()
                    .any(|r| self.fail_on.contains(&r.status)),
            )
        } else {
            5
        }
    }

    fn count(&self, feature: Option<&str>, status: Status) -> usize {
        self.results
            .iter()
            .filter(|r| feature.is_none_or(|f| r.feature == f) && r.status == status)
            .count()
    }

    fn features(&self) -> Vec<&str> {
        let mut features: Vec<&str> = Vec::new();
        for result in &self.results {
            if !features.contains(&result.feature.as_str()) {
                features.push(&result.feature);
            }
        }
        features
    }

    /// Findings first: silent ones, then by status, then in run order.
    fn findings(&self) -> Vec<&ProbeResult> {
        let mut findings: Vec<&ProbeResult> = self
            .results
            .iter()
            .filter(|r| r.status != Status::Pass)
            .collect();
        findings.sort_by_key(|r| (!r.silent, r.status));
        findings
    }

    /// The terminal output: a matrix per feature, the findings, cleanup and
    /// the result line.
    #[must_use]
    pub fn terminal(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "proofmark {}  endpoint {}  region {}  seed {}",
            env!("CARGO_PKG_VERSION"),
            self.endpoint,
            self.region,
            self.seed
        );
        let created = if self.buckets_created.contains(&self.bucket) {
            " (created by this run)"
        } else {
            " (existing)"
        };
        let _ = writeln!(out, "run {}  bucket {}{created}", self.run_id, self.bucket);
        let _ = writeln!(out, "ledger: {}", self.ledger);
        out.push('\n');

        let width = self
            .features()
            .iter()
            .map(|f| f.len())
            .chain(["feature".len()])
            .max()
            .unwrap_or(0);
        let _ = write!(out, "{:width$}  probes", "feature");
        for status in Status::ALL {
            let _ = write!(out, "  {status}");
        }
        out.push('\n');
        for feature in self.features() {
            let total = self.results.iter().filter(|r| r.feature == feature).count();
            let _ = write!(out, "{feature:width$}  {total:>6}");
            for status in Status::ALL {
                let n = self.count(Some(feature), status);
                let _ = write!(out, "  {n:>w$}", w = status.as_str().len());
            }
            out.push('\n');
        }
        out.push('\n');

        let findings = self.findings();
        if findings.is_empty() {
            out.push_str("findings: none\n");
        } else {
            out.push_str("findings\n");
            for r in findings {
                let silent = if r.silent { "silent" } else { "      " };
                let _ = writeln!(out, "  {:<12} {silent}  {}", r.status.as_str(), r.id);
                let _ = writeln!(out, "      {}", r.detail);
                let _ = writeln!(
                    out,
                    "      expected: {}; basis: {} ({}, \"{}\")",
                    r.expectation.statement,
                    r.expectation.basis.as_str(),
                    r.expectation.citation.url,
                    r.expectation.citation.section
                );
            }
        }
        out.push('\n');

        let _ = write!(
            out,
            "cleanup: {} bucket(s), {} object(s) removed",
            self.cleanup.buckets_removed, self.cleanup.objects_removed
        );
        if self.cleanup.complete() {
            out.push_str(", nothing left\n");
        } else {
            let _ = writeln!(
                out,
                ", {} left; ledger kept at {}",
                self.cleanup.left.len(),
                self.ledger
            );
            for left in &self.cleanup.left {
                let _ = writeln!(out, "  left: {left}");
            }
        }
        let counts: Vec<String> = Status::ALL[1..]
            .iter()
            .filter_map(|s| {
                let n = self.count(None, *s);
                (n > 0).then(|| format!("{n} {s}"))
            })
            .collect();
        let summary = if counts.is_empty() {
            format!("all {} passed", self.results.len())
        } else {
            counts.join(", ")
        };
        let _ = writeln!(out, "result: {summary} (exit {})", self.exit_code());
        out
    }

    /// The JSON report.
    #[must_use]
    pub fn json(&self) -> String {
        let results: Vec<Value> = self
            .results
            .iter()
            .map(|r| {
                let exchanges: Vec<Value> = r
                    .exchanges
                    .iter()
                    .map(|e| {
                        json!({
                            "label": e.label,
                            "method": e.method,
                            "target": e.target,
                            "status": e.status,
                            "request_id": e.request_id,
                        })
                    })
                    .collect();
                json!({
                    "id": r.id,
                    "feature": r.feature,
                    "status": r.status.as_str(),
                    "silent": r.silent,
                    "expectation": r.expectation.statement,
                    "basis": r.expectation.basis.as_str(),
                    "citation": {
                        "url": r.expectation.citation.url,
                        "section": r.expectation.citation.section,
                        "read": r.expectation.citation.read,
                    },
                    "detail": r.detail,
                    "exchanges": exchanges,
                })
            })
            .collect();
        let report = json!({
            "schema_version": SCHEMA_VERSION,
            "proofmark_version": env!("CARGO_PKG_VERSION"),
            "expectations_version": EXPECTATIONS_VERSION,
            "endpoint": self.endpoint,
            "region": self.region,
            "seed": self.seed,
            "run_id": self.run_id,
            "started": self.started.iso8601(),
            "selection": { "probes": self.selection.0, "features": self.selection.1 },
            "bucket": self.bucket,
            "buckets_created": self.buckets_created,
            "results": results,
            "cleanup": {
                "complete": self.cleanup.complete(),
                "objects_removed": self.cleanup.objects_removed,
                "buckets_removed": self.cleanup.buckets_removed,
                "left": self.cleanup.left,
            },
            "exit_code": self.exit_code(),
        });
        let mut text = serde_json::to_string_pretty(&report).unwrap_or_default();
        text.push('\n');
        text
    }

    /// The JUnit XML report: one suite per feature, one case per probe.
    /// A probe whose status is in `fail_on` is a failure; any other passes.
    #[must_use]
    pub fn junit(&self) -> String {
        let failed = |r: &ProbeResult| self.fail_on.contains(&r.status);
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        let _ = writeln!(
            out,
            "<testsuites name=\"proofmark\" tests=\"{}\" failures=\"{}\">",
            self.results.len(),
            self.results.iter().filter(|r| failed(r)).count()
        );
        for feature in self.features() {
            let cases: Vec<&ProbeResult> = self
                .results
                .iter()
                .filter(|r| r.feature == feature)
                .collect();
            let _ = writeln!(
                out,
                "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\">",
                xml_escape(feature),
                cases.len(),
                cases.iter().filter(|r| failed(r)).count()
            );
            for r in cases {
                let open = format!(
                    "    <testcase classname=\"proofmark.{}\" name=\"{}\"",
                    xml_escape(&r.feature),
                    xml_escape(&r.id)
                );
                if failed(r) {
                    let kind = if r.silent {
                        format!("{} (silent)", r.status)
                    } else {
                        r.status.to_string()
                    };
                    let _ = writeln!(
                        out,
                        "{open}>\n      <failure type=\"{}\" message=\"{}\">expected: {}; basis: {} ({}, &quot;{}&quot;)</failure>\n    </testcase>",
                        xml_escape(&kind),
                        xml_escape(&r.detail),
                        xml_escape(r.expectation.statement),
                        r.expectation.basis.as_str(),
                        xml_escape(r.expectation.citation.url),
                        xml_escape(r.expectation.citation.section)
                    );
                } else {
                    let _ = writeln!(out, "{open}/>");
                }
            }
            out.push_str("  </testsuite>\n");
        }
        out.push_str("</testsuites>\n");
        out
    }

    /// The Markdown report: one table row per probe.
    #[must_use]
    pub fn markdown(&self) -> String {
        let cell = |text: &str| text.replace('|', "\\|").replace(['\r', '\n'], " ");
        let mut out = String::from("# proofmark report\n\n");
        let _ = writeln!(
            out,
            "Endpoint `{}`, region `{}`, seed {}, proofmark {}, expectations version {EXPECTATIONS_VERSION}, started {}.\n",
            self.endpoint,
            self.region,
            self.seed,
            env!("CARGO_PKG_VERSION"),
            self.started.iso8601()
        );
        out.push_str("| Probe | Status | Detail |\n| --- | --- | --- |\n");
        for r in &self.results {
            let status = if r.silent {
                format!("{} (silent)", r.status)
            } else {
                r.status.to_string()
            };
            let _ = writeln!(out, "| `{}` | {status} | {} |", r.id, cell(&r.detail));
        }
        out.push('\n');
        if self.cleanup.complete() {
            out.push_str("Cleanup: complete.\n");
        } else {
            out.push_str("Cleanup: incomplete. Left:\n\n");
            for left in &self.cleanup.left {
                let _ = writeln!(out, "- {}", cell(left));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{Basis, Citation};

    fn report() -> Report {
        let expectation = Expectation {
            statement: "GET returns the bytes",
            basis: Basis::Documented,
            citation: Citation {
                url: "https://example.com/doc",
                section: "Description",
                read: "2026-11-25",
            },
        };
        let result = |id: &str, status, silent, detail: &str| ProbeResult {
            id: id.to_owned(),
            feature: "basic".to_owned(),
            status,
            silent,
            expectation,
            detail: detail.to_owned(),
            exchanges: vec![ExchangeSummary {
                label: "get".to_owned(),
                method: "GET".to_owned(),
                target: "/b/k".to_owned(),
                status: 200,
                request_id: Some("R1".to_owned()),
            }],
        };
        Report {
            endpoint: "http://127.0.0.1:9000".to_owned(),
            region: "us-east-1".to_owned(),
            seed: 42,
            run_id: "abc123".to_owned(),
            started: UtcTime::from_unix(1_764_000_000),
            selection: (Vec::new(), Vec::new()),
            bucket: "proofmark-abc123-main".to_owned(),
            buckets_created: vec!["proofmark-abc123-main".to_owned()],
            ledger: "proofmark-ledger-abc123.jsonl".to_owned(),
            results: vec![
                result("basic.put-get", Status::Pass, false, ""),
                result(
                    "basic.range",
                    Status::Violation,
                    true,
                    "get answered 200 | <x>",
                ),
                result(
                    "basic.delete-missing",
                    Status::Difference,
                    false,
                    "delete answered 404",
                ),
            ],
            cleanup: Cleanup {
                objects_removed: 3,
                buckets_removed: 1,
                left: Vec::new(),
                responses: 4,
            },
            fail_on: vec![Status::Violation, Status::Difference],
        }
    }

    #[test]
    fn the_terminal_output_lists_counts_findings_and_the_exit_code() {
        let text = report().terminal();
        let version = env!("CARGO_PKG_VERSION");
        let expected = format!(
            "proofmark {version}  endpoint http://127.0.0.1:9000  region us-east-1  seed 42
run abc123  bucket proofmark-abc123-main (created by this run)
ledger: proofmark-ledger-abc123.jsonl

feature  probes  pass  violation  difference  unsupported  inconclusive
basic         3     1          1           1            0             0

findings
  violation    silent  basic.range
      get answered 200 | <x>
      expected: GET returns the bytes; basis: documented (https://example.com/doc, \"Description\")
  difference           basic.delete-missing
      delete answered 404
      expected: GET returns the bytes; basis: documented (https://example.com/doc, \"Description\")

cleanup: 1 bucket(s), 3 object(s) removed, nothing left
result: 1 violation, 1 difference (exit 1)
"
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn junit_counts_match_the_report_when_parsed_back() {
        let report = report();
        let xml = report.junit();
        let doc = roxmltree::Document::parse(&xml).expect("well-formed JUnit");
        let root = doc.root_element();
        assert_eq!(root.attribute("tests"), Some("3"));
        assert_eq!(root.attribute("failures"), Some("2"));
        let failures: Vec<&str> = doc
            .descendants()
            .filter(|n| n.has_tag_name("failure"))
            .filter_map(|n| n.attribute("type"))
            .collect();
        assert_eq!(failures, vec!["violation (silent)", "difference"]);
        let message = doc
            .descendants()
            .find(|n| n.has_tag_name("failure"))
            .and_then(|n| n.attribute("message"));
        assert_eq!(message, Some("get answered 200 | <x>"));
    }

    #[test]
    fn markdown_escapes_table_cells() {
        let text = report().markdown();
        assert!(
            text.contains("| `basic.range` | violation (silent) | get answered 200 \\| <x> |\n")
        );
        assert!(text.contains("| `basic.put-get` | pass |  |\n"));
        assert!(text.ends_with("Cleanup: complete.\n"));
    }

    #[test]
    fn json_carries_the_versions_results_and_cleanup() {
        let value: Value = serde_json::from_str(&report().json()).expect("JSON");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["expectations_version"], EXPECTATIONS_VERSION);
        assert_eq!(value["results"][1]["status"], "violation");
        assert_eq!(value["results"][1]["silent"], true);
        assert_eq!(value["results"][1]["citation"]["section"], "Description");
        assert_eq!(value["results"][0]["exchanges"][0]["request_id"], "R1");
        assert_eq!(value["cleanup"]["complete"], true);
        assert_eq!(value["exit_code"], 1);
    }

    #[test]
    fn a_leftover_makes_the_exit_code_5_whatever_the_results() {
        let mut report = report();
        report
            .cleanup
            .left
            .push("bucket b: 409 BucketNotEmpty".to_owned());
        assert_eq!(report.exit_code(), 5);
        report.results.truncate(1);
        assert_eq!(report.exit_code(), 5);
        report.cleanup.left.clear();
        assert_eq!(report.exit_code(), 0);
    }
}
