//! Probes: what each one sends, what it expects and on what evidence, and
//! how its observation is judged
//! ([ADR 0003](../docs/adr/0003-expectations-carry-their-evidence.md)).
//!
//! A probe's `run` sends requests through a [`Session`]; its `judge` is a
//! pure function of the exchanges. The runner turns the judgement and the
//! expectation's basis into a [`Status`].

mod basic;

use std::fmt;

use crate::fake::Fault;
use crate::s3;
use crate::session::{Exchange, ProbeError, Session};

/// The version of the expectations as a whole. Any change to what a probe
/// expects bumps it, and reports carry it.
pub const EXPECTATIONS_VERSION: u32 = 1;

/// What an expectation rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Basis {
    /// The AWS documentation states the behaviour.
    Documented,
    /// Clients observed it on AWS; the documentation does not state it.
    Observed,
}

impl Basis {
    /// `documented` or `observed`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Documented => "documented",
            Self::Observed => "observed",
        }
    }
}

/// Where an expectation's evidence is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Citation {
    /// The page.
    pub url: &'static str,
    /// The section heading on that page, which outlives URL changes.
    pub section: &'static str,
    /// When it was read, `YYYY-MM-DD`.
    pub read: &'static str,
}

/// What a probe expects, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Expectation {
    /// One sentence a user can check against the evidence.
    pub statement: &'static str,
    /// What kind of evidence it is.
    pub basis: Basis,
    /// The evidence.
    pub citation: Citation,
}

/// A fault a probe catches, and whether the deviation it produces is
/// silent: the store answered success and ignored part of the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Catch {
    /// The fault.
    pub fault: Fault,
    /// Whether the probe reports it as silent.
    pub silent: bool,
}

/// What a judge concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Judgement {
    /// The store did what the expectation says.
    Matches,
    /// It did not.
    Deviates {
        /// What happened, in one line. Built from status codes, error
        /// codes and counts, never from response bodies.
        detail: String,
        /// The store answered success and ignored part of the request.
        silent: bool,
    },
    /// The store refused with `501 Not Implemented`.
    Unsupported {
        /// Which request was refused.
        detail: String,
    },
    /// The probe could not tell.
    Inconclusive {
        /// Why.
        reason: String,
    },
}

/// A probe's reported status: the table in ADR 0003.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Status {
    /// Matches the expectation.
    Pass,
    /// Breaks documented behaviour.
    Violation,
    /// Differs from behaviour observed on AWS.
    Difference,
    /// Refused honestly with `501`.
    Unsupported,
    /// Could not be judged.
    Inconclusive,
}

impl Status {
    /// Every status, in report order.
    pub const ALL: [Self; 5] = [
        Self::Pass,
        Self::Violation,
        Self::Difference,
        Self::Unsupported,
        Self::Inconclusive,
    ];

    /// The status as reports write it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Violation => "violation",
            Self::Difference => "difference",
            Self::Unsupported => "unsupported",
            Self::Inconclusive => "inconclusive",
        }
    }

    /// The status named `name`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == name)
    }

    /// The status for a judgement on an expectation with `basis`.
    #[must_use]
    pub fn of(judgement: &Judgement, basis: Basis) -> Self {
        match (judgement, basis) {
            (Judgement::Matches, _) => Self::Pass,
            (Judgement::Deviates { .. }, Basis::Documented) => Self::Violation,
            (Judgement::Deviates { .. }, Basis::Observed) => Self::Difference,
            (Judgement::Unsupported { .. }, _) => Self::Unsupported,
            (Judgement::Inconclusive { .. }, _) => Self::Inconclusive,
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One probe.
pub struct Probe {
    /// Stable id, such as `basic.put-get`.
    pub id: &'static str,
    /// The feature it belongs to.
    pub feature: &'static str,
    /// What it expects.
    pub expectation: Expectation,
    /// The requests it sends, for `proofmark explain`.
    pub requests: &'static str,
    /// The faults in the fake it catches. At least one.
    pub catches: &'static [Catch],
    /// Sends the requests.
    pub run: fn(&mut Session) -> Result<(), ProbeError>,
    /// Judges the exchanges `run` made.
    pub judge: fn(&[Exchange]) -> Judgement,
}

impl fmt::Debug for Probe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Probe")
            .field("id", &self.id)
            .field("feature", &self.feature)
            .finish_non_exhaustive()
    }
}

/// Every probe, in run order.
#[must_use]
pub fn all() -> &'static [Probe] {
    basic::PROBES
}

/// The probe with id `id`.
#[must_use]
pub fn find(id: &str) -> Option<&'static Probe> {
    all().iter().find(|p| p.id == id)
}

/// Every feature that has a probe, in run order, without repeats.
#[must_use]
pub fn features() -> Vec<&'static str> {
    let mut features: Vec<&'static str> = Vec::new();
    for probe in all() {
        if !features.contains(&probe.feature) {
            features.push(probe.feature);
        }
    }
    features
}

/// Judges what a probe saw. Any `501` makes it `unsupported` whatever the
/// judge would say: the store refused honestly.
#[must_use]
pub fn judge(probe: &Probe, exchanges: &[Exchange]) -> Judgement {
    if let Some(refused) = exchanges.iter().find(|e| e.response.status() == 501) {
        return Judgement::Unsupported {
            detail: format!(
                "{} answered 501 {}",
                refused.label,
                s3::error_code(refused.response.body()).unwrap_or_default()
            )
            .trim_end()
            .to_owned(),
        };
    }
    (probe.judge)(exchanges)
}

// Helpers for judges. Each returns `Err(judgement)` to stop at the first
// thing that is wrong, so a judge reads as a list of checks.

type Check = Result<(), Judgement>;

fn exchange<'a>(exchanges: &'a [Exchange], label: &str) -> Result<&'a Exchange, Judgement> {
    exchanges
        .iter()
        .find(|e| e.label == label)
        .ok_or_else(|| Judgement::Inconclusive {
            reason: format!("no response to the {label} request"),
        })
}

fn deviates(detail: String, silent: bool) -> Judgement {
    Judgement::Deviates { detail, silent }
}

/// `"403 AccessDenied"`, or `"403"` with no error code.
fn status_and_code(exchange: &Exchange) -> String {
    let status = exchange.response.status();
    match s3::error_code(exchange.response.body()) {
        Some(code) => format!("{status} {code}"),
        None => status.to_string(),
    }
}

fn status_is(exchange: &Exchange, want: u16) -> Check {
    if exchange.response.status() == want {
        Ok(())
    } else {
        Err(deviates(
            format!(
                "{} answered {}; expected {want}",
                exchange.label,
                status_and_code(exchange)
            ),
            false,
        ))
    }
}

/// The status and the XML error code an error response must carry.
fn error_is(exchange: &Exchange, status: u16, code: &str, silent_if_2xx: bool) -> Check {
    let got = exchange.response.status();
    let got_code = s3::error_code(exchange.response.body());
    if got == status && got_code.as_deref() == Some(code) {
        return Ok(());
    }
    let silent = silent_if_2xx && (200..300).contains(&got);
    Err(deviates(
        format!(
            "{} answered {}; expected {status} {code}",
            exchange.label,
            status_and_code(exchange)
        ),
        silent,
    ))
}

fn from_checks(result: Check) -> Judgement {
    match result {
        Ok(()) => Judgement::Matches,
        Err(judgement) => judgement,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_follows_the_table_in_adr_0003() {
        let deviates = Judgement::Deviates {
            detail: String::new(),
            silent: true,
        };
        let unsupported = Judgement::Unsupported {
            detail: String::new(),
        };
        let inconclusive = Judgement::Inconclusive {
            reason: String::new(),
        };
        for (judgement, documented, observed) in [
            (&Judgement::Matches, Status::Pass, Status::Pass),
            (&deviates, Status::Violation, Status::Difference),
            (&unsupported, Status::Unsupported, Status::Unsupported),
            (&inconclusive, Status::Inconclusive, Status::Inconclusive),
        ] {
            assert_eq!(Status::of(judgement, Basis::Documented), documented);
            assert_eq!(Status::of(judgement, Basis::Observed), observed);
        }
    }

    #[test]
    fn every_probe_is_cited_and_catches_a_fault() {
        let mut ids = std::collections::HashSet::new();
        for probe in all() {
            assert!(ids.insert(probe.id), "duplicate id {}", probe.id);
            assert!(probe.id.starts_with(&format!("{}.", probe.feature)));
            assert!(!probe.catches.is_empty(), "{} catches nothing", probe.id);
            let citation = probe.expectation.citation;
            assert!(citation.url.starts_with("https://"), "{}", probe.id);
            assert!(!citation.section.is_empty(), "{}", probe.id);
            assert_eq!(citation.read.len(), 10, "{}", probe.id);
        }
    }

    #[test]
    fn every_fault_is_caught_by_some_probe() {
        for fault in Fault::all() {
            assert!(
                all()
                    .iter()
                    .any(|p| p.catches.iter().any(|c| c.fault == fault)),
                "no probe catches {fault}"
            );
        }
    }
}
