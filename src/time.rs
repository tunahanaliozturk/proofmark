//! UTC timestamps in the three shapes S3 uses: the SigV4 basic format
//! (`20130524T000000Z`), the HTTP date (`Fri, 24 May 2013 00:00:00 GMT`) and
//! the ISO 8601 form in XML bodies (`2013-05-24T00:00:00.000Z`).
//!
//! The calendar arithmetic is Howard Hinnant's `days_from_civil` and
//! `civil_from_days`, which are exact for the proleptic Gregorian calendar.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

const SECONDS_PER_DAY: i64 = 86_400;

/// A UTC instant with one-second resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTime {
    unix: i64,
}

struct Civil {
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    minute: i64,
    second: i64,
    weekday: usize,
}

impl UtcTime {
    /// The instant `seconds` after 1970-01-01T00:00:00Z.
    #[must_use]
    pub const fn from_unix(seconds: i64) -> Self {
        Self { unix: seconds }
    }

    /// The system clock, now.
    #[must_use]
    pub fn now() -> Self {
        let unix = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(after) => i64::try_from(after.as_secs()).unwrap_or(i64::MAX),
            Err(before) => i64::try_from(before.duration().as_secs()).map_or(i64::MIN, |s| -s),
        };
        Self { unix }
    }

    /// Seconds since 1970-01-01T00:00:00Z.
    #[must_use]
    pub const fn unix(self) -> i64 {
        self.unix
    }

    /// Parses the SigV4 basic format, `YYYYMMDDTHHMMSSZ`.
    #[must_use]
    pub fn parse_amz(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 16 || bytes[8] != b'T' || bytes[15] != b'Z' {
            return None;
        }
        let number = |range: std::ops::Range<usize>| -> Option<i64> {
            let digits = text.get(range)?;
            if digits.bytes().all(|b| b.is_ascii_digit()) {
                digits.parse().ok()
            } else {
                None
            }
        };
        let (year, month, day) = (number(0..4)?, number(4..6)?, number(6..8)?);
        let (hour, minute, second) = (number(9..11)?, number(11..13)?, number(13..15)?);
        if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        let days = days_from_civil(year, month, day);
        // Rejects 31 April and the like: the date must survive a round trip.
        if civil_from_days(days) != (year, month, day) {
            return None;
        }
        Some(Self {
            unix: days * SECONDS_PER_DAY + hour * 3600 + minute * 60 + second,
        })
    }

    fn civil(self) -> Civil {
        let days = self.unix.div_euclid(SECONDS_PER_DAY);
        let rest = self.unix.rem_euclid(SECONDS_PER_DAY);
        let (year, month, day) = civil_from_days(days);
        // 1970-01-01 was a Thursday; index 0 is Sunday.
        let weekday = usize::try_from((days + 4).rem_euclid(7)).unwrap_or(0);
        Civil {
            year,
            month,
            day,
            hour: rest / 3600,
            minute: rest % 3600 / 60,
            second: rest % 60,
            weekday,
        }
    }

    /// The SigV4 basic format, `20130524T000000Z`.
    #[must_use]
    pub fn amz(self) -> String {
        let c = self.civil();
        format!(
            "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        )
    }

    /// The date part of the SigV4 credential scope, `20130524`.
    #[must_use]
    pub fn amz_date(self) -> String {
        let c = self.civil();
        format!("{:04}{:02}{:02}", c.year, c.month, c.day)
    }

    /// The HTTP date (RFC 9110, IMF-fixdate), `Fri, 24 May 2013 00:00:00 GMT`.
    #[must_use]
    pub fn http_date(self) -> String {
        const DAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let c = self.civil();
        let month = usize::try_from(c.month - 1).map_or("???", |i| MONTHS[i % 12]);
        format!(
            "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
            DAYS[c.weekday], c.day, month, c.year, c.hour, c.minute, c.second
        )
    }

    /// The ISO 8601 form S3 puts in XML bodies, `2013-05-24T00:00:00.000Z`.
    #[must_use]
    pub fn iso8601(self) -> String {
        let c = self.civil();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.000Z",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        )
    }
}

impl fmt::Display for UtcTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.amz())
    }
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The S3 SigV4 examples use 20130524T000000Z, "Fri, 24 May 2013 00:00:00 GMT".
    const EXAMPLE: i64 = 1_369_353_600;

    #[test]
    fn formats_the_s3_example_timestamp() {
        let t = UtcTime::from_unix(EXAMPLE);
        assert_eq!(t.amz(), "20130524T000000Z");
        assert_eq!(t.amz_date(), "20130524");
        assert_eq!(t.http_date(), "Fri, 24 May 2013 00:00:00 GMT");
        assert_eq!(t.iso8601(), "2013-05-24T00:00:00.000Z");
    }

    #[test]
    fn parses_what_it_formats() {
        for unix in [0, EXAMPLE, 951_782_400, 4_107_542_399, 1_440_938_160] {
            let t = UtcTime::from_unix(unix);
            assert_eq!(UtcTime::parse_amz(&t.amz()), Some(t), "{unix}");
        }
    }

    #[test]
    fn handles_leap_days_and_the_epoch() {
        assert_eq!(
            UtcTime::from_unix(0).http_date(),
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );
        assert_eq!(
            UtcTime::parse_amz("20000229T000000Z").map(UtcTime::unix),
            Some(951_782_400)
        );
        assert_eq!(UtcTime::parse_amz("19000229T000000Z"), None);
        assert_eq!(UtcTime::parse_amz("20150431T000000Z"), None);
    }

    #[test]
    fn rejects_malformed_amz_dates() {
        for bad in [
            "",
            "20130524T000000",
            "20130524 000000Z",
            "2013052AT000000Z",
            "20131324T000000Z",
            "20130524T240000Z",
            "20130524T006000Z",
            "+0130524T000000Z",
            "20130524T00000\u{e9}Z",
        ] {
            assert_eq!(UtcTime::parse_amz(bad), None, "{bad:?}");
        }
    }
}
