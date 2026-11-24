//! Strict RFC 3339 UTC timestamp parsing and formatting (Wire Format §1.6).

use chrono::{DateTime, NaiveDate, SecondsFormat, Utc};
use thiserror::Error;

/// The largest representable RFC 3339 timestamp (`9999-12-31T23:59:59.999Z`).
pub const MAX_TIME_MS: u64 = 253_402_300_799_999;

/// Timestamp parsing errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TimeError {
    /// Input does not conform to the Wire Format §1.6 RFC 3339 UTC grammar.
    #[error("invalid RFC 3339 UTC timestamp")]
    InvalidFormat,
    /// Input represents a timestamp before 1970-01-01T00:00:00Z.
    #[error("timestamp is before Unix epoch")]
    BeforeEpoch,
}

/// Formats Unix milliseconds as RFC 3339 UTC with three fractional digits
/// (e.g. `2026-01-01T00:06:00.000Z`).
#[must_use]
pub fn format_rfc3339(ms: u64) -> String {
    let clamped = i64::try_from(ms.min(MAX_TIME_MS)).unwrap_or(0);
    DateTime::<Utc>::from_timestamp_millis(clamped)
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Parses a strict Wire Format §1.6 RFC 3339 UTC timestamp into Unix milliseconds.
///
/// Grammar: `YYYY-MM-DDTHH:MM:SS[.F]Z` with uppercase `T` and `Z`, and an optional
/// fractional part of 1 to 9 ASCII digits. Sub-millisecond digits are truncated, not
/// rounded. Leap seconds (`:60`), invalid calendar dates, non-`Z` offsets, and times
/// before 1970 are rejected.
///
/// # Errors
///
/// Returns [`TimeError`] if the string is outside the grammar or before 1970.
pub fn parse_rfc3339(text: &str) -> Result<u64, TimeError> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes.last() != Some(&b'Z') {
        return Err(TimeError::InvalidFormat);
    }

    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators.iter().any(|(i, c)| bytes.get(*i) != Some(c)) {
        return Err(TimeError::InvalidFormat);
    }

    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let slice = bytes.get(range)?;
        if !slice.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(slice).ok()?.parse().ok()
    };

    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        digits(0..4),
        digits(5..7),
        digits(8..10),
        digits(11..13),
        digits(14..16),
        digits(17..19),
    ) else {
        return Err(TimeError::InvalidFormat);
    };

    let fraction_slice = bytes
        .get(19..bytes.len() - 1)
        .ok_or(TimeError::InvalidFormat)?;
    let fraction_ms = match fraction_slice {
        [] => 0u64,
        [b'.', fraction @ ..] => {
            if fraction.is_empty() || fraction.len() > 9 || !fraction.iter().all(u8::is_ascii_digit)
            {
                return Err(TimeError::InvalidFormat);
            }
            fraction
                .iter()
                .chain(std::iter::repeat(&b'0'))
                .take(3)
                .fold(0u64, |acc, d| acc * 10 + u64::from(d - b'0'))
        }
        _ => return Err(TimeError::InvalidFormat),
    };

    if hour > 23 || minute > 59 || second > 59 {
        return Err(TimeError::InvalidFormat);
    }

    let year_i32 = i32::try_from(year).map_err(|_| TimeError::InvalidFormat)?;
    let date = NaiveDate::from_ymd_opt(year_i32, month, day).ok_or(TimeError::InvalidFormat)?;
    let datetime = date
        .and_hms_opt(hour, minute, second)
        .ok_or(TimeError::InvalidFormat)?;

    let secs = u64::try_from(datetime.and_utc().timestamp()).map_err(|_| TimeError::BeforeEpoch)?;
    secs.checked_mul(1_000)
        .and_then(|ms| ms.checked_add(fraction_ms))
        .ok_or(TimeError::InvalidFormat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_rfc3339_variants_and_truncates_sub_ms() {
        assert_eq!(
            parse_rfc3339("2026-01-01T00:06:00.000Z").unwrap(),
            1_767_225_960_000
        );
        assert_eq!(
            parse_rfc3339("2026-01-01T00:06:00Z").unwrap(),
            1_767_225_960_000
        );
        assert_eq!(
            parse_rfc3339("2026-01-01T00:06:00.5Z").unwrap(),
            1_767_225_960_500
        );
        assert_eq!(
            parse_rfc3339("2026-01-01T00:06:00.999999999Z").unwrap(),
            1_767_225_960_999
        );
        assert_eq!(
            format_rfc3339(1_767_225_960_000),
            "2026-01-01T00:06:00.000Z"
        );
    }

    #[test]
    fn rejects_invalid_timestamps() {
        for bad in [
            "",
            "2026-01-01T00:00:60Z",
            "2026-02-30T00:00:00Z",
            "2026-01-01T00:00:00.Z",
            "2026-01-01T00:00:00.1234567890Z",
            "2026-01-01 00:00:00Z",
            "2026-01-01t00:00:00Z",
            "2026-01-01T00:00:00z",
            "2026-01-01T00:00:00+00:00",
            "1969-12-31T23:59:59Z",
        ] {
            assert!(parse_rfc3339(bad).is_err(), "expected error for {bad:?}");
        }
    }
}
