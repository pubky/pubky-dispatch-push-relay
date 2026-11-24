//! Strict RFC 3339 UTC timestamp parsing and formatting (Wire Format §1.6).

use thiserror::Error;

/// The largest representable RFC 3339 timestamp (`9999-12-31T23:59:59.999Z`).
pub const MAX_TIME_MS: u64 = 253_402_300_799_999;

const SECS_PER_DAY: i64 = 86_400;

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
    let clamped = ms.min(MAX_TIME_MS);
    let total_secs = i64::try_from(clamped / 1_000).unwrap_or(0);
    let millis = clamped % 1_000;
    let days = total_secs.div_euclid(SECS_PER_DAY);
    let secs_of_day = u64::try_from(total_secs.rem_euclid(SECS_PER_DAY)).unwrap_or(0);

    let (year, month, day) = civil_from_days(days);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
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

    let max_day = days_in_month(year, month).ok_or(TimeError::InvalidFormat)?;
    if day == 0 || day > max_day {
        return Err(TimeError::InvalidFormat);
    }

    let days = days_from_civil(year, month, day);
    let secs_i64 = days
        .checked_mul(SECS_PER_DAY)
        .and_then(|s| {
            s.checked_add(i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second))
        })
        .ok_or(TimeError::InvalidFormat)?;

    let secs = u64::try_from(secs_i64).map_err(|_| TimeError::BeforeEpoch)?;
    secs.checked_mul(1_000)
        .and_then(|ms| ms.checked_add(fraction_ms))
        .ok_or(TimeError::InvalidFormat)
}

const fn is_leap_year(year: u32) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

const fn days_in_month(year: u32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if is_leap_year(year) { 29 } else { 28 }),
        _ => None,
    }
}

/// Converts a validated proleptic Gregorian date to days since 1970-01-01 (Howard Hinnant).
const fn days_from_civil(year: u32, month: u32, day: u32) -> i64 {
    let y = (year as i64) - if month <= 2 { 1 } else { 0 };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = month as i64;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + (day as i64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Converts days since 1970-01-01 to `(year, month, day)` in the proleptic Gregorian calendar.
const fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_rfc3339_variants_and_truncates_sub_ms() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00.000Z");

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

        // Leap years (2000 divisible by 400; 2024 divisible by 4) and MAX_TIME_MS.
        assert_eq!(
            format_rfc3339(parse_rfc3339("2000-02-29T12:34:56.789Z").unwrap()),
            "2000-02-29T12:34:56.789Z"
        );
        assert_eq!(
            format_rfc3339(parse_rfc3339("2024-02-29T23:59:59.001Z").unwrap()),
            "2024-02-29T23:59:59.001Z"
        );
        assert_eq!(
            parse_rfc3339("9999-12-31T23:59:59.999Z").unwrap(),
            MAX_TIME_MS
        );
        assert_eq!(format_rfc3339(MAX_TIME_MS), "9999-12-31T23:59:59.999Z");
    }

    #[test]
    fn rejects_invalid_timestamps() {
        for bad in [
            "",
            "2026-01-01T00:00:60Z",
            "2026-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-01-00T00:00:00Z",
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
