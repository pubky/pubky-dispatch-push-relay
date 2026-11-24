//! Strict JSON validation per Wire Format §1.1.
//!
//! Rejects UTF-8 BOMs, trailing non-whitespace tokens, duplicate object keys at any depth
//! (compared after JSON unescaping), lone surrogates, and numbers outside integer range
//! `0..=2^53 - 1` (including negative numbers, fractions, and exponents).

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use thiserror::Error;

/// Largest permitted JSON integer (`2^53 - 1`) per Wire Format §1.1.
pub const MAX_SAFE_INT: u64 = (1 << 53) - 1;

/// Errors produced when validating or parsing strict JSON.
#[derive(Debug, Error)]
pub enum JsonError {
    /// Input started with a UTF-8 byte order mark.
    #[error("JSON must not start with a UTF-8 BOM")]
    ByteOrderMark,
    /// Input failed strict JSON validation or deserialization.
    #[error("invalid JSON: {0}")]
    Invalid(String),
}

/// Validates that `bytes` represent a single strict Wire Format §1.1 JSON value.
///
/// # Errors
///
/// Returns [`JsonError`] if any Wire Format §1.1 rule is violated.
pub fn check_strict_json(bytes: &[u8]) -> Result<(), JsonError> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(JsonError::ByteOrderMark);
    }

    let mut de = serde_json::Deserializer::from_slice(bytes);
    StrictSeed
        .deserialize(&mut de)
        .map_err(|e| JsonError::Invalid(e.to_string()))?;
    de.end().map_err(|e| JsonError::Invalid(e.to_string()))?;
    Ok(())
}

/// Validates `bytes` against Wire Format §1.1 and deserializes `T`.
///
/// # Errors
///
/// Returns [`JsonError`] if validation or deserialization fails.
pub fn parse_strict_json<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, JsonError> {
    check_strict_json(bytes)?;
    serde_json::from_slice(bytes).map_err(|e| JsonError::Invalid(e.to_string()))
}

struct StrictSeed;

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a strict JSON value")
    }

    fn visit_bool<E>(self, _v: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v < 0 {
            return Err(E::custom("negative JSON integer is not permitted"));
        }
        let u = u64::try_from(v).map_err(|_| E::custom("JSON integer out of range"))?;
        self.visit_u64(u)
    }

    fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v > MAX_SAFE_INT {
            return Err(E::custom("JSON integer exceeds 2^53 - 1"));
        }
        Ok(())
    }

    fn visit_f64<E>(self, _v: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom(
            "JSON numbers must be unsigned integers without fraction or exponent",
        ))
    }

    fn visit_str<E>(self, _v: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while seq.next_element_seed(StrictSeed)?.is_some() {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key) {
                return Err(de::Error::custom("duplicate JSON object member name"));
            }
            map.next_value_seed(StrictSeed)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_strict_json() {
        assert!(check_strict_json(br#"{"v":1,"a":[0,9007199254740991],"b":null}"#).is_ok());
        assert!(check_strict_json(b"{\"v\":1}  \n\t").is_ok());
    }

    #[test]
    fn rejects_bom_duplicates_trailing_and_bad_numbers() {
        let mut with_bom = vec![0xEF, 0xBB, 0xBF];
        with_bom.extend_from_slice(br#"{"v":1}"#);
        assert!(matches!(
            check_strict_json(&with_bom),
            Err(JsonError::ByteOrderMark)
        ));

        for bad in [
            br#"{"v":1,"v":1}"#.as_slice(),
            br#"{"v":1,"\u0076":1}"#.as_slice(),
            br#"{"nested":{"a":1,"\u0061":2}}"#.as_slice(),
            br#"{"v":1.0}"#.as_slice(),
            br#"{"v":1e0}"#.as_slice(),
            br#"{"v":-1}"#.as_slice(),
            br#"{"v":9007199254740992}"#.as_slice(),
            br#"{"v":1} trailing"#.as_slice(),
            br#"{"s":"\ud800"}"#.as_slice(),
        ] {
            assert!(
                check_strict_json(bad).is_err(),
                "expected rejection for {}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
