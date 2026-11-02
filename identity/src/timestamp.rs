//! Timestamp helpers used by signed values.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Nanoseconds since the Unix epoch.
///
/// JSON representation is always a decimal string: raw integers lose
/// precision in JavaScript past 2^53, and these timestamps live far
/// beyond that. Deserialization also accepts plain JSON numbers that
/// fit in a `u64` exactly (what the old format produced), so existing
/// payloads keep verifying.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct TimeStamp(u64);

impl TimeStamp {
    /// Returns the current UTC timestamp in nanoseconds.
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc().unix_timestamp_nanos() as u64)
    }

    /// Builds a timestamp from raw nanoseconds since the Unix epoch.
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// Returns the raw nanosecond value.
    pub const fn as_nanos(&self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for TimeStamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for TimeStamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for TimeStamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Unexpected, Visitor};

        struct StringOrNumber;

        impl Visitor<'_> for StringOrNumber {
            type Value = TimeStamp;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str(
                    "a decimal timestamp string or an exact u64 number",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<TimeStamp, E>
            where
                E: de::Error,
            {
                value.parse::<u64>().map(TimeStamp).map_err(|_| {
                    de::Error::invalid_value(Unexpected::Str(value), &self)
                })
            }

            fn visit_u64<E>(self, value: u64) -> Result<TimeStamp, E>
            where
                E: de::Error,
            {
                Ok(TimeStamp(value))
            }
        }

        deserializer.deserialize_any(StringOrNumber)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timestamp_from_nanos_zero() {
        let ts = TimeStamp::from_nanos(0);
        assert_eq!(ts.as_nanos(), 0);
        assert_eq!(format!("{}", ts), "0");
    }
}

#[cfg(test)]
mod json_tests {
    use super::*;

    #[test]
    fn timestamp_serializes_as_decimal_string() {
        let ts = TimeStamp::from_nanos(1792022400123456789);
        let json = serde_json::to_string(&ts).unwrap();
        assert_eq!(json, "\"1792022400123456789\"");
    }

    #[test]
    fn timestamp_accepts_string_and_exact_number() {
        let from_string: TimeStamp =
            serde_json::from_str("\"1792022400123456789\"").unwrap();
        assert_eq!(from_string.as_nanos(), 1792022400123456789);
        let from_number: TimeStamp = serde_json::from_str("123").unwrap();
        assert_eq!(from_number.as_nanos(), 123);
    }

    #[test]
    fn timestamp_rejects_garbage() {
        assert!(serde_json::from_str::<TimeStamp>("\"abc\"").is_err());
        assert!(serde_json::from_str::<TimeStamp>("\"-1\"").is_err());
        assert!(serde_json::from_str::<TimeStamp>("1.5").is_err());
        assert!(serde_json::from_str::<TimeStamp>("-1").is_err());
    }
}
