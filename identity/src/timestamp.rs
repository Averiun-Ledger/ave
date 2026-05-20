//! Timestamp helpers used by signed values.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Nanoseconds since the Unix epoch.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
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
