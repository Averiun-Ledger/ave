//! API-facing bridge models.
//!
//! The bridge namespace contains transport-oriented request, response and
//! signature types together with conversions to and from the internal models.

pub mod conversions;
pub mod request;
pub mod response;
pub mod signature;

/// `u64` nanosecond timestamps as decimal strings on the wire, accepting
/// plain JSON numbers on the way in exactly when they fit in a `u64`
/// (what the old format produced). Raw integers lose precision in
/// JavaScript past 2^53; these timestamps live far beyond that.
/// Monotonic counters (sns, versions, limits) stay numeric: they can
/// never approach 2^53.
pub(crate) mod quoted_u64 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::{self, Unexpected, Visitor};

        struct StringOrNumber;

        impl Visitor<'_> for StringOrNumber {
            type Value = u64;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str(
                    "a decimal timestamp string or an exact u64 number",
                )
            }

            fn visit_str<E>(self, value: &str) -> Result<u64, E>
            where
                E: de::Error,
            {
                value.parse::<u64>().map_err(|_| {
                    de::Error::invalid_value(Unexpected::Str(value), &self)
                })
            }

            fn visit_u64<E>(self, value: u64) -> Result<u64, E>
            where
                E: de::Error,
            {
                Ok(value)
            }
        }

        deserializer.deserialize_any(StringOrNumber)
    }
}
