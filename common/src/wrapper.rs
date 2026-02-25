use std::{
    io::{Read, Write},
    ops::Deref,
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

// Maximum recursion depth for deserializing nested structures
// Prevents stack overflow from deeply nested JSON/Borsh data
const MAX_RECURSION_DEPTH: usize = 128;

// Maximum array/object length to prevent memory exhaustion
const MAX_COLLECTION_SIZE: u32 = 100_000;

/// Wrapper for `serde_json::Value` that implements `BorshSerialize` and `BorshDeserialize`.
///
/// This type bridges the gap between JSON-based state/event representations and the
/// efficient Borsh binary serialization format used for WASM boundary crossings.
/// It allows contract states and events (which are JSON-compatible) to be efficiently
/// transferred between the WASM module and the host runtime.
///
/// The wrapper handles all JSON value types:
/// - Bool: Boolean values
/// - Number: Numeric values (f64, i64, u64)
/// - String: Text values
/// - Array: Ordered collections of values
/// - Object: Key-value maps
/// - Null: Null values
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct ValueWrapper(pub Value);

impl Deref for ValueWrapper {
    type Target = Value;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Default for ValueWrapper {
    fn default() -> Self {
        Self(Value::Null)
    }
}

/// Borsh serialization implementation for `ValueWrapper`.
///
/// Serializes JSON values into an efficient binary format using type tags.
/// Each JSON type is prefixed with a discriminator byte to identify its type:
/// - 0: Boolean
/// - 1: Number (with sub-discriminator for f64=0, i64=1, u64=2)
/// - 2: String
/// - 3: Array
/// - 4: Object
/// - 5: Null
impl BorshSerialize for ValueWrapper {
    #[inline]
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match &self.0 {
            // Serialize boolean: type tag (0) + boolean value
            Value::Bool(data) => {
                BorshSerialize::serialize(&0u8, writer)?;
                BorshSerialize::serialize(&data, writer)
            }
            // Serialize number: type tag (1) + numeric sub-type tag + value
            Value::Number(data) => {
                BorshSerialize::serialize(&1u8, writer)?;
                'data: {
                    // Try f64 first
                    if data.is_f64() {
                        let Some(data) = data.as_f64() else {
                            break 'data;
                        };
                        BorshSerialize::serialize(&0u8, writer)?;
                        return BorshSerialize::serialize(&data, writer);
                    }
                    // Try i64
                    else if data.is_i64() {
                        let Some(data) = data.as_i64() else {
                            break 'data;
                        };
                        BorshSerialize::serialize(&1u8, writer)?;
                        return BorshSerialize::serialize(&data, writer);
                    }
                    // Try u64
                    else if data.is_u64() {
                        let Some(data) = data.as_u64() else {
                            break 'data;
                        };
                        BorshSerialize::serialize(&2u8, writer)?;
                        return BorshSerialize::serialize(&data, writer);
                    }
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid number type",
                ))
            }
            // Serialize string: type tag (2) + string data
            Value::String(data) => {
                BorshSerialize::serialize(&2u8, writer)?;
                BorshSerialize::serialize(&data, writer)
            }
            // Serialize array: type tag (3) + length + elements
            Value::Array(data) => {
                BorshSerialize::serialize(&3u8, writer)?;
                // Check array length fits in u32
                let len = u32::try_from(data.len()).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Array too large to serialize: {} elements exceeds u32::MAX",
                            data.len()
                        ),
                    )
                })?;
                BorshSerialize::serialize(&len, writer)?;
                for element in data {
                    let element = Self(element.to_owned());
                    BorshSerialize::serialize(&element, writer)?;
                }
                Ok(())
            }
            // Serialize object: type tag (4) + length + key-value pairs
            Value::Object(data) => {
                BorshSerialize::serialize(&4u8, writer)?;
                // Check object length fits in u32
                let len = u32::try_from(data.len()).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Object too large to serialize: {} keys exceeds u32::MAX",
                            data.len()
                        ),
                    )
                })?;
                BorshSerialize::serialize(&len, writer)?;
                for (key, value) in data {
                    BorshSerialize::serialize(&key, writer)?;
                    let value = Self(value.to_owned());
                    BorshSerialize::serialize(&value, writer)?;
                }
                Ok(())
            }
            // Serialize null: just type tag (5)
            Value::Null => BorshSerialize::serialize(&5u8, writer),
        }
    }
}

/// Borsh deserialization implementation for `ValueWrapper`.
///
/// Deserializes binary Borsh data back into JSON values by reading type discriminators
/// and reconstructing the appropriate JSON value type. This is the inverse of the
/// serialization process.
///
/// The type tags used are:
/// - 0: Boolean
/// - 1: Number (with sub-discriminator for f64=0, i64=1, u64=2)
/// - 2: String
/// - 3: Array
/// - 4: Object
/// - 5: Null
impl ValueWrapper {
    /// Internal deserialization with recursion depth tracking.
    ///
    /// This prevents stack overflow attacks from deeply nested structures.
    fn deserialize_reader_with_depth<R: Read>(
        reader: &mut R,
        depth: usize,
    ) -> std::io::Result<Self> {
        if depth > MAX_RECURSION_DEPTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Recursion depth limit exceeded: maximum depth is {}",
                    MAX_RECURSION_DEPTH
                ),
            ));
        }

        // Read the type discriminator byte
        let order: u8 = BorshDeserialize::deserialize_reader(reader)?;
        match order {
            // Type 0: Boolean
            0 => {
                let data: bool = BorshDeserialize::deserialize_reader(reader)?;
                Ok(Self(Value::Bool(data)))
            }
            // Type 1: Number (requires reading numeric sub-type)
            1 => {
                let internal_order: u8 =
                    BorshDeserialize::deserialize_reader(reader)?;
                match internal_order {
                    // Sub-type 0: f64
                    0 => {
                        let data: f64 =
                            BorshDeserialize::deserialize_reader(reader)?;
                        let Some(data_f64) = Number::from_f64(data) else {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!("Invalid f64 Number: {}", data),
                            ));
                        };
                        Ok(Self(Value::Number(data_f64)))
                    }
                    // Sub-type 1: i64
                    1 => {
                        let data: i64 =
                            BorshDeserialize::deserialize_reader(reader)?;
                        Ok(Self(Value::Number(Number::from(data))))
                    }
                    // Sub-type 2: u64
                    2 => {
                        let data: u64 =
                            BorshDeserialize::deserialize_reader(reader)?;
                        Ok(Self(Value::Number(Number::from(data))))
                    }
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Invalid Number representation: {}",
                            internal_order
                        ),
                    )),
                }
            }
            // Type 2: String
            2 => {
                let data: String =
                    BorshDeserialize::deserialize_reader(reader)?;
                Ok(Self(Value::String(data)))
            }
            // Type 3: Array (read length, then elements)
            3 => {
                let len = u32::deserialize_reader(reader)?;

                // Security check: prevent excessive array sizes
                if len > MAX_COLLECTION_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Array size too large: {} exceeds maximum of {}",
                            len, MAX_COLLECTION_SIZE
                        ),
                    ));
                }

                if len == 0 {
                    Ok(Self(Value::Array(Vec::new())))
                } else {
                    let mut result = Vec::with_capacity(len as usize);
                    // Use checked arithmetic to prevent depth overflow
                    let next_depth = depth.checked_add(1).ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Recursion depth counter overflow",
                        )
                    })?;
                    for _ in 0..len {
                        result.push(
                            Self::deserialize_reader_with_depth(
                                reader, next_depth,
                            )?
                            .0,
                        );
                    }
                    Ok(Self(Value::Array(result)))
                }
            }
            // Type 4: Object (read length, then key-value pairs)
            4 => {
                let len = u32::deserialize_reader(reader)?;

                // Security check: prevent excessive object sizes
                if len > MAX_COLLECTION_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Object size too large: {} exceeds maximum of {}",
                            len, MAX_COLLECTION_SIZE
                        ),
                    ));
                }

                let mut result = Map::new();
                // Use checked arithmetic to prevent depth overflow
                let next_depth = depth.checked_add(1).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Recursion depth counter overflow",
                    )
                })?;
                for _ in 0..len {
                    let key = String::deserialize_reader(reader)?;
                    let value = Self::deserialize_reader_with_depth(
                        reader, next_depth,
                    )?;
                    result.insert(key, value.0);
                }
                Ok(Self(Value::Object(result)))
            }
            // Type 5: Null
            5 => Ok(Self(Value::Null)),
            // Unknown type discriminator
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid Value representation: {}", order),
            )),
        }
    }
}

impl BorshDeserialize for ValueWrapper {
    #[inline]
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        // Start deserialization with depth 0
        Self::deserialize_reader_with_depth(reader, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // Basic serialization round-trip: string values
    #[test]
    fn test_value_wrapper_string() {
        let value = ValueWrapper(Value::String("test".to_owned()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Basic serialization round-trip: boolean values (true/false)
    #[test]
    fn test_value_wrapper_bool() {
        let value = ValueWrapper(Value::Bool(true));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);

        let value_false = ValueWrapper(Value::Bool(false));
        let vec_false = borsh::to_vec(&value_false).unwrap();
        let value2_false: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec_false).unwrap();
        assert_eq!(value_false, value2_false);
    }

    // Basic serialization round-trip: f64 numbers
    #[test]
    fn test_value_wrapper_number_f64() {
        let value =
            ValueWrapper(Value::Number(Number::from_f64(3.14).unwrap()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Basic serialization round-trip: i64 numbers (negative values)
    #[test]
    fn test_value_wrapper_number_i64() {
        let value = ValueWrapper(Value::Number(Number::from(-42i64)));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Basic serialization round-trip: u64 numbers (positive values)
    #[test]
    fn test_value_wrapper_number_u64() {
        let value = ValueWrapper(Value::Number(Number::from(12345u64)));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Basic serialization round-trip: null values
    #[test]
    fn test_value_wrapper_null() {
        let value = ValueWrapper(Value::Null);
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Arrays with mixed types serialize correctly
    #[test]
    fn test_value_wrapper_array() {
        let value = ValueWrapper(Value::Array(vec![
            Value::Bool(true),
            Value::String("test".to_owned()),
            Value::Number(Number::from(42)),
            Value::Null,
        ]));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Empty arrays are handled correctly
    #[test]
    fn test_value_wrapper_empty_array() {
        let value = ValueWrapper(Value::Array(vec![]));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Objects with string keys and mixed value types
    #[test]
    fn test_value_wrapper_object() {
        let mut map = Map::new();
        map.insert("name".to_string(), Value::String("Alice".to_owned()));
        map.insert("age".to_string(), Value::Number(Number::from(30)));
        map.insert("active".to_string(), Value::Bool(true));

        let value = ValueWrapper(Value::Object(map));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Empty objects are handled correctly
    #[test]
    fn test_value_wrapper_empty_object() {
        let value = ValueWrapper(Value::Object(Map::new()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Nested structures (objects within objects, arrays within objects)
    #[test]
    fn test_value_wrapper_nested_structure() {
        let mut inner_map = Map::new();
        inner_map.insert("x".to_string(), Value::Number(Number::from(1)));
        inner_map.insert("y".to_string(), Value::Number(Number::from(2)));

        let mut outer_map = Map::new();
        outer_map.insert("point".to_string(), Value::Object(inner_map));
        outer_map.insert(
            "values".to_string(),
            Value::Array(vec![
                Value::Number(Number::from(1)),
                Value::Number(Number::from(2)),
                Value::Number(Number::from(3)),
            ]),
        );

        let value = ValueWrapper(Value::Object(outer_map));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Accepts structures at max recursion depth (128 levels)
    #[test]
    fn test_value_wrapper_max_recursion_depth() {
        let mut value = Value::Null;
        for _ in 0..MAX_RECURSION_DEPTH {
            value = Value::Array(vec![value]);
        }

        let wrapper = ValueWrapper(value);
        let vec = borsh::to_vec(&wrapper).unwrap();

        let result: Result<ValueWrapper, _> =
            BorshDeserialize::try_from_slice(&vec);
        assert!(result.is_ok());
    }

    // Rejects structures exceeding max recursion depth (prevents stack overflow)
    #[test]
    fn test_value_wrapper_exceeds_recursion_depth() {
        let mut value = Value::Null;
        for _ in 0..=MAX_RECURSION_DEPTH {
            value = Value::Array(vec![value]);
        }

        let wrapper = ValueWrapper(value);
        let vec = borsh::to_vec(&wrapper).unwrap();

        let result: Result<ValueWrapper, _> =
            BorshDeserialize::try_from_slice(&vec);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Recursion depth limit exceeded")
        );
    }

    // Accepts arrays at max collection size (100,000 elements)
    #[test]
    fn test_value_wrapper_large_array() {
        let large_array = vec![Value::Null; MAX_COLLECTION_SIZE as usize];
        let value = ValueWrapper(Value::Array(large_array));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Rejects arrays exceeding max size (prevents memory exhaustion)
    #[test]
    fn test_value_wrapper_array_size_overflow() {
        let mut bytes = vec![3u8]; // Type tag for Array
        let oversized_len = MAX_COLLECTION_SIZE + 1;
        bytes.extend_from_slice(&oversized_len.to_le_bytes());

        let result: Result<ValueWrapper, _> =
            BorshDeserialize::try_from_slice(&bytes);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Array size too large")
        );
    }

    // Rejects objects exceeding max size (prevents memory exhaustion)
    #[test]
    fn test_value_wrapper_object_size_overflow() {
        let mut bytes = vec![4u8]; // Type tag for Object
        let oversized_len = MAX_COLLECTION_SIZE + 1;
        bytes.extend_from_slice(&oversized_len.to_le_bytes());

        let result: Result<ValueWrapper, _> =
            BorshDeserialize::try_from_slice(&bytes);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Object size too large")
        );
    }

    // Rejects unknown type discriminators (valid: 0-5)
    #[test]
    fn test_value_wrapper_invalid_type_tag() {
        let bytes = vec![6u8];

        let result: Result<ValueWrapper, _> =
            BorshDeserialize::try_from_slice(&bytes);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid Value representation")
        );
    }

    // Rejects invalid number sub-types (valid: 0=f64, 1=i64, 2=u64)
    #[test]
    fn test_value_wrapper_invalid_number_type() {
        let bytes = vec![1u8, 3u8];

        let result: Result<ValueWrapper, _> =
            BorshDeserialize::try_from_slice(&bytes);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid Number representation")
        );
    }

    // Unicode strings (multi-byte characters, emojis) are handled correctly
    #[test]
    fn test_value_wrapper_unicode_strings() {
        let value = ValueWrapper(Value::String("Hello 世界 🌍".to_owned()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Empty strings are valid
    #[test]
    fn test_value_wrapper_empty_string() {
        let value = ValueWrapper(Value::String(String::new()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Special float values: +0.0 and -0.0 are valid (but NaN/Infinity are not)
    #[test]
    fn test_value_wrapper_special_floats() {
        let value = ValueWrapper(Value::Number(Number::from_f64(0.0).unwrap()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);

        let value =
            ValueWrapper(Value::Number(Number::from_f64(-0.0).unwrap()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper =
            BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    // Clone trait works correctly
    #[test]
    fn test_value_wrapper_clone() {
        let value = ValueWrapper(Value::String("test".to_owned()));
        let cloned = value.clone();
        assert_eq!(value, cloned);
    }

    // Debug trait produces readable output
    #[test]
    fn test_value_wrapper_debug() {
        let value = ValueWrapper(Value::String("test".to_owned()));
        let debug_str = format!("{:?}", value);
        assert!(debug_str.contains("test"));
    }

    // Deref trait allows direct access to Value methods
    #[test]
    fn test_value_wrapper_as_str() {
        let value = ValueWrapper(Value::String("hello".to_owned()));
        assert_eq!(value.as_str(), Some("hello"));

        let non_string = ValueWrapper(Value::Number(Number::from(42)));
        assert_eq!(non_string.as_str(), None);
    }

    // Object key access via Deref (get method)
    #[test]
    fn test_value_wrapper_get() {
        let mut map = Map::new();
        map.insert("name".to_string(), Value::String("Alice".to_owned()));
        map.insert("age".to_string(), Value::Number(Number::from(30)));

        let value = ValueWrapper(Value::Object(map));
        assert_eq!(value.get("name"), Some(&Value::String("Alice".to_owned())));
        assert_eq!(value.get("age"), Some(&Value::Number(Number::from(30))));
        assert_eq!(value.get("missing"), None);

        let non_object =
            ValueWrapper(Value::String("not an object".to_owned()));
        assert_eq!(non_object.get("key"), None);
    }

    // Deref allows calling Value type-checking methods
    #[test]
    fn test_value_wrapper_deref() {
        let value = ValueWrapper(Value::String("test".to_owned()));
        assert!(value.is_string());
        assert!(!value.is_number());

        let number = ValueWrapper(Value::Number(Number::from(42)));
        assert!(number.is_number());
        assert!(!number.is_string());
    }

    // Default produces Null value
    #[test]
    fn test_value_wrapper_default() {
        let value = ValueWrapper::default();
        assert_eq!(value.0, Value::Null);
        assert!(value.is_null());
    }

    // Hash trait allows use in HashMap/HashSet
    #[test]
    fn test_value_wrapper_hash() {
        use std::collections::HashMap;

        let wrapper1 = ValueWrapper(Value::String("key1".to_owned()));
        let wrapper2 = ValueWrapper(Value::String("key2".to_owned()));

        let mut map = HashMap::new();
        map.insert(wrapper1.clone(), "value1");
        map.insert(wrapper2.clone(), "value2");

        assert_eq!(map.get(&wrapper1), Some(&"value1"));
        assert_eq!(map.get(&wrapper2), Some(&"value2"));
    }

    // Helper: deserialize from raw bytes
    fn deser(bytes: Vec<u8>) -> std::io::Result<ValueWrapper> {
        let mut c = Cursor::new(bytes);
        ValueWrapper::deserialize_reader(&mut c)
    }

    // Helper: push single byte (type discriminators)
    fn push_u8(buf: &mut Vec<u8>, v: u8) {
        buf.push(v);
    }

    // Helper: push u32 in little-endian (collection lengths)
    fn push_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    // Helper: push i64 in little-endian (signed integers)
    fn push_i64(buf: &mut Vec<u8>, v: i64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    // Helper: push u64 in little-endian (unsigned integers)
    fn push_u64(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    // Helper: push f64 in little-endian (floating point numbers)
    fn push_f64(buf: &mut Vec<u8>, v: f64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    // Helper: push Borsh-encoded string (u32 length + UTF-8 bytes)
    fn push_borsh_string(buf: &mut Vec<u8>, s: &str) {
        let b = s.as_bytes();
        push_u32(buf, b.len() as u32);
        buf.extend_from_slice(b);
    }

    // Rejects invalid type discriminator (255 is not in 0-5 range)
    #[test]
    fn rejects_unknown_discriminator() {
        let bytes = vec![255u8];
        assert!(deser(bytes).is_err());
    }

    // Rejects invalid number sub-type (99 is not in 0-2 range)
    #[test]
    fn rejects_number_unknown_internal_order() {
        let mut bytes = Vec::new();
        push_u8(&mut bytes, 1); // Type: Number
        push_u8(&mut bytes, 99); // invalid sub-type
        assert!(deser(bytes).is_err());
    }

    // Rejects NaN values (not representable in JSON)
    #[test]
    fn rejects_nan_f64_number() {
        let mut bytes = Vec::new();
        push_u8(&mut bytes, 1); // Type: Number
        push_u8(&mut bytes, 0); // Sub-type: f64
        push_f64(&mut bytes, f64::NAN);
        assert!(deser(bytes).is_err());
    }

    // Rejects Infinity values (not representable in JSON)
    #[test]
    fn rejects_infinite_f64_number() {
        let mut bytes = Vec::new();
        push_u8(&mut bytes, 1); // Type: Number
        push_u8(&mut bytes, 0); // Sub-type: f64
        push_f64(&mut bytes, f64::INFINITY);
        assert!(deser(bytes).is_err());
    }

    // Rejects array length header exceeding MAX_COLLECTION_SIZE
    #[test]
    fn rejects_array_too_large() {
        let mut bytes = Vec::new();
        push_u8(&mut bytes, 3); // Type: Array
        let len = (MAX_COLLECTION_SIZE as u32) + 1;
        push_u32(&mut bytes, len);
        assert!(deser(bytes).is_err());
    }

    // Rejects object length header exceeding MAX_COLLECTION_SIZE
    #[test]
    fn rejects_object_too_large() {
        let mut bytes = Vec::new();
        push_u8(&mut bytes, 4); // Type: Object
        let len = (MAX_COLLECTION_SIZE as u32) + 1;
        push_u32(&mut bytes, len);
        assert!(deser(bytes).is_err());
    }

    // Rejects deeply nested arrays exceeding recursion limit
    #[test]
    fn rejects_recursion_depth_exceeded_nested_arrays() {
        let mut bytes = Vec::new();

        let levels = (MAX_RECURSION_DEPTH as usize) + 2;
        for _ in 0..levels {
            push_u8(&mut bytes, 3); // Array
            push_u32(&mut bytes, 1); // len=1
        }
        push_u8(&mut bytes, 5); // Null

        assert!(deser(bytes).is_err());
    }

    // Rejects invalid UTF-8 byte sequences in strings
    #[test]
    fn rejects_invalid_utf8_string() {
        let mut bytes = Vec::new();
        push_u8(&mut bytes, 2); // Type: String
        push_u32(&mut bytes, 1); // length=1
        bytes.push(0xFF); // invalid UTF-8 byte

        assert!(deser(bytes).is_err());
    }

    // Rejects incomplete f64 value (missing 8 bytes)
    #[test]
    fn rejects_truncated_payload_mid_value() {
        let mut bytes = Vec::new();
        push_u8(&mut bytes, 1); // Number
        push_u8(&mut bytes, 0); // f64
        // missing 8 bytes for f64 value
        assert!(deser(bytes).is_err());
    }

    // Rejects object with incomplete key-value pair (truncated value)
    #[test]
    fn rejects_object_with_truncated_kv_pair() {
        let mut bytes = Vec::new();
        push_u8(&mut bytes, 4); // Object
        push_u32(&mut bytes, 1); // 1 pair

        push_borsh_string(&mut bytes, "k");

        push_u8(&mut bytes, 2); // String
        push_u32(&mut bytes, 10); // claims length=10
        // missing actual string bytes

        assert!(deser(bytes).is_err());
    }

    // Rejects incomplete i64 value (only 3 bytes instead of 8)
    #[test]
    fn rejects_number_i64_ok_but_truncated() {
        let mut bytes = Vec::new();
        push_u8(&mut bytes, 1); // Number
        push_u8(&mut bytes, 1); // i64

        bytes.extend_from_slice(&[1, 2, 3]); // only 3 bytes
        assert!(deser(bytes).is_err());
    }

    // Tests push_i64: serializes negative i64 correctly
    #[test]
    fn accepts_i64_number_via_push_i64() {
        let mut bytes = Vec::new();
        push_u8(&mut bytes, 1); // Type: Number
        push_u8(&mut bytes, 1); // Sub-type: i64
        push_i64(&mut bytes, -123456789);

        let result = deser(bytes).expect("should deserialize i64");
        assert_eq!(result.0, Value::Number(Number::from(-123456789i64)));
    }

    // Tests push_i64: handles boundary values (MIN/MAX)
    #[test]
    fn accepts_i64_min_max_values() {
        let mut bytes_min = Vec::new();
        push_u8(&mut bytes_min, 1); // Type: Number
        push_u8(&mut bytes_min, 1); // Sub-type: i64
        push_i64(&mut bytes_min, i64::MIN);

        let result_min = deser(bytes_min).expect("should deserialize i64::MIN");
        assert_eq!(result_min.0, Value::Number(Number::from(i64::MIN)));

        let mut bytes_max = Vec::new();
        push_u8(&mut bytes_max, 1); // Type: Number
        push_u8(&mut bytes_max, 1); // Sub-type: i64
        push_i64(&mut bytes_max, i64::MAX);

        let result_max = deser(bytes_max).expect("should deserialize i64::MAX");
        assert_eq!(result_max.0, Value::Number(Number::from(i64::MAX)));
    }

    // Tests push_i64: handles zero, positive, and negative values
    #[test]
    fn accepts_i64_zero_positive_negative() {
        let mut bytes_zero = Vec::new();
        push_u8(&mut bytes_zero, 1);
        push_u8(&mut bytes_zero, 1);
        push_i64(&mut bytes_zero, 0);
        let result_zero = deser(bytes_zero).expect("should deserialize 0");
        assert_eq!(result_zero.0, Value::Number(Number::from(0i64)));

        let mut bytes_pos = Vec::new();
        push_u8(&mut bytes_pos, 1);
        push_u8(&mut bytes_pos, 1);
        push_i64(&mut bytes_pos, 42);
        let result_pos = deser(bytes_pos).expect("should deserialize positive");
        assert_eq!(result_pos.0, Value::Number(Number::from(42i64)));

        let mut bytes_neg = Vec::new();
        push_u8(&mut bytes_neg, 1);
        push_u8(&mut bytes_neg, 1);
        push_i64(&mut bytes_neg, -42);
        let result_neg = deser(bytes_neg).expect("should deserialize negative");
        assert_eq!(result_neg.0, Value::Number(Number::from(-42i64)));
    }

    // Tests push_u64: serializes unsigned integers correctly
    #[test]
    fn accepts_u64_number_via_push_u64() {
        let mut bytes = Vec::new();
        push_u8(&mut bytes, 1); // Type: Number
        push_u8(&mut bytes, 2); // Sub-type: u64
        push_u64(&mut bytes, 987654321);

        let result = deser(bytes).expect("should deserialize u64");
        assert_eq!(result.0, Value::Number(Number::from(987654321u64)));
    }

    // Tests push_u64: handles boundary values (MIN=0, MAX)
    #[test]
    fn accepts_u64_min_max_values() {
        let mut bytes_min = Vec::new();
        push_u8(&mut bytes_min, 1); // Type: Number
        push_u8(&mut bytes_min, 2); // Sub-type: u64
        push_u64(&mut bytes_min, u64::MIN);

        let result_min = deser(bytes_min).expect("should deserialize u64::MIN");
        assert_eq!(result_min.0, Value::Number(Number::from(u64::MIN)));

        let mut bytes_max = Vec::new();
        push_u8(&mut bytes_max, 1); // Type: Number
        push_u8(&mut bytes_max, 2); // Sub-type: u64
        push_u64(&mut bytes_max, u64::MAX);

        let result_max = deser(bytes_max).expect("should deserialize u64::MAX");
        assert_eq!(result_max.0, Value::Number(Number::from(u64::MAX)));
    }

    // Tests push_f64: serializes floating point numbers correctly
    #[test]
    fn accepts_f64_number_via_push_f64() {
        let mut bytes = Vec::new();
        push_u8(&mut bytes, 1); // Type: Number
        push_u8(&mut bytes, 0); // Sub-type: f64
        push_f64(&mut bytes, 3.14159);

        let result = deser(bytes).expect("should deserialize f64");
        assert_eq!(result.0, Value::Number(Number::from_f64(3.14159).unwrap()));
    }

    // Tests push_f64: handles special values (+0, -0, very large/small)
    #[test]
    fn accepts_f64_special_values() {
        let mut bytes_pos_zero = Vec::new();
        push_u8(&mut bytes_pos_zero, 1);
        push_u8(&mut bytes_pos_zero, 0);
        push_f64(&mut bytes_pos_zero, 0.0);
        let result = deser(bytes_pos_zero).expect("should deserialize +0.0");
        assert_eq!(result.0, Value::Number(Number::from_f64(0.0).unwrap()));

        let mut bytes_neg_zero = Vec::new();
        push_u8(&mut bytes_neg_zero, 1);
        push_u8(&mut bytes_neg_zero, 0);
        push_f64(&mut bytes_neg_zero, -0.0);
        let result = deser(bytes_neg_zero).expect("should deserialize -0.0");
        assert_eq!(result.0, Value::Number(Number::from_f64(-0.0).unwrap()));

        let mut bytes_large = Vec::new();
        push_u8(&mut bytes_large, 1);
        push_u8(&mut bytes_large, 0);
        push_f64(&mut bytes_large, 1.7976931348623157e308);
        let result = deser(bytes_large).expect("should deserialize large f64");
        assert!(result.0.is_number());

        let mut bytes_small = Vec::new();
        push_u8(&mut bytes_small, 1);
        push_u8(&mut bytes_small, 0);
        push_f64(&mut bytes_small, -2.2250738585072014e-308);
        let result =
            deser(bytes_small).expect("should deserialize small negative f64");
        assert!(result.0.is_number());
    }

    // Duplicate object keys: last value wins (semantic note: not ideal but accepted)
    #[test]
    fn accepts_but_overwrites_duplicate_object_keys_semantic_issue() {
        let mut bytes = Vec::new();
        push_u8(&mut bytes, 4); // Object
        push_u32(&mut bytes, 2); // 2 pairs

        push_borsh_string(&mut bytes, "a");
        push_u8(&mut bytes, 1); // Number
        push_u8(&mut bytes, 2); // u64
        push_u64(&mut bytes, 1);

        push_borsh_string(&mut bytes, "a"); // duplicate key
        push_u8(&mut bytes, 1); // Number
        push_u8(&mut bytes, 2); // u64
        push_u64(&mut bytes, 2);

        let v = deser(bytes).expect("should deserialize");
        match v.0 {
            serde_json::Value::Object(map) => {
                assert_eq!(
                    map.get("a").unwrap(),
                    &serde_json::Value::Number(serde_json::Number::from(2u64))
                );
            }
            _ => panic!("expected object"),
        }
    }
}
