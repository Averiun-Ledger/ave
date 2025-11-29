

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
        ValueWrapper(Value::Null)
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
                    let element = ValueWrapper(element.to_owned());
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
                    let value = ValueWrapper(value.to_owned());
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
                Ok(ValueWrapper(Value::Bool(data)))
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
                        Ok(ValueWrapper(Value::Number(data_f64)))
                    }
                    // Sub-type 1: i64
                    1 => {
                        let data: i64 =
                            BorshDeserialize::deserialize_reader(reader)?;
                        Ok(ValueWrapper(Value::Number(Number::from(data))))
                    }
                    // Sub-type 2: u64
                    2 => {
                        let data: u64 =
                            BorshDeserialize::deserialize_reader(reader)?;
                        Ok(ValueWrapper(Value::Number(Number::from(data))))
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
                Ok(ValueWrapper(Value::String(data)))
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
                    Ok(ValueWrapper(Value::Array(Vec::new())))
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
                            ValueWrapper::deserialize_reader_with_depth(
                                reader,
                                next_depth,
                            )?
                            .0,
                        );
                    }
                    Ok(ValueWrapper(Value::Array(result)))
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
                    let value =
                        ValueWrapper::deserialize_reader_with_depth(reader, next_depth)?;
                    result.insert(key, value.0);
                }
                Ok(ValueWrapper(Value::Object(result)))
            }
            // Type 5: Null
            5 => Ok(ValueWrapper(Value::Null)),
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
        ValueWrapper::deserialize_reader_with_depth(reader, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_value_wrapper_string() {
        let value = ValueWrapper(Value::String("test".to_owned()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_bool() {
        let value = ValueWrapper(Value::Bool(true));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);

        let value_false = ValueWrapper(Value::Bool(false));
        let vec_false = borsh::to_vec(&value_false).unwrap();
        let value2_false: ValueWrapper = BorshDeserialize::try_from_slice(&vec_false).unwrap();
        assert_eq!(value_false, value2_false);
    }

    #[test]
    fn test_value_wrapper_number_f64() {
        let value = ValueWrapper(Value::Number(Number::from_f64(3.14).unwrap()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_number_i64() {
        let value = ValueWrapper(Value::Number(Number::from(-42i64)));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_number_u64() {
        let value = ValueWrapper(Value::Number(Number::from(12345u64)));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_null() {
        let value = ValueWrapper(Value::Null);
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_array() {
        let value = ValueWrapper(Value::Array(vec![
            Value::Bool(true),
            Value::String("test".to_owned()),
            Value::Number(Number::from(42)),
            Value::Null,
        ]));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_empty_array() {
        let value = ValueWrapper(Value::Array(vec![]));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_object() {
        let mut map = Map::new();
        map.insert("name".to_string(), Value::String("Alice".to_owned()));
        map.insert("age".to_string(), Value::Number(Number::from(30)));
        map.insert("active".to_string(), Value::Bool(true));

        let value = ValueWrapper(Value::Object(map));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_empty_object() {
        let value = ValueWrapper(Value::Object(Map::new()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_nested_structure() {
        let mut inner_map = Map::new();
        inner_map.insert("x".to_string(), Value::Number(Number::from(1)));
        inner_map.insert("y".to_string(), Value::Number(Number::from(2)));

        let mut outer_map = Map::new();
        outer_map.insert("point".to_string(), Value::Object(inner_map));
        outer_map.insert("values".to_string(), Value::Array(vec![
            Value::Number(Number::from(1)),
            Value::Number(Number::from(2)),
            Value::Number(Number::from(3)),
        ]));

        let value = ValueWrapper(Value::Object(outer_map));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_max_recursion_depth() {
        // Create a deeply nested structure
        let mut value = Value::Null;
        for _ in 0..MAX_RECURSION_DEPTH {
            value = Value::Array(vec![value]);
        }

        let wrapper = ValueWrapper(value);
        let vec = borsh::to_vec(&wrapper).unwrap();

        // This should succeed as we're at the limit
        let result: Result<ValueWrapper, _> = BorshDeserialize::try_from_slice(&vec);
        assert!(result.is_ok());
    }

    #[test]
    fn test_value_wrapper_exceeds_recursion_depth() {
        // Create a structure that exceeds max depth
        let mut value = Value::Null;
        for _ in 0..=MAX_RECURSION_DEPTH {
            value = Value::Array(vec![value]);
        }

        let wrapper = ValueWrapper(value);
        let vec = borsh::to_vec(&wrapper).unwrap();

        // This should fail due to exceeding recursion limit
        let result: Result<ValueWrapper, _> = BorshDeserialize::try_from_slice(&vec);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Recursion depth limit exceeded"));
    }

    #[test]
    fn test_value_wrapper_large_array() {
        // Create an array with MAX_COLLECTION_SIZE elements
        let large_array = vec![Value::Null; MAX_COLLECTION_SIZE as usize];
        let value = ValueWrapper(Value::Array(large_array));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_array_size_overflow() {
        // Create a byte array that claims to have more than MAX_COLLECTION_SIZE elements
        let mut bytes = vec![3u8]; // Type tag for Array
        let oversized_len = MAX_COLLECTION_SIZE + 1;
        bytes.extend_from_slice(&oversized_len.to_le_bytes());

        let result: Result<ValueWrapper, _> = BorshDeserialize::try_from_slice(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Array size too large"));
    }

    #[test]
    fn test_value_wrapper_object_size_overflow() {
        // Create a byte array that claims to have more than MAX_COLLECTION_SIZE keys
        let mut bytes = vec![4u8]; // Type tag for Object
        let oversized_len = MAX_COLLECTION_SIZE + 1;
        bytes.extend_from_slice(&oversized_len.to_le_bytes());

        let result: Result<ValueWrapper, _> = BorshDeserialize::try_from_slice(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Object size too large"));
    }

    #[test]
    fn test_value_wrapper_invalid_type_tag() {
        // Use an invalid type tag (6 doesn't exist, valid are 0-5)
        let bytes = vec![6u8];

        let result: Result<ValueWrapper, _> = BorshDeserialize::try_from_slice(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid Value representation"));
    }

    #[test]
    fn test_value_wrapper_invalid_number_type() {
        // Type tag 1 (Number) with invalid internal order 3
        let bytes = vec![1u8, 3u8];

        let result: Result<ValueWrapper, _> = BorshDeserialize::try_from_slice(&bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid Number representation"));
    }

    #[test]
    fn test_value_wrapper_unicode_strings() {
        let value = ValueWrapper(Value::String("Hello 世界 🌍".to_owned()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_empty_string() {
        let value = ValueWrapper(Value::String(String::new()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_special_floats() {
        // Test zero
        let value = ValueWrapper(Value::Number(Number::from_f64(0.0).unwrap()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);

        // Test negative zero
        let value = ValueWrapper(Value::Number(Number::from_f64(-0.0).unwrap()));
        let vec = borsh::to_vec(&value).unwrap();
        let value2: ValueWrapper = BorshDeserialize::try_from_slice(&vec).unwrap();
        assert_eq!(value, value2);
    }

    #[test]
    fn test_value_wrapper_clone() {
        let value = ValueWrapper(Value::String("test".to_owned()));
        let cloned = value.clone();
        assert_eq!(value, cloned);
    }

    #[test]
    fn test_value_wrapper_debug() {
        let value = ValueWrapper(Value::String("test".to_owned()));
        let debug_str = format!("{:?}", value);
        assert!(debug_str.contains("test"));
    }

    #[test]
    fn test_value_wrapper_as_str() {
        let value = ValueWrapper(Value::String("hello".to_owned()));
        assert_eq!(value.as_str(), Some("hello"));

        let non_string = ValueWrapper(Value::Number(Number::from(42)));
        assert_eq!(non_string.as_str(), None);
    }

    #[test]
    fn test_value_wrapper_get() {
        let mut map = Map::new();
        map.insert("name".to_string(), Value::String("Alice".to_owned()));
        map.insert("age".to_string(), Value::Number(Number::from(30)));

        let value = ValueWrapper(Value::Object(map));
        assert_eq!(value.get("name"), Some(&Value::String("Alice".to_owned())));
        assert_eq!(value.get("age"), Some(&Value::Number(Number::from(30))));
        assert_eq!(value.get("missing"), None);

        let non_object = ValueWrapper(Value::String("not an object".to_owned()));
        assert_eq!(non_object.get("key"), None);
    }

    #[test]
    fn test_value_wrapper_deref() {
        let value = ValueWrapper(Value::String("test".to_owned()));
        // Test that we can use Value methods directly through Deref
        assert!(value.is_string());
        assert!(!value.is_number());

        let number = ValueWrapper(Value::Number(Number::from(42)));
        assert!(number.is_number());
        assert!(!number.is_string());
    }

    #[test]
    fn test_value_wrapper_default() {
        let value = ValueWrapper::default();
        assert_eq!(value.0, Value::Null);
        assert!(value.is_null());
    }

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
}
