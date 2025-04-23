// Aevor Custom Serialization Module
//
// This module provides custom serialization implementations for types that need special handling
// during serialization/deserialization processes.

use std::fmt;
use serde::{Deserialize, Deserializer, Serializer, Serialize};
use serde::de::{self, Visitor};

/// Serializes a byte array as a hex string
pub fn bytes_as_hex<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

/// Deserializes a hex string to a byte array
pub fn bytes_from_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct HexVisitor;

    impl<'de> Visitor<'de> for HexVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a hex string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            hex::decode(v).map_err(de::Error::custom)
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&v)
        }
    }

    deserializer.deserialize_str(HexVisitor)
}

/// Serializes a byte array as a base64 string
pub fn bytes_as_base64<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&base64::encode(bytes))
}

/// Deserializes a base64 string to a byte array
pub fn bytes_from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Base64Visitor;

    impl<'de> Visitor<'de> for Base64Visitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a base64 string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            base64::decode(v).map_err(de::Error::custom)
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            self.visit_str(&v)
        }
    }

    deserializer.deserialize_str(Base64Visitor)
}

/// Module for serializing Option<Vec<u8>> as hex strings
pub mod option_bytes_as_hex {
    use super::*;
    use serde::{Deserializer, Serializer};
    
    /// Serializes an Option<Vec<u8>> as an optional hex string
    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }
    
    /// Deserializes an optional hex string to an Option<Vec<u8>>
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer).map(|opt_string| {
            opt_string.map(|string| hex::decode(&string).map_err(de::Error::custom))
                .transpose()
                .map_err(de::Error::custom)
        })?
    }
}

/// Module for serializing Option<Vec<u8>> as base64 strings
pub mod option_bytes_as_base64 {
    use super::*;
    use serde::{Deserializer, Serializer};
    
    /// Serializes an Option<Vec<u8>> as an optional base64 string
    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(bytes) => serializer.serialize_some(&base64::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }
    
    /// Deserializes an optional base64 string to an Option<Vec<u8>>
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer).map(|opt_string| {
            opt_string.map(|string| base64::decode(&string).map_err(de::Error::custom))
                .transpose()
                .map_err(de::Error::custom)
        })?
    }
}

/// Serializes a timestamp as an ISO 8601 formatted string
pub fn timestamp_as_iso8601<S>(timestamp_ms: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    use chrono::{DateTime, TimeZone, Utc};
    let dt = Utc.timestamp_millis_opt(*timestamp_ms as i64).unwrap();
    serializer.serialize_str(&dt.to_rfc3339())
}

/// Deserializes an ISO 8601 formatted string to a timestamp
pub fn timestamp_from_iso8601<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    struct ISO8601Visitor;

    impl<'de> Visitor<'de> for ISO8601Visitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an ISO 8601 formatted string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            use chrono::DateTime;
            let dt = DateTime::parse_from_rfc3339(v)
                .map_err(|e| de::Error::custom(format!("Invalid ISO 8601 format: {}", e)))?;
            
            Ok(dt.timestamp_millis() as u64)
        }
    }

    deserializer.deserialize_str(ISO8601Visitor)
}

/// Serializes an address as a checksummed hex string with 0x prefix
pub fn address_as_checksummed_hex<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = hex::encode(bytes);
    let checksummed = format!("0x{}", add_checksum_to_hex(&hex_string));
    serializer.serialize_str(&checksummed)
}

/// Deserializes a checksummed hex string to a byte array
pub fn address_from_checksummed_hex<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ChecksummedHexVisitor;

    impl<'de> Visitor<'de> for ChecksummedHexVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a checksummed hex string with 0x prefix")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if !v.starts_with("0x") && !v.starts_with("0X") {
                return Err(de::Error::custom("address must start with 0x"));
            }
            
            hex::decode(&v[2..]).map_err(|e| de::Error::custom(format!("Invalid hex: {}", e)))
        }
    }

    deserializer.deserialize_str(ChecksummedHexVisitor)
}

/// Adds a simple checksum to a hex string by capitalizing certain characters
fn add_checksum_to_hex(hex: &str) -> String {
    let hash = hex::encode(sha2::Sha256::digest(hex.as_bytes()));
    let mut result = String::with_capacity(hex.len());
    
    for (i, c) in hex.char_indices() {
        if c.is_alphabetic() {
            // Use the corresponding hash character to determine capitalization
            let hash_char = hash.chars().nth(i % hash.len()).unwrap_or('0');
            if hash_char >= '8' {
                result.push(c.to_ascii_uppercase());
            } else {
                result.push(c.to_ascii_lowercase());
            }
        } else {
            result.push(c);
        }
    }
    
    result
}

/// Allows serializing a fixed-size array as a hex string
pub mod array_as_hex {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::marker::PhantomData;
    
    /// Serialize a fixed-size array as a hex string
    pub fn serialize<S, const N: usize>(data: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(data))
    }
    
    /// Deserialize a hex string into a fixed-size array
    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HexVisitor<const M: usize>(PhantomData<[u8; M]>);
        
        impl<'de, const M: usize> serde::de::Visitor<'de> for HexVisitor<M> {
            type Value = [u8; M];
            
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a hex string representing {} bytes", M)
            }
            
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let bytes = hex::decode(v).map_err(serde::de::Error::custom)?;
                
                if bytes.len() != M {
                    return Err(serde::de::Error::custom(
                        format!("expected {} bytes, got {}", M, bytes.len())
                    ));
                }
                
                let mut result = [0u8; M];
                result.copy_from_slice(&bytes);
                Ok(result)
            }
        }
        
        deserializer.deserialize_str(HexVisitor(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestHex {
        #[serde(serialize_with = "bytes_as_hex", deserialize_with = "bytes_from_hex")]
        data: Vec<u8>,
    }
    
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestBase64 {
        #[serde(serialize_with = "bytes_as_base64", deserialize_with = "bytes_from_base64")]
        data: Vec<u8>,
    }
    
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestOptionHex {
        #[serde(with = "option_bytes_as_hex")]
        data: Option<Vec<u8>>,
    }
    
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestTimestamp {
        #[serde(serialize_with = "timestamp_as_iso8601", deserialize_with = "timestamp_from_iso8601")]
        timestamp: u64,
    }
    
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestArrayHex<const N: usize> {
        #[serde(with = "array_as_hex")]
        data: [u8; N],
    }
    
    #[test]
    fn test_bytes_as_hex() {
        let test_struct = TestHex { data: vec![0x01, 0x02, 0x03, 0x04] };
        let json = serde_json::to_string(&test_struct).unwrap();
        
        // Check the JSON has the hex encoded string
        assert_eq!(json, r#"{"data":"01020304"}"#);
        
        // Deserialize and check equality
        let deserialized: TestHex = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, test_struct);
    }
    
    #[test]
    fn test_bytes_as_base64() {
        let test_struct = TestBase64 { data: vec![0x01, 0x02, 0x03, 0x04] };
        let json = serde_json::to_string(&test_struct).unwrap();
        
        // Check the JSON has the base64 encoded string
        assert_eq!(json, r#"{"data":"AQIDBA=="}"#);
        
        // Deserialize and check equality
        let deserialized: TestBase64 = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, test_struct);
    }
    
    #[test]
    fn test_option_bytes_as_hex() {
        // Test with Some value
        let test_struct = TestOptionHex { data: Some(vec![0x01, 0x02, 0x03, 0x04]) };
        let json = serde_json::to_string(&test_struct).unwrap();
        
        assert_eq!(json, r#"{"data":"01020304"}"#);
        
        let deserialized: TestOptionHex = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, test_struct);
        
        // Test with None value
        let test_struct = TestOptionHex { data: None };
        let json = serde_json::to_string(&test_struct).unwrap();
        
        assert_eq!(json, r#"{"data":null}"#);
        
        let deserialized: TestOptionHex = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, test_struct);
    }
    
    #[test]
    fn test_timestamp_as_iso8601() {
        // Test with a known timestamp (2021-01-01T00:00:00Z)
        let timestamp = 1609459200000;
        let test_struct = TestTimestamp { timestamp };
        let json = serde_json::to_string(&test_struct).unwrap();
        
        assert_eq!(json, r#"{"timestamp":"2021-01-01T00:00:00+00:00"}"#);
        
        let deserialized: TestTimestamp = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, test_struct);
    }
    
    #[test]
    fn test_array_as_hex() {
        let test_struct = TestArrayHex { data: [0x01, 0x02, 0x03, 0x04] };
        let json = serde_json::to_string(&test_struct).unwrap();
        
        // Check the JSON has the hex encoded string
        assert_eq!(json, r#"{"data":"01020304"}"#);
        
        // Deserialize and check equality
        let deserialized: TestArrayHex<4> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, test_struct);
    }
    
    #[test]
    fn test_checksum() {
        let hex = "deadbeef";
        let checksummed = add_checksum_to_hex(hex);
        
        // Ensure result is same length
        assert_eq!(checksummed.len(), hex.len());
        
        // Ensure lowercase and uppercase are used
        let has_lowercase = checksummed.chars().any(|c| c.is_lowercase());
        let has_uppercase = checksummed.chars().any(|c| c.is_uppercase());
        assert!(has_lowercase);
        assert!(has_uppercase);
    }
}
