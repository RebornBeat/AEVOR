// Aevor Serialization Module
//
// This module provides serialization and deserialization functionality for the Aevor blockchain,
// supporting multiple formats including binary, JSON, and MessagePack.

use std::fmt;
use std::io::{Read, Write};

use serde::{Deserialize, Serialize};

use crate::error::{AevorError, Result};

/// Supported serialization formats
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializationFormat {
    /// Binary format (using bincode)
    Binary,
    
    /// JSON format (using serde_json)
    JSON,
    
    /// MessagePack format (using rmp_serde)
    MessagePack,
}

impl SerializationFormat {
    /// Returns the name of the format as a string
    pub fn name(&self) -> &'static str {
        match self {
            SerializationFormat::Binary => "Binary",
            SerializationFormat::JSON => "JSON",
            SerializationFormat::MessagePack => "MessagePack",
        }
    }
    
    /// Returns the MIME type of the format
    pub fn mime_type(&self) -> &'static str {
        match self {
            SerializationFormat::Binary => "application/octet-stream",
            SerializationFormat::JSON => "application/json",
            SerializationFormat::MessagePack => "application/msgpack",
        }
    }
    
    /// Returns the file extension for this format
    pub fn extension(&self) -> &'static str {
        match self {
            SerializationFormat::Binary => "bin",
            SerializationFormat::JSON => "json",
            SerializationFormat::MessagePack => "msgpack",
        }
    }
}

impl fmt::Display for SerializationFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for SerializationFormat {
    type Err = AevorError;
    
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "binary" | "bin" => Ok(SerializationFormat::Binary),
            "json" => Ok(SerializationFormat::JSON),
            "messagepack" | "msgpack" => Ok(SerializationFormat::MessagePack),
            _ => Err(AevorError::serialization(format!("Unknown serialization format: {}", s))),
        }
    }
}

/// Serializes a value to bytes using the specified format
pub fn serialize<T>(value: &T, format: SerializationFormat) -> Result<Vec<u8>>
where
    T: Serialize,
{
    match format {
        SerializationFormat::Binary => {
            bincode::serialize(value)
                .map_err(|e| AevorError::serialization(format!("Binary serialization failed: {}", e)))
        }
        SerializationFormat::JSON => {
            serde_json::to_vec(value)
                .map_err(|e| AevorError::serialization(format!("JSON serialization failed: {}", e)))
        }
        SerializationFormat::MessagePack => {
            rmp_serde::to_vec(value)
                .map_err(|e| AevorError::serialization(format!("MessagePack serialization failed: {}", e)))
        }
    }
}

/// Deserializes bytes to a value using the specified format
pub fn deserialize<T>(bytes: &[u8], format: SerializationFormat) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    match format {
        SerializationFormat::Binary => {
            bincode::deserialize(bytes)
                .map_err(|e| AevorError::deserialization(format!("Binary deserialization failed: {}", e)))
        }
        SerializationFormat::JSON => {
            serde_json::from_slice(bytes)
                .map_err(|e| AevorError::deserialization(format!("JSON deserialization failed: {}", e)))
        }
        SerializationFormat::MessagePack => {
            rmp_serde::from_slice(bytes)
                .map_err(|e| AevorError::deserialization(format!("MessagePack deserialization failed: {}", e)))
        }
    }
}

/// Serializes a value to a writer using the specified format
pub fn serialize_to_writer<T, W>(value: &T, writer: W, format: SerializationFormat) -> Result<()>
where
    T: Serialize,
    W: Write,
{
    match format {
        SerializationFormat::Binary => {
            bincode::serialize_into(writer, value)
                .map_err(|e| AevorError::serialization(format!("Binary serialization failed: {}", e)))
        }
        SerializationFormat::JSON => {
            serde_json::to_writer(writer, value)
                .map_err(|e| AevorError::serialization(format!("JSON serialization failed: {}", e)))
        }
        SerializationFormat::MessagePack => {
            rmp_serde::encode::write(writer, value)
                .map_err(|e| AevorError::serialization(format!("MessagePack serialization failed: {}", e)))
        }
    }
}

/// Deserializes from a reader using the specified format
pub fn deserialize_from_reader<T, R>(reader: R, format: SerializationFormat) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    R: Read,
{
    match format {
        SerializationFormat::Binary => {
            bincode::deserialize_from(reader)
                .map_err(|e| AevorError::deserialization(format!("Binary deserialization failed: {}", e)))
        }
        SerializationFormat::JSON => {
            serde_json::from_reader(reader)
                .map_err(|e| AevorError::deserialization(format!("JSON deserialization failed: {}", e)))
        }
        SerializationFormat::MessagePack => {
            rmp_serde::from_read(reader)
                .map_err(|e| AevorError::deserialization(format!("MessagePack deserialization failed: {}", e)))
        }
    }
}

/// Serializes a value to a pretty-printed JSON string (only applicable for JSON format)
pub fn serialize_to_string<T>(value: &T, format: SerializationFormat) -> Result<String>
where
    T: Serialize,
{
    match format {
        SerializationFormat::JSON => {
            serde_json::to_string_pretty(value)
                .map_err(|e| AevorError::serialization(format!("JSON serialization failed: {}", e)))
        }
        _ => {
            // For non-JSON formats, serialize to bytes and then encode as hex
            let bytes = serialize(value, format)?;
            Ok(hex::encode(&bytes))
        }
    }
}

/// Deserializes from a string using the specified format
pub fn deserialize_from_string<T>(s: &str, format: SerializationFormat) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    match format {
        SerializationFormat::JSON => {
            serde_json::from_str(s)
                .map_err(|e| AevorError::deserialization(format!("JSON deserialization failed: {}", e)))
        }
        _ => {
            // For non-JSON formats, decode from hex and then deserialize
            let bytes = hex::decode(s)
                .map_err(|e| AevorError::deserialization(format!("Hex decoding failed: {}", e)))?;
            deserialize(&bytes, format)
        }
    }
}

/// Calculates the size of a serialized value without actually serializing it
/// 
/// Note: This is most accurate for Binary format, as JSON and MessagePack
/// sizes may vary depending on the serialization implementation details.
pub fn serialized_size<T>(value: &T, format: SerializationFormat) -> Result<usize>
where
    T: Serialize,
{
    match format {
        SerializationFormat::Binary => {
            bincode::serialized_size(value)
                .map(|size| size as usize)
                .map_err(|e| AevorError::serialization(format!("Binary size calculation failed: {}", e)))
        }
        _ => {
            // For other formats, serialize and measure the result
            let bytes = serialize(value, format)?;
            Ok(bytes.len())
        }
    }
}

/// Module with additional compression utilities
pub mod compression;

/// Module with custom serialization implementations
pub mod custom;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestStruct {
        id: u64,
        name: String,
        data: Vec<u8>,
    }
    
    fn create_test_struct() -> TestStruct {
        TestStruct {
            id: 42,
            name: "Test".to_string(),
            data: vec![1, 2, 3, 4],
        }
    }
    
    #[test]
    fn test_serialization_format_conversion() {
        assert_eq!("Binary".parse::<SerializationFormat>().unwrap(), SerializationFormat::Binary);
        assert_eq!("json".parse::<SerializationFormat>().unwrap(), SerializationFormat::JSON);
        assert_eq!("msgpack".parse::<SerializationFormat>().unwrap(), SerializationFormat::MessagePack);
        
        assert!("unknown".parse::<SerializationFormat>().is_err());
    }
    
    #[test]
    fn test_binary_serialization() {
        let test_struct = create_test_struct();
        
        // Serialize
        let serialized = serialize(&test_struct, SerializationFormat::Binary).unwrap();
        
        // Deserialize
        let deserialized: TestStruct = deserialize(&serialized, SerializationFormat::Binary).unwrap();
        
        // Check that we got the same struct back
        assert_eq!(deserialized, test_struct);
    }
    
    #[test]
    fn test_json_serialization() {
        let test_struct = create_test_struct();
        
        // Serialize
        let serialized = serialize(&test_struct, SerializationFormat::JSON).unwrap();
        
        // Deserialize
        let deserialized: TestStruct = deserialize(&serialized, SerializationFormat::JSON).unwrap();
        
        // Check that we got the same struct back
        assert_eq!(deserialized, test_struct);
    }
    
    #[test]
    fn test_messagepack_serialization() {
        let test_struct = create_test_struct();
        
        // Serialize
        let serialized = serialize(&test_struct, SerializationFormat::MessagePack).unwrap();
        
        // Deserialize
        let deserialized: TestStruct = deserialize(&serialized, SerializationFormat::MessagePack).unwrap();
        
        // Check that we got the same struct back
        assert_eq!(deserialized, test_struct);
    }
    
    #[test]
    fn test_writer_serialization() {
        let test_struct = create_test_struct();
        
        // Serialize to writer
        let mut buf = Vec::new();
        serialize_to_writer(&test_struct, &mut buf, SerializationFormat::Binary).unwrap();
        
        // Deserialize from reader
        let deserialized: TestStruct = deserialize_from_reader(&buf[..], SerializationFormat::Binary).unwrap();
        
        // Check that we got the same struct back
        assert_eq!(deserialized, test_struct);
    }
    
    #[test]
    fn test_string_serialization() {
        let test_struct = create_test_struct();
        
        // Serialize to string
        let serialized = serialize_to_string(&test_struct, SerializationFormat::JSON).unwrap();
        
        // Make sure it's valid JSON
        assert!(serialized.contains("\"id\":42"));
        assert!(serialized.contains("\"name\":\"Test\""));
        
        // Deserialize from string
        let deserialized: TestStruct = deserialize_from_string(&serialized, SerializationFormat::JSON).unwrap();
        
        // Check that we got the same struct back
        assert_eq!(deserialized, test_struct);
    }
    
    #[test]
    fn test_serialized_size() {
        let test_struct = create_test_struct();
        
        // Calculate size
        let size = serialized_size(&test_struct, SerializationFormat::Binary).unwrap();
        
        // Make sure the size is reasonable
        assert!(size > 0);
        
        // The actual serialized data should match the calculated size
        let serialized = serialize(&test_struct, SerializationFormat::Binary).unwrap();
        assert_eq!(serialized.len(), size);
    }
    
    #[test]
    fn test_format_properties() {
        assert_eq!(SerializationFormat::Binary.name(), "Binary");
        assert_eq!(SerializationFormat::JSON.name(), "JSON");
        assert_eq!(SerializationFormat::MessagePack.name(), "MessagePack");
        
        assert_eq!(SerializationFormat::Binary.mime_type(), "application/octet-stream");
        assert_eq!(SerializationFormat::JSON.mime_type(), "application/json");
        assert_eq!(SerializationFormat::MessagePack.mime_type(), "application/msgpack");
        
        assert_eq!(SerializationFormat::Binary.extension(), "bin");
        assert_eq!(SerializationFormat::JSON.extension(), "json");
        assert_eq!(SerializationFormat::MessagePack.extension(), "msgpack");
    }
}
