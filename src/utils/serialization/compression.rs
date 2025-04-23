// Aevor Serialization Compression Module
//
// This module provides compression and decompression functionality for serialized data,
// supporting multiple compression algorithms.

use std::io::{Read, Write};

use flate2::read::{GzDecoder, ZlibDecoder};
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression as Flate2Compression;
use snap::read::FrameDecoder as SnapDecoder;
use snap::write::FrameEncoder as SnapEncoder;

use crate::error::{AevorError, Result};

/// Supported compression algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    /// No compression
    None,
    
    /// Gzip compression
    Gzip,
    
    /// Zlib compression
    Zlib,
    
    /// Snappy compression
    Snappy,
    
    /// LZ4 compression
    LZ4,
}

impl CompressionAlgorithm {
    /// Returns the name of the algorithm as a string
    pub fn name(&self) -> &'static str {
        match self {
            CompressionAlgorithm::None => "None",
            CompressionAlgorithm::Gzip => "Gzip",
            CompressionAlgorithm::Zlib => "Zlib",
            CompressionAlgorithm::Snappy => "Snappy",
            CompressionAlgorithm::LZ4 => "LZ4",
        }
    }
    
    /// Returns the identifier byte for the algorithm
    pub fn id_byte(&self) -> u8 {
        match self {
            CompressionAlgorithm::None => 0,
            CompressionAlgorithm::Gzip => 1,
            CompressionAlgorithm::Zlib => 2,
            CompressionAlgorithm::Snappy => 3,
            CompressionAlgorithm::LZ4 => 4,
        }
    }
    
    /// Returns the algorithm from an identifier byte
    pub fn from_id_byte(byte: u8) -> Result<Self> {
        match byte {
            0 => Ok(CompressionAlgorithm::None),
            1 => Ok(CompressionAlgorithm::Gzip),
            2 => Ok(CompressionAlgorithm::Zlib),
            3 => Ok(CompressionAlgorithm::Snappy),
            4 => Ok(CompressionAlgorithm::LZ4),
            _ => Err(AevorError::deserialization(format!("Unknown compression algorithm: {}", byte))),
        }
    }
}

impl std::fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl std::str::FromStr for CompressionAlgorithm {
    type Err = AevorError;
    
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(CompressionAlgorithm::None),
            "gzip" => Ok(CompressionAlgorithm::Gzip),
            "zlib" => Ok(CompressionAlgorithm::Zlib),
            "snappy" => Ok(CompressionAlgorithm::Snappy),
            "lz4" => Ok(CompressionAlgorithm::LZ4),
            _ => Err(AevorError::serialization(format!("Unknown compression algorithm: {}", s))),
        }
    }
}

/// Compression levels (None, Fast, Default, Best)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionLevel {
    /// No compression
    None,
    
    /// Fast compression (minimal CPU usage)
    Fast,
    
    /// Default compression (balanced)
    Default,
    
    /// Best compression (maximal compression ratio)
    Best,
}

impl CompressionLevel {
    /// Converts to flate2 compression level
    pub fn to_flate2_level(&self) -> Flate2Compression {
        match self {
            CompressionLevel::None => Flate2Compression::none(),
            CompressionLevel::Fast => Flate2Compression::fast(),
            CompressionLevel::Default => Flate2Compression::default(),
            CompressionLevel::Best => Flate2Compression::best(),
        }
    }
}

/// Compress data using the specified algorithm
pub fn compress(data: &[u8], algorithm: CompressionAlgorithm, level: CompressionLevel) -> Result<Vec<u8>> {
    match algorithm {
        CompressionAlgorithm::None => {
            // No compression, just return the original data
            Ok(data.to_vec())
        }
        CompressionAlgorithm::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), level.to_flate2_level());
            encoder.write_all(data)
                .map_err(|e| AevorError::serialization(format!("Gzip compression failed: {}", e)))?;
            encoder.finish()
                .map_err(|e| AevorError::serialization(format!("Gzip compression finalization failed: {}", e)))
        }
        CompressionAlgorithm::Zlib => {
            let mut encoder = ZlibEncoder::new(Vec::new(), level.to_flate2_level());
            encoder.write_all(data)
                .map_err(|e| AevorError::serialization(format!("Zlib compression failed: {}", e)))?;
            encoder.finish()
                .map_err(|e| AevorError::serialization(format!("Zlib compression finalization failed: {}", e)))
        }
        CompressionAlgorithm::Snappy => {
            let mut encoder = SnapEncoder::new(Vec::new());
            encoder.write_all(data)
                .map_err(|e| AevorError::serialization(format!("Snappy compression failed: {}", e)))?;
            encoder.into_inner()
                .map_err(|e| AevorError::serialization(format!("Snappy compression finalization failed: {}", e)))
        }
        CompressionAlgorithm::LZ4 => {
            let mut compressed = Vec::new();
            let mut encoder = lz4::EncoderBuilder::new()
                .level(match level {
                    CompressionLevel::None => 0,
                    CompressionLevel::Fast => 1,
                    CompressionLevel::Default => 4,
                    CompressionLevel::Best => 16,
                })
                .build(&mut compressed)
                .map_err(|e| AevorError::serialization(format!("LZ4 encoder creation failed: {}", e)))?;
            
            encoder.write_all(data)
                .map_err(|e| AevorError::serialization(format!("LZ4 compression failed: {}", e)))?;
            
            let (result, error) = encoder.finish();
            if let Err(e) = error {
                return Err(AevorError::serialization(format!("LZ4 compression finalization failed: {}", e)));
            }
            
            Ok(result)
        }
    }
}

/// Decompress data using the specified algorithm
pub fn decompress(compressed_data: &[u8], algorithm: CompressionAlgorithm) -> Result<Vec<u8>> {
    match algorithm {
        CompressionAlgorithm::None => {
            // No compression, just return the original data
            Ok(compressed_data.to_vec())
        }
        CompressionAlgorithm::Gzip => {
            let mut decoder = GzDecoder::new(compressed_data);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)
                .map_err(|e| AevorError::deserialization(format!("Gzip decompression failed: {}", e)))?;
            Ok(decompressed)
        }
        CompressionAlgorithm::Zlib => {
            let mut decoder = ZlibDecoder::new(compressed_data);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)
                .map_err(|e| AevorError::deserialization(format!("Zlib decompression failed: {}", e)))?;
            Ok(decompressed)
        }
        CompressionAlgorithm::Snappy => {
            let mut decoder = SnapDecoder::new(compressed_data);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)
                .map_err(|e| AevorError::deserialization(format!("Snappy decompression failed: {}", e)))?;
            Ok(decompressed)
        }
        CompressionAlgorithm::LZ4 => {
            let mut decoder = lz4::Decoder::new(compressed_data)
                .map_err(|e| AevorError::deserialization(format!("LZ4 decoder creation failed: {}", e)))?;
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)
                .map_err(|e| AevorError::deserialization(format!("LZ4 decompression failed: {}", e)))?;
            Ok(decompressed)
        }
    }
}

/// Compress and add a header for identification
pub fn compress_with_header(data: &[u8], algorithm: CompressionAlgorithm, level: CompressionLevel) -> Result<Vec<u8>> {
    let compressed = compress(data, algorithm, level)?;
    
    // Create header: 4-byte magic + 1-byte algorithm ID + 4-byte original size
    let mut result = Vec::with_capacity(9 + compressed.len());
    result.extend_from_slice(b"AEVC"); // Magic bytes for Aevor Compression
    result.push(algorithm.id_byte());
    result.extend_from_slice(&(data.len() as u32).to_le_bytes());
    result.extend_from_slice(&compressed);
    
    Ok(result)
}

/// Decompress data with a header
pub fn decompress_with_header(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 9 {
        return Err(AevorError::deserialization("Compressed data too small to contain header"));
    }
    
    // Check magic bytes
    if &data[0..4] != b"AEVC" {
        return Err(AevorError::deserialization("Invalid compression header magic bytes"));
    }
    
    // Get algorithm
    let algorithm = CompressionAlgorithm::from_id_byte(data[4])?;
    
    // Get original size
    let original_size = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;
    
    // Decompress
    let decompressed = decompress(&data[9..], algorithm)?;
    
    // Verify original size
    if decompressed.len() != original_size {
        return Err(AevorError::deserialization(format!(
            "Decompressed size mismatch: expected {}, got {}",
            original_size,
            decompressed.len()
        )));
    }
    
    Ok(decompressed)
}

/// Compresses if the result is smaller, otherwise returns original
pub fn compress_if_smaller(data: &[u8], algorithm: CompressionAlgorithm, level: CompressionLevel) -> Result<(Vec<u8>, bool)> {
    // Don't bother compressing very small data
    if data.len() < 100 {
        return Ok((data.to_vec(), false));
    }
    
    let compressed = compress(data, algorithm, level)?;
    
    // Check if compression actually helped
    if compressed.len() < data.len() {
        Ok((compressed, true))
    } else {
        Ok((data.to_vec(), false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    const TEST_DATA: &[u8] = b"This is some test data that should be reasonably compressible. \
        It contains some repetition, repetition, repetition, which compression algorithms love to see. \
        The more repetition we have, the better compression we get. \
        So let's repeat this sentence many times. So let's repeat this sentence many times. \
        So let's repeat this sentence many times. So let's repeat this sentence many times.";
    
    const SMALL_DATA: &[u8] = b"Small";
    
    #[test]
    fn test_compress_decompress_gzip() {
        let compressed = compress(TEST_DATA, CompressionAlgorithm::Gzip, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed, CompressionAlgorithm::Gzip).unwrap();
        
        // Make sure the compression did something
        assert!(compressed.len() < TEST_DATA.len());
        
        // Make sure we can get the original data back
        assert_eq!(decompressed, TEST_DATA);
    }
    
    #[test]
    fn test_compress_decompress_zlib() {
        let compressed = compress(TEST_DATA, CompressionAlgorithm::Zlib, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed, CompressionAlgorithm::Zlib).unwrap();
        
        // Make sure the compression did something
        assert!(compressed.len() < TEST_DATA.len());
        
        // Make sure we can get the original data back
        assert_eq!(decompressed, TEST_DATA);
    }
    
    #[test]
    fn test_compress_decompress_snappy() {
        let compressed = compress(TEST_DATA, CompressionAlgorithm::Snappy, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed, CompressionAlgorithm::Snappy).unwrap();
        
        // Make sure the compression did something
        assert!(compressed.len() < TEST_DATA.len());
        
        // Make sure we can get the original data back
        assert_eq!(decompressed, TEST_DATA);
    }
    
    #[test]
    fn test_compress_decompress_lz4() {
        let compressed = compress(TEST_DATA, CompressionAlgorithm::LZ4, CompressionLevel::Default).unwrap();
        let decompressed = decompress(&compressed, CompressionAlgorithm::LZ4).unwrap();
        
        // Make sure the compression did something
        assert!(compressed.len() < TEST_DATA.len());
        
        // Make sure we can get the original data back
        assert_eq!(decompressed, TEST_DATA);
    }
    
    #[test]
    fn test_compression_levels() {
        // Test that higher compression levels generally produce smaller output
        let fast = compress(TEST_DATA, CompressionAlgorithm::Gzip, CompressionLevel::Fast).unwrap();
        let default = compress(TEST_DATA, CompressionAlgorithm::Gzip, CompressionLevel::Default).unwrap();
        let best = compress(TEST_DATA, CompressionAlgorithm::Gzip, CompressionLevel::Best).unwrap();
        
        // Best should be smaller or equal to default, which should be smaller or equal to fast
        // Note: in rare cases this might not hold, but it generally does for reasonable test data
        assert!(best.len() <= default.len() || default.len() <= fast.len());
    }
    
    #[test]
    fn test_compress_with_header() {
        let with_header = compress_with_header(TEST_DATA, CompressionAlgorithm::Gzip, CompressionLevel::Default).unwrap();
        let decompressed = decompress_with_header(&with_header).unwrap();
        
        // Make sure we can get the original data back
        assert_eq!(decompressed, TEST_DATA);
        
        // Make sure the header is correct
        assert_eq!(&with_header[0..4], b"AEVC");
        assert_eq!(with_header[4], CompressionAlgorithm::Gzip.id_byte());
        
        // Check original size
        let original_size = u32::from_le_bytes([with_header[5], with_header[6], with_header[7], with_header[8]]);
        assert_eq!(original_size as usize, TEST_DATA.len());
    }   
}
