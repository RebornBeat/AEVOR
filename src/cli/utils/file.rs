use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::error::{AevorError, Result};
use super::display;

/// Read a file to a string
pub fn read_to_string<P: AsRef<Path>>(path: P) -> Result<String> {
    fs::read_to_string(path.as_ref())
        .map_err(|e| AevorError::io(format!("Failed to read file {}: {}", path.as_ref().display(), e)))
}

/// Read a file to bytes
pub fn read_to_bytes<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    fs::read(path.as_ref())
        .map_err(|e| AevorError::io(format!("Failed to read file {}: {}", path.as_ref().display(), e)))
}

/// Write string to a file
pub fn write_string<P: AsRef<Path>>(path: P, content: &str) -> Result<()> {
    // Create parent directories if they don't exist
    if let Some(parent) = path.as_ref().parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| AevorError::io(format!("Failed to create directory {}: {}", parent.display(), e)))?;
        }
    }
    
    fs::write(path.as_ref(), content)
        .map_err(|e| AevorError::io(format!("Failed to write to file {}: {}", path.as_ref().display(), e)))
}

/// Write bytes to a file
pub fn write_bytes<P: AsRef<Path>>(path: P, bytes: &[u8]) -> Result<()> {
    // Create parent directories if they don't exist
    if let Some(parent) = path.as_ref().parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| AevorError::io(format!("Failed to create directory {}: {}", parent.display(), e)))?;
        }
    }
    
    fs::write(path.as_ref(), bytes)
        .map_err(|e| AevorError::io(format!("Failed to write to file {}: {}", path.as_ref().display(), e)))
}

/// Check if a file exists
pub fn file_exists<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref().exists() && path.as_ref().is_file()
}

/// Check if a directory exists
pub fn dir_exists<P: AsRef<Path>>(path: P) -> bool {
    path.as_ref().exists() && path.as_ref().is_dir()
}

/// Create a directory and all parent directories
pub fn create_dir_all<P: AsRef<Path>>(path: P) -> Result<()> {
    fs::create_dir_all(path.as_ref())
        .map_err(|e| AevorError::io(format!("Failed to create directory {}: {}", path.as_ref().display(), e)))
}

/// Remove a file
pub fn remove_file<P: AsRef<Path>>(path: P) -> Result<()> {
    fs::remove_file(path.as_ref())
        .map_err(|e| AevorError::io(format!("Failed to remove file {}: {}", path.as_ref().display(), e)))
}

/// Remove a directory
pub fn remove_dir<P: AsRef<Path>>(path: P) -> Result<()> {
    fs::remove_dir(path.as_ref())
        .map_err(|e| AevorError::io(format!("Failed to remove directory {}: {}", path.as_ref().display(), e)))
}

/// Remove a directory and all its contents
pub fn remove_dir_all<P: AsRef<Path>>(path: P) -> Result<()> {
    fs::remove_dir_all(path.as_ref())
        .map_err(|e| AevorError::io(format!("Failed to remove directory {}: {}", path.as_ref().display(), e)))
}

/// Copy a file
pub fn copy_file<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> Result<()> {
    fs::copy(&from, &to)
        .map_err(|e| AevorError::io(format!("Failed to copy file from {} to {}: {}", 
            from.as_ref().display(), to.as_ref().display(), e)))?;
    Ok(())
}

/// Rename a file
pub fn rename<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> Result<()> {
    fs::rename(&from, &to)
        .map_err(|e| AevorError::io(format!("Failed to rename {} to {}: {}", 
            from.as_ref().display(), to.as_ref().display(), e)))
}

/// Get file size
pub fn file_size<P: AsRef<Path>>(path: P) -> Result<u64> {
    let metadata = fs::metadata(path.as_ref())
        .map_err(|e| AevorError::io(format!("Failed to get metadata for {}: {}", path.as_ref().display(), e)))?;
    Ok(metadata.len())
}

/// Get file modification time
pub fn file_modified_time<P: AsRef<Path>>(path: P) -> Result<std::time::SystemTime> {
    let metadata = fs::metadata(path.as_ref())
        .map_err(|e| AevorError::io(format!("Failed to get metadata for {}: {}", path.as_ref().display(), e)))?;
    
    metadata.modified()
        .map_err(|e| AevorError::io(format!("Failed to get modified time for {}: {}", path.as_ref().display(), e)))
}

/// List directory contents
pub fn list_dir<P: AsRef<Path>>(path: P) -> Result<Vec<PathBuf>> {
    let entries = fs::read_dir(path.as_ref())
        .map_err(|e| AevorError::io(format!("Failed to read directory {}: {}", path.as_ref().display(), e)))?;
    
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| AevorError::io(format!("Failed to read directory entry: {}", e)))?;
        paths.push(entry.path());
    }
    
    Ok(paths)
}

/// Find files matching a glob pattern
pub fn find_files<P: AsRef<Path>>(dir: P, pattern: &str) -> Result<Vec<PathBuf>> {
    let pattern_str = dir.as_ref().join(pattern).to_string_lossy().to_string();
    
    glob::glob(&pattern_str)
        .map_err(|e| AevorError::io(format!("Invalid glob pattern {}: {}", pattern, e)))?
        .map(|res| res.map_err(|e| AevorError::io(format!("Glob error: {}", e))))
        .collect()
}

/// Create a temporary file
pub fn temp_file() -> Result<(PathBuf, File)> {
    tempfile::NamedTempFile::new()
        .map_err(|e| AevorError::io(format!("Failed to create temporary file: {}", e)))
        .map(|file| {
            let path = file.path().to_owned();
            let file = file.into_file();
            (path, file)
        })
}

/// Create a temporary directory
pub fn temp_dir() -> Result<PathBuf> {
    tempfile::tempdir()
        .map_err(|e| AevorError::io(format!("Failed to create temporary directory: {}", e)))
        .map(|dir| dir.into_path())
}

/// Read a file in chunks
pub fn read_chunks<P: AsRef<Path>, F>(path: P, chunk_size: usize, mut callback: F) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let mut file = File::open(path.as_ref())
        .map_err(|e| AevorError::io(format!("Failed to open file {}: {}", path.as_ref().display(), e)))?;
    
    let mut buffer = vec![0; chunk_size];
    
    loop {
        let bytes_read = file.read(&mut buffer)
            .map_err(|e| AevorError::io(format!("Failed to read from file {}: {}", path.as_ref().display(), e)))?;
        
        if bytes_read == 0 {
            break;
        }
        
        callback(&buffer[..bytes_read])?;
        
        if bytes_read < chunk_size {
            break;
        }
    }
    
    Ok(())
}

/// Write a file with a progress indicator
pub fn write_with_progress<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<()> {
    // Create parent directories if they don't exist
    if let Some(parent) = path.as_ref().parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| AevorError::io(format!("Failed to create directory {}: {}", parent.display(), e)))?;
        }
    }
    
    let total_size = data.len();
    let path_str = path.as_ref().display().to_string();
    let pb = display::progress_bar(total_size as u64, &format!("Writing to {}", path_str));
    
    let mut file = File::create(path.as_ref())
        .map_err(|e| AevorError::io(format!("Failed to create file {}: {}", path.as_ref().display(), e)))?;
    
    // Write in chunks of 64KB
    const CHUNK_SIZE: usize = 64 * 1024;
    let mut written = 0;
    
    while written < total_size {
        let end = (written + CHUNK_SIZE).min(total_size);
        let chunk = &data[written..end];
        
        file.write_all(chunk)
            .map_err(|e| AevorError::io(format!("Failed to write to file {}: {}", path.as_ref().display(), e)))?;
        
        written = end;
        pb.set_position(written as u64);
    }
    
    pb.finish_with_message(&format!("Successfully wrote {} to {}", super::format_size(total_size), path_str));
    Ok(())
}

/// Read a file with a progress indicator
pub fn read_with_progress<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let size = file_size(&path)?;
    let path_str = path.as_ref().display().to_string();
    let pb = display::progress_bar(size, &format!("Reading from {}", path_str));
    
    let mut file = File::open(path.as_ref())
        .map_err(|e| AevorError::io(format!("Failed to open file {}: {}", path.as_ref().display(), e)))?;
    
    let mut buffer = Vec::with_capacity(size as usize);
    let mut chunk = vec![0; 64 * 1024]; // 64KB chunks
    let mut read = 0;
    
    loop {
        let bytes_read = file.read(&mut chunk)
            .map_err(|e| AevorError::io(format!("Failed to read from file {}: {}", path.as_ref().display(), e)))?;
        
        if bytes_read == 0 {
            break;
        }
        
        buffer.extend_from_slice(&chunk[..bytes_read]);
        read += bytes_read as u64;
        pb.set_position(read);
        
        if bytes_read < chunk.len() {
            break;
        }
    }
    
    pb.finish_with_message(&format!("Successfully read {} from {}", super::format_size(read as usize), path_str));
    Ok(buffer)
}

/// Ensure a directory exists, creating it if necessary
pub fn ensure_dir<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    if !path.exists() {
        fs::create_dir_all(path)
            .map_err(|e| AevorError::io(format!("Failed to create directory {}: {}", path.display(), e)))?;
    } else if !path.is_dir() {
        return Err(AevorError::io(format!("{} exists but is not a directory", path.display())));
    }
    
    Ok(())
}

/// Get the canonical absolute path
pub fn canonical_path<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    let path = path.as_ref();
    
    path.canonicalize()
        .map_err(|e| AevorError::io(format!("Failed to get canonical path for {}: {}", path.display(), e)))
}
