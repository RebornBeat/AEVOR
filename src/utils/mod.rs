// Aevor Utilities Module
//
// This module provides various utility functionality for the Aevor blockchain,
// including concurrency primitives, logging, metrics collection, and serialization.

// Re-export utility modules
pub mod concurrency;
pub mod logging;
pub mod metrics;
pub mod serialization;

// Commonly used utility functions

/// Generates a random identifier string suitable for correlation IDs, request IDs, etc.
pub fn random_id() -> String {
    use rand::Rng;
    let random_bytes = rand::thread_rng().gen::<[u8; 16]>();
    hex::encode(random_bytes)
}

/// Returns the current time as a millisecond timestamp
pub fn current_time_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64
}

/// Formats a byte size to a human-readable string (e.g., 1024 -> "1 KiB")
pub fn format_bytes(bytes: usize) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        // For bytes, use no decimal places
        format!("{} {}", size as usize, UNITS[unit_index])
    } else {
        // For KB and higher, use 2 decimal places
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

/// Formats a duration in milliseconds to a human-readable string
pub fn format_duration(millis: u64) -> String {
    if millis < 1000 {
        return format!("{}ms", millis);
    }
    
    let seconds = millis / 1000;
    if seconds < 60 {
        return format!("{:.2}s", millis as f64 / 1000.0);
    }
    
    let minutes = seconds / 60;
    let remaining_seconds = seconds % 60;
    if minutes < 60 {
        return format!("{}m {}s", minutes, remaining_seconds);
    }
    
    let hours = minutes / 60;
    let remaining_minutes = minutes % 60;
    format!("{}h {}m {}s", hours, remaining_minutes, remaining_seconds)
}

/// Gracefully handles a critical error, logging it and optionally exiting the process
pub fn handle_critical_error<E: std::fmt::Display>(error: E, exit: bool) {
    // Log to stderr directly in case the logging system is not available
    eprintln!("CRITICAL ERROR: {}", error);
    
    // Try to log using our logging system as well
    if let Ok(logger) = logging::global_logger() {
        logger.critical(&format!("Critical error: {}", error));
    }
    
    if exit {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_random_id() {
        let id1 = random_id();
        let id2 = random_id();
        
        // IDs should be 32 characters (16 bytes in hex)
        assert_eq!(id1.len(), 32);
        assert_eq!(id2.len(), 32);
        
        // Different calls should produce different IDs
        assert_ne!(id1, id2);
    }
    
    #[test]
    fn test_current_time_ms() {
        let time1 = current_time_ms();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let time2 = current_time_ms();
        
        // Later time should be greater
        assert!(time2 > time1);
        
        // Difference should be at least 10ms
        assert!(time2 - time1 >= 10);
    }
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KiB");
        assert_eq!(format_bytes(1536), "1.50 KiB");
        assert_eq!(format_bytes(1048576), "1.00 MiB");
        assert_eq!(format_bytes(1073741824), "1.00 GiB");
        assert_eq!(format_bytes(1099511627776), "1.00 TiB");
    }
    
    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(500), "500ms");
        assert_eq!(format_duration(1500), "1.50s");
        assert_eq!(format_duration(60000), "1m 0s");
        assert_eq!(format_duration(90000), "1m 30s");
        assert_eq!(format_duration(3600000), "1h 0m 0s");
        assert_eq!(format_duration(3661000), "1h 1m 1s");
    }
}
