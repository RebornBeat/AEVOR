// Aevor Logging Module
//
// This module provides a comprehensive logging infrastructure for the Aevor blockchain,
// including different log levels, configurable log targets, and structured logging.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, Once};

use chrono::{DateTime, Utc};
use colored::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

static LOGGER_INIT: Once = Once::new();
static mut GLOBAL_LOGGER: Option<Arc<Logger>> = None;

/// Log level for filtering log messages
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl LogLevel {
    /// Converts a string to a log level
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "trace" => Some(LogLevel::Trace),
            "debug" => Some(LogLevel::Debug),
            "info" => Some(LogLevel::Info),
            "warn" | "warning" => Some(LogLevel::Warn),
            "error" | "err" => Some(LogLevel::Error),
            "fatal" | "critical" => Some(LogLevel::Fatal),
            _ => None,
        }
    }
    
    /// Returns the level as a string
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Trace => "TRACE",
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
            LogLevel::Fatal => "FATAL",
        }
    }
    
    /// Returns the level as a colored string
    pub fn as_colored_str(&self) -> ColoredString {
        match self {
            LogLevel::Trace => "TRACE".magenta(),
            LogLevel::Debug => "DEBUG".blue(),
            LogLevel::Info => "INFO".green(),
            LogLevel::Warn => "WARN".yellow(),
            LogLevel::Error => "ERROR".red(),
            LogLevel::Fatal => "FATAL".red().bold(),
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A log entry representing a single log message
#[derive(Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp of the log entry
    pub timestamp: DateTime<Utc>,
    
    /// Log level
    pub level: LogLevel,
    
    /// Module or component name
    pub module: String,
    
    /// Log message
    pub message: String,
    
    /// Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Log target for directing log output
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogTarget {
    /// Log to console only
    Console,
    
    /// Log to file only
    File,
    
    /// Log to both console and file
    Both,
    
    /// Log to a custom target
    Custom,
}

/// Configuration for the logger
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggerConfig {
    /// Minimum log level
    pub min_level: LogLevel,
    
    /// Log target
    pub target: LogTarget,
    
    /// Log file path (when target is File or Both)
    pub file_path: Option<String>,
    
    /// Enable timestamps in console output
    pub timestamps: bool,
    
    /// Enable colored output on console
    pub colors: bool,
    
    /// Log format (text, json)
    pub format: LogFormat,
    
    /// Include source file and line in log messages
    pub include_source_info: bool,
    
    /// Maximum log file size in bytes (0 for no limit)
    pub max_file_size: u64,
    
    /// Maximum number of log files to keep (0 for no limit)
    pub max_files: usize,
    
    /// Enable asynchronous logging
    pub async_logging: bool,
}

/// Log format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogFormat {
    /// Plain text format
    Text,
    
    /// JSON format
    Json,
}

impl Default for LoggerConfig {
    fn default() -> Self {
        Self {
            min_level: LogLevel::Info,
            target: LogTarget::Console,
            file_path: None,
            timestamps: true,
            colors: true,
            format: LogFormat::Text,
            include_source_info: false,
            max_file_size: 10 * 1024 * 1024, // 10 MB
            max_files: 5,
            async_logging: true,
        }
    }
}

/// The main logger for Aevor blockchain
pub struct Logger {
    /// Logger configuration
    config: LoggerConfig,
    
    /// File handle for logging to file
    file: Option<Arc<Mutex<File>>>,
}

impl Logger {
    /// Creates a new logger with the given configuration
    pub fn new(config: LoggerConfig) -> Result<Self, io::Error> {
        let mut logger = Self {
            config,
            file: None,
        };
        
        // Open the log file if needed
        if matches!(logger.config.target, LogTarget::File | LogTarget::Both) {
            if let Some(file_path) = &logger.config.file_path {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(file_path)?;
                
                logger.file = Some(Arc::new(Mutex::new(file)));
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Log file path not provided",
                ));
            }
        }
        
        Ok(logger)
    }
    
    /// Logs a message at the specified level
    pub fn log(&self, level: LogLevel, module: &str, message: &str, metadata: Option<Value>) {
        // Skip if the level is below the minimum
        if level < self.config.min_level {
            return;
        }
        
        let entry = LogEntry {
            timestamp: Utc::now(),
            level,
            module: module.to_string(),
            message: message.to_string(),
            metadata,
        };
        
        // Log to console
        if matches!(self.config.target, LogTarget::Console | LogTarget::Both) {
            self.log_to_console(&entry);
        }
        
        // Log to file
        if matches!(self.config.target, LogTarget::File | LogTarget::Both) {
            if let Some(file) = &self.file {
                self.log_to_file(&entry, file);
            }
        }
    }
    
    /// Logs a trace message
    pub fn trace(&self, message: &str) {
        self.log(LogLevel::Trace, "", message, None);
    }
    
    /// Logs a debug message
    pub fn debug(&self, message: &str) {
        self.log(LogLevel::Debug, "", message, None);
    }
    
    /// Logs an info message
    pub fn info(&self, message: &str) {
        self.log(LogLevel::Info, "", message, None);
    }
    
    /// Logs a warning message
    pub fn warn(&self, message: &str) {
        self.log(LogLevel::Warn, "", message, None);
    }
    
    /// Logs an error message
    pub fn error(&self, message: &str) {
        self.log(LogLevel::Error, "", message, None);
    }
    
    /// Logs a fatal message
    pub fn fatal(&self, message: &str) {
        self.log(LogLevel::Fatal, "", message, None);
    }
    
    /// Logs a message with module and metadata
    pub fn log_with(&self, level: LogLevel, module: &str, message: &str, metadata: Option<Value>) {
        self.log(level, module, message, metadata);
    }
    
    /// Logs a message at the trace level with module and metadata
    pub fn trace_with(&self, module: &str, message: &str, metadata: Option<Value>) {
        self.log(LogLevel::Trace, module, message, metadata);
    }
    
    /// Logs a message at the debug level with module and metadata
    pub fn debug_with(&self, module: &str, message: &str, metadata: Option<Value>) {
        self.log(LogLevel::Debug, module, message, metadata);
    }
    
    /// Logs a message at the info level with module and metadata
    pub fn info_with(&self, module: &str, message: &str, metadata: Option<Value>) {
        self.log(LogLevel::Info, module, message, metadata);
    }
    
    /// Logs a message at the warn level with module and metadata
    pub fn warn_with(&self, module: &str, message: &str, metadata: Option<Value>) {
        self.log(LogLevel::Warn, module, message, metadata);
    }
    
    /// Logs a message at the error level with module and metadata
    pub fn error_with(&self, module: &str, message: &str, metadata: Option<Value>) {
        self.log(LogLevel::Error, module, message, metadata);
    }
    
    /// Logs a message at the fatal level with module and metadata
    pub fn fatal_with(&self, module: &str, message: &str, metadata: Option<Value>) {
        self.log(LogLevel::Fatal, module, message, metadata);
    }
    
    /// Logs an entry to the console
    fn log_to_console(&self, entry: &LogEntry) {
        let formatted = match self.config.format {
            LogFormat::Text => self.format_text(entry),
            LogFormat::Json => self.format_json(entry),
        };
        
        println!("{}", formatted);
    }
    
    /// Logs an entry to the file
    fn log_to_file(&self, entry: &LogEntry, file: &Arc<Mutex<File>>) {
        let formatted = match self.config.format {
            LogFormat::Text => self.format_text_file(entry),
            LogFormat::Json => self.format_json(entry),
        };
        
        if let Ok(mut file) = file.lock() {
            let _ = writeln!(file, "{}", formatted);
            let _ = file.flush();
        }
    }
    
    /// Formats a log entry as text for console output
    fn format_text(&self, entry: &LogEntry) -> String {
        let level_str = if self.config.colors {
            entry.level.as_colored_str().to_string()
        } else {
            entry.level.as_str().to_string()
        };
        
        let timestamp = if self.config.timestamps {
            format!("[{}] ", entry.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"))
        } else {
            String::new()
        };
        
        let module = if !entry.module.is_empty() {
            format!("[{}] ", entry.module)
        } else {
            String::new()
        };
        
        format!("{}{}{} {}", timestamp, level_str, module, entry.message)
    }
    
    /// Formats a log entry as text for file output
    fn format_text_file(&self, entry: &LogEntry) -> String {
        let timestamp = entry.timestamp.format("%Y-%m-%d %H:%M:%S%.3f");
        let level_str = entry.level.as_str();
        
        let module = if !entry.module.is_empty() {
            format!("[{}] ", entry.module)
        } else {
            String::new()
        };
        
        let metadata = if let Some(metadata) = &entry.metadata {
            format!(" {}", serde_json::to_string(metadata).unwrap_or_default())
        } else {
            String::new()
        };
        
        format!(
            "{} [{}] {}{}{}", 
            timestamp, 
            level_str, 
            module, 
            entry.message,
            metadata
        )
    }
    
    /// Formats a log entry as JSON
    fn format_json(&self, entry: &LogEntry) -> String {
        serde_json::to_string(entry).unwrap_or_else(|_| {
            format!(
                "{{\"error\":\"Failed to serialize log entry\",\"message\":\"{}\"}}",
                entry.message
            )
        })
    }
    
    /// Gets the current configuration
    pub fn get_config(&self) -> &LoggerConfig {
        &self.config
    }
    
    /// Updates the logger configuration
    pub fn update_config(&mut self, config: LoggerConfig) -> Result<(), io::Error> {
        // If the log file path changed, reopen the file
        if self.config.file_path != config.file_path &&
           matches!(config.target, LogTarget::File | LogTarget::Both) {
            if let Some(file_path) = &config.file_path {
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(file_path)?;
                
                self.file = Some(Arc::new(Mutex::new(file)));
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Log file path not provided",
                ));
            }
        }
        
        self.config = config;
        Ok(())
    }
    
    /// Flushes any pending log messages
    pub fn flush(&self) {
        if let Some(file) = &self.file {
            if let Ok(mut file) = file.lock() {
                let _ = file.flush();
            }
        }
    }
}

impl fmt::Debug for Logger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Logger")
            .field("config", &self.config)
            .field("file", &self.file.is_some())
            .finish()
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Initializes the global logger
pub fn init_global_logger(config: LoggerConfig) -> Result<Arc<Logger>, io::Error> {
    let logger = Arc::new(Logger::new(config)?);
    
    LOGGER_INIT.call_once(|| {
        unsafe {
            GLOBAL_LOGGER = Some(Arc::clone(&logger));
        }
    });
    
    Ok(logger)
}

/// Gets the global logger
pub fn global_logger() -> Result<Arc<Logger>, io::Error> {
    unsafe {
        if let Some(logger) = &GLOBAL_LOGGER {
            Ok(Arc::clone(logger))
        } else {
            let config = LoggerConfig::default();
            init_global_logger(config)
        }
    }
}

/// Logs a message at the trace level
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {{
        if let Ok(logger) = $crate::utils::logging::global_logger() {
            logger.trace(&format!($($arg)*));
        }
    }};
}

/// Logs a message at the debug level
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {{
        if let Ok(logger) = $crate::utils::logging::global_logger() {
            logger.debug(&format!($($arg)*));
        }
    }};
}

/// Logs a message at the info level
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {{
        if let Ok(logger) = $crate::utils::logging::global_logger() {
            logger.info(&format!($($arg)*));
        }
    }};
}

/// Logs a message at the warn level
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {{
        if let Ok(logger) = $crate::utils::logging::global_logger() {
            logger.warn(&format!($($arg)*));
        }
    }};
}

/// Logs a message at the error level
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {{
        if let Ok(logger) = $crate::utils::logging::global_logger() {
            logger.error(&format!($($arg)*));
        }
    }};
}

/// Logs a message at the fatal level
#[macro_export]
macro_rules! fatal {
    ($($arg:tt)*) => {{
        if let Ok(logger) = $crate::utils::logging::global_logger() {
            logger.fatal(&format!($($arg)*));
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::io::Read;
    
    #[test]
    fn test_log_level_from_str() {
        assert_eq!(LogLevel::from_str("trace"), Some(LogLevel::Trace));
        assert_eq!(LogLevel::from_str("debug"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::from_str("INFO"), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_str("Warning"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("error"), Some(LogLevel::Error));
        assert_eq!(LogLevel::from_str("FATAL"), Some(LogLevel::Fatal));
        assert_eq!(LogLevel::from_str("critical"), Some(LogLevel::Fatal));
        assert_eq!(LogLevel::from_str("unknown"), None);
    }
    
    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Fatal);
    }
    
    #[test]
    fn test_logger_console() {
        let config = LoggerConfig {
            min_level: LogLevel::Debug,
            target: LogTarget::Console,
            file_path: None,
            timestamps: false,
            colors: false,
            format: LogFormat::Text,
            include_source_info: false,
            max_file_size: 0,
            max_files: 0,
            async_logging: false,
        };
        
        let logger = Logger::new(config).unwrap();
        
        // These should be logged
        logger.debug("Debug message");
        logger.info("Info message");
        logger.warn("Warning message");
        logger.error("Error message");
        logger.fatal("Fatal message");
        
        // This should be filtered out
        logger.trace("Trace message");
    }
    
    #[test]
    fn test_logger_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.log");
        
        let config = LoggerConfig {
            min_level: LogLevel::Info,
            target: LogTarget::File,
            file_path: Some(file_path.to_str().unwrap().to_string()),
            timestamps: true,
            colors: false,
            format: LogFormat::Text,
            include_source_info: false,
            max_file_size: 0,
            max_files: 0,
            async_logging: false,
        };
        
        let logger = Logger::new(config).unwrap();
        
        // These should be logged
        logger.info("Info message");
        logger.warn("Warning message");
        logger.error("Error message");
        logger.fatal("Fatal message");
        
        // These should be filtered out
        logger.trace("Trace message");
        logger.debug("Debug message");
        
        // Flush to ensure all messages are written
        logger.flush();
        
        // Read the log file and check for messages
        let mut file = File::open(&file_path).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        
        assert!(contents.contains("Info message"));
        assert!(contents.contains("Warning message"));
        assert!(contents.contains("Error message"));
        assert!(contents.contains("Fatal message"));
        assert!(!contents.contains("Trace message"));
        assert!(!contents.contains("Debug message"));
    }
    
    #[test]
    fn test_logger_json_format() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.log");
        
        let config = LoggerConfig {
            min_level: LogLevel::Info,
            target: LogTarget::File,
            file_path: Some(file_path.to_str().unwrap().to_string()),
            timestamps: true,
            colors: false,
            format: LogFormat::Json,
            include_source_info: false,
            max_file_size: 0,
            max_files: 0,
            async_logging: false,
        };
        
        let logger = Logger::new(config).unwrap();
        
        // Log with metadata
        let metadata = serde_json::json!({
            "user_id": 123,
            "status": "active",
        });
        
        logger.log_with(LogLevel::Info, "auth", "User logged in", Some(metadata));
        
        // Flush to ensure all messages are written
        logger.flush();
        
        // Read the log file and check for JSON structure
        let mut file = File::open(&file_path).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();
        
        let log_entry: serde_json::Value = serde_json::from_str(&contents).unwrap();
        
        assert_eq!(log_entry["level"], "Info");
        assert_eq!(log_entry["module"], "auth");
        assert_eq!(log_entry["message"], "User logged in");
        assert_eq!(log_entry["metadata"]["user_id"], 123);
        assert_eq!(log_entry["metadata"]["status"], "active");
    }
    
    #[test]
    fn test_global_logger() {
        let config = LoggerConfig {
            min_level: LogLevel::Info,
            target: LogTarget::Console,
            file_path: None,
            timestamps: false,
            colors: false,
            format: LogFormat::Text,
            include_source_info: false,
            max_file_size: 0,
            max_files: 0,
            async_logging: false,
        };
        
        let logger = init_global_logger(config).unwrap();
        
        // Test global logger functions
        logger.info("Info from global logger");
        
        // Test getting the global logger
        let global = global_logger().unwrap();
        global.info("Another info message");
        
        // They should be the same instance
        assert!(Arc::ptr_eq(&logger, &global));
    }
}
