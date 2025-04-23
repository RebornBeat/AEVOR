// Public modules
pub mod display;
pub mod config;
pub mod network;
pub mod file;

// Prompt utilities module
mod prompt;
pub use prompt::*;

/// Gets a human-readable duration string
pub fn format_duration(duration_ms: u64) -> String {
    if duration_ms < 1000 {
        // Less than 1 second
        format!("{}ms", duration_ms)
    } else if duration_ms < 60_000 {
        // Less than 1 minute
        format!("{:.1}s", duration_ms as f64 / 1000.0)
    } else if duration_ms < 3_600_000 {
        // Less than 1 hour
        let minutes = duration_ms / 60_000;
        let seconds = (duration_ms % 60_000) / 1000;
        format!("{}m {}s", minutes, seconds)
    } else {
        // Hours or more
        let hours = duration_ms / 3_600_000;
        let minutes = (duration_ms % 3_600_000) / 60_000;
        format!("{}h {}m", hours, minutes)
    }
}

/// Formats a number with thousand separators
pub fn format_number(num: u64) -> String {
    let mut s = String::new();
    let num_str = num.to_string();
    let a = num_str.chars().rev().enumerate();
    
    for (i, c) in a {
        if i % 3 == 0 && i != 0 {
            s.insert(0, ',');
        }
        s.insert(0, c);
    }
    
    s
}

/// Gets a user-friendly status string with color
pub fn format_status<T: std::fmt::Display>(status: T) -> colored::ColoredString {
    use colored::*;
    
    let status_str = status.to_string().to_lowercase();
    match status_str.as_str() {
        "success" | "succeeded" | "completed" | "valid" | "active" | "online" | "running" => 
            status.to_string().green(),
        "pending" | "waiting" | "processing" | "validating" => 
            status.to_string().yellow(),
        "error" | "failed" | "invalid" | "rejected" | "offline" | "stopped" => 
            status.to_string().red(),
        _ => status.to_string().normal(),
    }
}

/// Truncates a string to a maximum length with ellipsis
pub fn truncate_string(s: &str, max_length: usize) -> String {
    if s.len() <= max_length {
        s.to_string()
    } else {
        format!("{}...", &s[0..max_length - 3])
    }
}

/// Checks if we're in a terminal
pub fn is_terminal() -> bool {
    atty::is(atty::Stream::Stdout) && atty::is(atty::Stream::Stderr)
}

/// Randomly generate a string identifier
pub fn random_id() -> String {
    use rand::{thread_rng, Rng};
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    
    let mut rng = thread_rng();
    let id: String = (0..8)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    
    id
}

/// Computes the estimated time of arrival (ETA) based on progress and elapsed time
pub fn compute_eta(progress: f64, elapsed_ms: u64) -> String {
    if progress <= 0.0 || elapsed_ms == 0 {
        return "Calculating...".to_string();
    }
    
    let remaining_ms = (elapsed_ms as f64 / progress) as u64 - elapsed_ms;
    format_duration(remaining_ms)
}

/// Gets a human-readable security level label with color
pub fn format_security_level(level: u8) -> colored::ColoredString {
    use colored::*;
    
    match level {
        0 => "Minimal".yellow(),
        1 => "Basic".green(),
        2 => "Strong".blue(),
        3 => "Full".purple(),
        _ => "Unknown".red(),
    }
}

/// Gets the base data directory for Aevor
pub fn get_aevor_dir() -> std::path::PathBuf {
    let home_dir = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
    home_dir.join(".aevor")
}
