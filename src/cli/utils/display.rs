use colored::*;
use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use comfy_table::{Table, ContentArrangement, Row, Cell, presets::UTF8_FULL};
use std::time::Duration;
use std::io::{self, Write};

/// Show the Aevor banner
pub fn show_banner() {
    let version = crate::VERSION;
    let banner = format!(r#"
     █████╗ ███████╗██╗   ██╗ ██████╗ ██████╗ 
    ██╔══██╗██╔════╝██║   ██║██╔═══██╗██╔══██╗
    ███████║█████╗  ██║   ██║██║   ██║██████╔╝
    ██╔══██║██╔══╝  ╚██╗ ██╔╝██║   ██║██╔══██╗
    ██║  ██║███████╗ ╚████╔╝ ╚██████╔╝██║  ██║
    ╚═╝  ╚═╝╚══════╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝
                                  v{version}
    "#);
    
    println!("{}", banner.bright_purple());
    println!("{}", "Dual-DAG Proof of Uncorruption Blockchain".bright_blue());
    println!("{}", "-------------------------------------".bright_blue());
    println!();
}

/// Show a mini banner (for smaller displays)
pub fn show_mini_banner() {
    let version = crate::VERSION;
    let banner = format!(r#"
     __ _  ___ _   __ ___ _ _
    / _` |/ -_) | / _/ _ \ '_|
    \__,_|\___|_| \__\___/_|   v{version}
    "#);
    
    println!("{}", banner.bright_purple());
}

/// Create a spinner with a message
pub fn spinner(message: &str) -> ProgressBar {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&[
                "⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"
            ])
            .template("{spinner:.purple} {msg:.bright_blue}")
            .unwrap()
    );
    spinner.set_message(message.to_string());
    spinner.enable_steady_tick(Duration::from_millis(100));
    
    spinner
}

/// Create a progress bar
pub fn progress_bar(len: u64, message: &str) -> ProgressBar {
    let bar = ProgressBar::new(len);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.purple/blue}] {pos}/{len} ({eta}) {msg}")
            .unwrap()
            .progress_chars("=>-")
    );
    bar.set_message(message.to_string());
    
    bar
}

/// Create a multi-progress instance for multiple progress indicators
pub fn multi_progress() -> MultiProgress {
    MultiProgress::new()
}

/// Print a success message
pub fn success(message: &str) {
    println!("{} {}", "✓".green().bold(), message);
}

/// Print an error message
pub fn error(message: &str) {
    eprintln!("{} {}", "✗".red().bold(), message);
}

/// Print a warning message
pub fn warning(message: &str) {
    println!("{} {}", "!".yellow().bold(), message);
}

/// Print an info message
pub fn info(message: &str) {
    println!("{} {}", "i".blue().bold(), message);
}

/// Print a section header
pub fn section(title: &str) {
    println!();
    println!("{}", title.underline().bold());
    println!();
}

/// Create a table for displaying data
pub fn create_table(headers: Vec<&str>) -> Table {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(headers.iter().map(|h| Cell::new(*h).fg(Color::Blue).add_attribute(comfy_table::Attribute::Bold)));
    
    table
}

/// Add a row to a table
pub fn add_row(table: &mut Table, cells: Vec<String>) {
    let row = Row::from(cells);
    table.add_row(row);
}

/// Print a table to stdout
pub fn print_table(table: Table) {
    println!("\n{table}\n");
}

/// Prompt the user for input
pub fn prompt(message: &str) -> String {
    print!("{} ", message.blue().bold());
    io::stdout().flush().unwrap();
    
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    
    input.trim().to_string()
}

/// Prompt the user for a password (with hidden input)
pub fn prompt_password(message: &str) -> String {
    rpassword::prompt_password(format!("{} ", message.blue().bold()))
        .unwrap_or_default()
}

/// Ask for confirmation
pub fn confirm(message: &str) -> bool {
    let input = prompt(&format!("{} (y/n)", message)).to_lowercase();
    input == "y" || input == "yes"
}

/// Print a formatted JSON value
pub fn print_json(json: &serde_json::Value) {
    if let Ok(pretty) = serde_json::to_string_pretty(json) {
        println!("{}", pretty);
    } else {
        println!("{:?}", json);
    }
}

/// Format a transaction hash for display
pub fn format_hash(hash: &[u8]) -> String {
    let hash_str = hex::encode(hash);
    if hash_str.len() > 16 {
        format!("{}...{}", &hash_str[0..8], &hash_str[hash_str.len() - 8..])
    } else {
        hash_str
    }
}

/// Format an address for display
pub fn format_address(address: &[u8]) -> String {
    format_hash(address)
}

/// Format a byte size with units
pub fn format_size(size: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    const GB: usize = MB * 1024;
    
    if size >= GB {
        format!("{:.2} GB", size as f64 / GB as f64)
    } else if size >= MB {
        format!("{:.2} MB", size as f64 / MB as f64)
    } else if size >= KB {
        format!("{:.2} KB", size as f64 / KB as f64)
    } else {
        format!("{} B", size)
    }
}

/// Clear the terminal screen
pub fn clear_screen() {
    print!("\x1B[2J\x1B[1;1H");
    io::stdout().flush().unwrap();
}

/// Show a countdown timer
pub fn countdown(seconds: u64, message: &str) {
    let pb = ProgressBar::new(seconds);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} {msg} [{bar:40.purple/blue}] {seconds_elapsed}/{seconds_total}")
            .unwrap()
            .progress_chars("=>-")
    );
    pb.set_message(message.to_string());
    
    for _ in 0..seconds {
        pb.inc(1);
        std::thread::sleep(Duration::from_secs(1));
    }
    
    pb.finish_with_message("Complete!");
}
