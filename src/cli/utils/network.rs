use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::error::{AevorError, Result};
use super::display;

/// Check if a host is reachable
pub fn check_host_reachable(host: &str, port: u16, timeout_ms: u64) -> bool {
    let address = format!("{}:{}", host, port);
    match address.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                return check_socket_reachable(&addr, timeout_ms);
            }
        }
        Err(_) => {}
    }
    
    false
}

/// Check if a socket address is reachable
pub fn check_socket_reachable(addr: &SocketAddr, timeout_ms: u64) -> bool {
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    
    // We need to run this in a Tokio runtime
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    
    rt.block_on(async {
        let timeout_duration = Duration::from_millis(timeout_ms);
        match timeout(timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => true,
            _ => false,
        }
    })
}

/// Test network connectivity to a list of hosts
pub fn test_network_connectivity(hosts: &[(&str, u16)]) -> Vec<(String, bool)> {
    use indicatif::{ProgressBar, ProgressStyle};
    
    let pb = ProgressBar::new(hosts.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) Testing network connectivity...")
            .unwrap()
            .progress_chars("=>-")
    );
    
    let mut results = Vec::new();
    
    for (host, port) in hosts {
        pb.inc(1);
        let reachable = check_host_reachable(host, *port, 2000);
        results.push((format!("{}:{}", host, port), reachable));
    }
    
    pb.finish_with_message("Network connectivity test complete");
    
    results
}

/// Print network connectivity test results
pub fn print_connectivity_results(results: &[(String, bool)]) {
    use colored::Colorize;
    
    display::section("Network Connectivity Results");
    
    let mut table = display::create_table(vec!["Host", "Status"]);
    
    for (host, reachable) in results {
        let status = if *reachable {
            "REACHABLE".green().to_string()
        } else {
            "UNREACHABLE".red().to_string()
        };
        
        display::add_row(&mut table, vec![host.clone(), status]);
    }
    
    display::print_table(table);
}

/// Check if a port is available on the local machine
pub fn is_port_available(port: u16) -> bool {
    use std::net::TcpListener;
    
    // Try to bind to the port
    match TcpListener::bind(("127.0.0.1", port)) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Find an available port in a range
pub fn find_available_port(start_port: u16, end_port: u16) -> Option<u16> {
    (start_port..=end_port).find(|&port| is_port_available(port))
}

/// Get local IP addresses
pub fn get_local_ip_addresses() -> Result<Vec<String>> {
    use local_ip_address::list_afinet_netifas;
    
    let network_interfaces = list_afinet_netifas()
        .map_err(|e| AevorError::network(format!("Failed to get network interfaces: {}", e)))?;
    
    let mut addresses = Vec::new();
    
    for (name, ip) in network_interfaces {
        // Skip loopback interfaces
        if name != "lo" && !ip.to_string().starts_with("127.") {
            addresses.push(ip.to_string());
        }
    }
    
    Ok(addresses)
}

/// Get public IP address
pub async fn get_public_ip_address() -> Result<String> {
    use reqwest::Client;
    
    let client = Client::new();
    let response = client.get("https://api.ipify.org")
        .send()
        .await
        .map_err(|e| AevorError::network(format!("Failed to get public IP: {}", e)))?;
    
    let ip = response.text()
        .await
        .map_err(|e| AevorError::network(format!("Failed to read response: {}", e)))?;
    
    Ok(ip)
}

/// Measure ping to a host
pub fn measure_ping(host: &str) -> Result<Duration> {
    use surge_ping::{PingIdentifier, PingSequence, ICMP};
    
    // We need to run this in a Tokio runtime
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    
    rt.block_on(async {
        let client = surge_ping::Client::new(&ICMP::default())
            .map_err(|e| AevorError::network(format!("Failed to create ping client: {}", e)))?;
        
        let payload = [0; 56];
        
        let mut pinger = client
            .pinger(host, PingIdentifier(111))
            .await
            .map_err(|e| AevorError::network(format!("Failed to resolve host {}: {}", host, e)))?;
        
        pinger.timeout(Duration::from_secs(1));
        
        let result = pinger
            .ping(PingSequence(0), &payload)
            .await
            .map_err(|e| AevorError::network(format!("Ping failed: {}", e)))?;
        
        Ok(result.rtt)
    })
}

/// Measure ping to multiple hosts
pub fn measure_pings(hosts: &[&str]) -> Vec<(String, Result<Duration>)> {
    use indicatif::{ProgressBar, ProgressStyle};
    
    let pb = ProgressBar::new(hosts.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) Measuring network latency...")
            .unwrap()
            .progress_chars("=>-")
    );
    
    let mut results = Vec::new();
    
    for host in hosts {
        pb.inc(1);
        let result = measure_ping(host);
        results.push((host.to_string(), result));
    }
    
    pb.finish_with_message("Latency measurement complete");
    
    results
}

/// Print ping measurement results
pub fn print_ping_results(results: &[(String, Result<Duration>)]) {
    use colored::Colorize;
    
    display::section("Network Latency Results");
    
    let mut table = display::create_table(vec!["Host", "Latency"]);
    
    for (host, result) in results {
        let latency = match result {
            Ok(duration) => {
                let ms = duration.as_millis();
                // Color based on latency
                if ms < 50 {
                    format!("{} ms", ms).green().to_string()
                } else if ms < 100 {
                    format!("{} ms", ms).yellow().to_string()
                } else {
                    format!("{} ms", ms).red().to_string()
                }
            },
            Err(_) => "TIMEOUT".red().to_string(),
        };
        
        display::add_row(&mut table, vec![host.clone(), latency]);
    }
    
    display::print_table(table);
}
