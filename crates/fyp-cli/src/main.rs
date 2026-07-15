use clap::{Parser, Subcommand};
use std::net::IpAddr;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "fyp", version, about = "Find Your Port — network interface & port scanner")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List all network interfaces and their IP addresses
    Interfaces,
    /// Show the best local IP for outbound connections
    LocalIp,
    /// Scan ports on a given IP
    Scan {
        #[arg(long)]
        ip: Option<String>,
        #[arg(long, default_value = "1")]
        start: u16,
        #[arg(long, default_value = "1024")]
        end: u16,
        #[arg(long, default_value_t = 200)]
        timeout_ms: u64,
    },
}

fn main() {
    let cli = Cli::parse();
    let adapter = fyp_os::system_adapter();

    match cli.command {
        Some(Commands::Interfaces) => {
            match adapter.list_interfaces() {
                Ok(interfaces) => {
                    if interfaces.is_empty() {
                        println!("No network interfaces found.");
                    } else {
                        println!("Network interfaces:");
                        println!("{:-<60}", "");
                        for iface in interfaces {
                            println!("  {}:", iface.name);
                            for ip in &iface.ip_addresses {
                                println!("    - {}", ip);
                            }
                        }
                    }
                }
                Err(e) => eprintln!("Error listing interfaces: {}", e),
            }
        }
        Some(Commands::LocalIp) => match adapter.get_local_ip() {
            Ok(ip) => println!("Local IP: {}", ip),
            Err(e) => eprintln!("Error getting local IP: {}", e),
        },
        Some(Commands::Scan { ip, start, end, timeout_ms }) => {
            let target_ip = match ip {
                Some(s) => match s.parse::<IpAddr>() {
                    Ok(ip) => ip,
                    Err(_) => {
                        eprintln!("Invalid IP address: {}", s);
                        std::process::exit(1);
                    }
                },
                None => match adapter.get_local_ip() {
                    Ok(ip) => ip,
                    Err(e) => {
                        eprintln!("Could not determine local IP: {}", e);
                        std::process::exit(1);
                    }
                },
            };

            println!("Scanning {}:{}-{} (timeout {}ms)...", target_ip, start, end, timeout_ms);
            let timeout = Duration::from_millis(timeout_ms);
            let mut open_ports = Vec::new();

            for port in start..=end {
                if adapter.is_port_open(target_ip, port, timeout) {
                    let service = adapter.get_service_name(port, "tcp").unwrap_or_else(|| "unknown".to_string());
                    println!("  [OPEN] {}:{} — {}", target_ip, port, service);
                    open_ports.push((port, service));
                }
            }

            println!("{:-<60}", "");
            if open_ports.is_empty() {
                println!("No open ports found in range {}-{} on {}", start, end, target_ip);
            } else {
                println!("Found {} open port(s) on {}", open_ports.len(), target_ip);
            }
        }
        None => {
            println!("Find Your Port — Network Interface & Port Scanner");
            println!();
            println!("Commands:");
            println!("  interfaces   List all network interfaces and their IP addresses");
            println!("  local-ip     Show the best local IP for outbound connections");
            println!("  scan         Scan ports on a given IP (or localhost if none given)");
            println!();
            println!("Run `fyp --help` for more details.");
        }
    }
}
