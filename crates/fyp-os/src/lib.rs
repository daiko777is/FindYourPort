use std::net::{IpAddr, UdpSocket};
use std::time::Duration;

/// Represents a network interface.
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// Human-readable name of the interface (e.g., "Ethernet", "Wi-Fi").
    pub name: String,
    /// List of IP addresses assigned to this interface.
    pub ip_addresses: Vec<IpAddr>,
}

/// Trait abstracting OS-specific network operations.
pub trait NetworkAdapter: Send + Sync {
    /// List all network interfaces with their IP addresses.
    fn list_interfaces(&self) -> Result<Vec<NetworkInterface>, Box<dyn std::error::Error>>;

    /// Get the best local IP address for reaching external destinations.
    fn get_local_ip(&self) -> Result<IpAddr, Box<dyn std::error::Error>>;

    /// Check if a TCP port is open on the given IP address.
    fn is_port_open(&self, ip: IpAddr, port: u16, timeout: Duration) -> bool;

    /// Get the service name associated with a port/protocol (e.g., 80/tcp -> "http").
    fn get_service_name(&self, port: u16, protocol: &str) -> Option<String>;
}

/// Default adapter using standard library only (works on most platforms).
#[derive(Debug, Clone, Copy)]
pub struct DefaultAdapter;

impl NetworkAdapter for DefaultAdapter {
    fn list_interfaces(&self) -> Result<Vec<NetworkInterface>, Box<dyn std::error::Error>> {
        // This is a simplified implementation that returns localhost only.
        // In a real implementation, we would use platform-specific APIs.
        Ok(vec![NetworkInterface {
            name: "localhost".to_string(),
            ip_addresses: vec![IpAddr::V4([127, 0, 0, 1].into()), IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 1].into())],
        }])
    }

    fn get_local_ip(&self) -> Result<IpAddr, Box<dyn std::error::Error>> {
        // Create a UDP socket to determine the outgoing interface
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        // Connect to a public DNS server (doesn't send actual packet until we send data)
        socket.connect("8.8.8.8:80")?;
        let local_addr = socket.local_addr()?;
        Ok(local_addr.ip())
    }

    fn is_port_open(&self, ip: IpAddr, port: u16, timeout: Duration) -> bool {
        match std::net::TcpStream::connect_timeout(&format!("{}:{}", ip, port).parse().unwrap(), timeout) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn get_service_name(&self, port: u16, protocol: &str) -> Option<String> {
        // Common port mappings (could be loaded from /etc/services or similar)
        let services = vec![
            (20, "ftp", "ftp-data"),
            (21, "ftp", "ftp"),
            (22, "ssh", "ssh"),
            (23, "telnet", "telnet"),
            (25, "smtp", "smtp"),
            (53, "dns", "domain"),
            (80, "http", "http"),
            (110, "pop3", "pop3"),
            (143, "imap", "imap"),
            (443, "https", "https"),
            (465, "smtps", "smtps"),
            (587, "submission", "submission"),
            (993, "imaps", "imaps"),
            (995, "pop3s", "pop3s"),
            (3306, "mysql", "mysql"),
            (5432, "postgresql", "postgres"),
            (6379, "redis", "redis"),
            (8080, "http-alt", "http-alt"),
        ];

        for &(p, tcp_name, udp_name) in &services {
            if p == port {
                if protocol.eq_ignore_ascii_case("tcp") {
                    return Some(tcp_name.to_string());
                } else if protocol.eq_ignore_ascii_case("udp") {
                    return Some(udp_name.to_string());
                }
            }
        }
        None
    }
}

pub mod adapters;

/// Returns the appropriate network adapter for the current operating system.
pub fn system_adapter() -> Box<dyn NetworkAdapter> {
    #[cfg(target_os = "windows")]
    {
        Box::new(adapters::windows_adapter::WindowsAdapter)
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(adapters::linux_adapter::LinuxAdapter)
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Box::new(DefaultAdapter)
    }
}