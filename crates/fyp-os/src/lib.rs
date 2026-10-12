use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Represents a network interface.
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// Human-readable name of the interface (e.g., "Ethernet", "Wi-Fi").
    pub name: String,
    /// List of IP addresses assigned to this interface.
    pub ip_addresses: Vec<IpAddr>,
}

/// Defines the possible states of a network connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Unknown or unspecified state.
    Unknown,
    /// Listening for incoming connections.
    Listen,
    /// Connection established.
    Established,
    /// Sent a connection request.
    SynSent,
    /// Received a connection request.
    SynRecv,
    /// Waiting for a termination request from the remote TCP.
    FinWait1,
    /// Waiting for a termination request from the local TCP.
    FinWait2,
    /// Waiting for enough time to pass to be sure the remote TCP received the acknowledgment.
    TimeWait,
    /// The connection is closed.
    Close,
    /// Waiting for a termination request from the remote TCP.
    CloseWait,
    /// Received a termination request from the remote TCP.
    LastAck,
    /// Waiting for a termination request from the remote TCP.
    Closing,
    /// For UDP connections (no state).
    Unconnected,
}

/// Represents a network connection.
#[derive(Debug, Clone)]
pub struct Connection {
    /// The protocol (TCP or UDP).
    pub protocol: String,
    /// The local address (IP:port).
    pub local_addr: SocketAddr,
    /// The remote address (IP:port), if any (None for UDP listening sockets).
    pub remote_addr: Option<SocketAddr>,
    /// The state of the connection.
    pub state: ConnectionState,
    /// The process ID owning this connection.
    pub pid: u32,
    /// The name of the process (e.g., "chrome.exe").
    pub process_name: String,
    /// The full path to the process executable.
    pub process_path: PathBuf,
    /// Optional icon bytes of the process (PNG format).
    pub process_icon: Option<Vec<u8>>,
    /// How long this connection has been active.
    pub duration: Duration,
    /// Whether the process is signed (None = not checked, Some = result).
    pub is_signed: Option<bool>,
    /// The user who owns the process.
    pub user: String,
}

/// Represents detailed process information.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// The process ID.
    pub pid: u32,
    /// The name of the process (e.g., "chrome.exe").
    pub name: String,
    /// The full path to the process executable.
    pub path: PathBuf,
    /// The command line arguments.
    pub cmdline: Vec<String>,
    /// The user who owns the process.
    pub user: String,
    /// CPU usage as a percentage.
    pub cpu_usage: f32,
    /// Memory usage in bytes.
    pub memory_usage: u64,
    /// The system time when the process started.
    pub start_time: std::time::SystemTime,
    /// Signature information if available.
    pub signature: Option<SignatureInfo>,
}

/// Information about a digital signature.
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    /// Whether the signature is valid.
    pub is_valid: bool,
    /// The publisher name.
    pub publisher: String,
    /// The thumbprint of the certificate.
    pub thumbprint: String,
    /// Optional timestamp of the signature.
    pub timestamp: Option<std::time::SystemTime>,
}

/// The status of a signature check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureStatus {
    /// The signature is valid and trusted.
    Valid,
    /// The signature is invalid or not trusted.
    Invalid,
    /// The signature could not be verified (e.g., not signed).
    NotSigned,
    /// An error occurred during verification.
    Error,
}

/// Trait abstracting OS-specific network and process operations.
pub trait NetworkAdapter: Send + Sync {
    /// List all network interfaces with their IP addresses.
    fn list_interfaces(&self) -> Result<Vec<NetworkInterface>, Box<dyn std::error::Error>>;

    /// Get the best local IP address for reaching external destinations.
    fn get_local_ip(&self) -> Result<IpAddr, Box<dyn std::error::Error>>;

    /// Check if a TCP port is open on the given IP address.
    fn is_port_open(&self, ip: IpAddr, port: u16, timeout: Duration) -> bool;

    /// Get the service name associated with a port/protocol (e.g., 80/tcp -> "http").
    fn get_service_name(&self, port: u16, protocol: &str) -> Option<String>;

    /// Scan for all active network connections on the system.
    fn scan_connections(&self) -> Result<Vec<Connection>, Box<dyn std::error::Error>>;

    /// Get detailed information about a process by its PID.
    fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, Box<dyn std::error::Error>>;

    /// Terminate a process by its PID.
    fn kill_process(&self, pid: u32, force: bool) -> Result<(), Box<dyn std::error::Error>>;

    /// Get the icon of a process as PNG bytes.
    fn get_process_icon(&self, pid: u32) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>>;

    /// Check the digital signature of an executable file.
    fn check_signature(&self, path: &Path) -> Result<SignatureStatus, Box<dyn std::error::Error>>;

    /// Attempt to elevate privileges (e.g., UAC prompt on Windows, sudo/pkexec on Linux).
    fn elevate_privileges(&self) -> Result<bool, Box<dyn std::error::Error>>;
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
            ip_addresses: vec![
                IpAddr::V4([127, 0, 0, 1].into()),
                IpAddr::V6([0, 0, 0, 0, 0, 0, 0, 1].into()),
            ],
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

    fn scan_connections(&self) -> Result<Vec<Connection>, Box<dyn std::error::Error>> {
        // Default implementation returns empty - platforms should override
        Ok(vec![])
    }

    fn get_process_info(&self, _pid: u32) -> Result<ProcessInfo, Box<dyn std::error::Error>> {
        Err("Not implemented on this platform".into())
    }

    fn kill_process(&self, _pid: u32, _force: bool) -> Result<(), Box<dyn std::error::Error>> {
        Err("Not implemented on this platform".into())
    }

    fn get_process_icon(&self, _pid: u32) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        Ok(None)
    }

    fn check_signature(&self, _path: &Path) -> Result<SignatureStatus, Box<dyn std::error::Error>> {
        Err("Not implemented on this platform".into())
    }

    fn elevate_privileges(&self) -> Result<bool, Box<dyn std::error::Error>> {
        Err("Not implemented on this platform".into())
    }
}

mod adapters;

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