//! Linux implementation of the `NetworkAdapter` trait.
//!
//! Connection scanning uses `/proc/net/tcp*`, `/proc/net/udp*` and maps sockets to
//! PIDs via `/proc/<pid>/fd`. Process management uses `/proc/<pid>/` files and `kill(2)`.

use crate::{Connection, ConnectionState, NetworkAdapter, NetworkInterface, ProcessInfo, SignatureInfo, SignatureStatus};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use libc::{freeifaddrs, getifaddrs, ifaddrs, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6, kill, SIGTERM, SIGKILL};

/// Linux-specific implementation of NetworkAdapter using /proc filesystem.
#[derive(Debug, Clone, Copy)]
pub struct LinuxAdapter;

/// Represents a socket entry from /proc/net/tcp* files.
#[derive(Debug, Clone)]
struct ProcNetEntry {
    protocol: String,      // "TCP" or "UDP"
    local_addr: IpAddr,
    local_port: u16,
    remote_addr: Option<IpAddr>,
    remote_port: Option<u16>,
    state: u8,
    inode: u64,
}

/// Parses a single line from /proc/net/tcp* or /proc/net/udp* files.
fn parse_proc_net_line(line: &str, protocol: &str) -> Option<ProcNetEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }

    // Skip header line
    if parts[0].starts_with("sl") {
        return None;
    }

    // Parse local address:port (format: 0100007F:1F90 for 127.0.0.1:8080)
    let local_parts: Vec<&str> = parts[1].split(':').collect();
    if local_parts.len() != 2 {
        return None;
    }
    let local_addr_hex = local_parts[0];
    let local_port_hex = local_parts[1];

    let local_addr = parse_ip_hex(local_addr_hex)?;
    let local_port = u16::from_str_radix(local_port_hex, 16).ok()?;

    // Parse remote address:port
    let remote_parts: Vec<&str> = parts[2].split(':').collect();
    let (remote_addr, remote_port) = if remote_parts.len() == 2 {
        let remote_addr_hex = remote_parts[0];
        let remote_port_hex = remote_parts[1];
        let remote_addr = parse_ip_hex(remote_addr_hex).ok();
        let remote_port = u16::from_str_radix(remote_port_hex, 16).ok();
        (remote_addr, remote_port)
    } else {
        (None, None)
    };

    // Parse state (hex)
    let state = u8::from_str_radix(parts[3], 16).ok()?;

    // Parse inode
    let inode = parts[9].parse::<u64>().ok()?;

    Some(ProcNetEntry {
        protocol: protocol.to_string(),
        local_addr,
        local_port,
        remote_addr,
        remote_port,
        state,
        inode,
    })
}

/// Parses an IPv4 or IPv6 address from hex string (little-endian byte order in /proc).
fn parse_ip_hex(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8 => {
            // IPv4: 0100007F -> 127.0.0.1 (little-endian)
            let bytes = hex::decode(hex).ok()?;
            if bytes.len() == 4 {
                let ip = Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0]);
                return Some(IpAddr::V4(ip));
            }
        }
        32 => {
            // IPv6: 32 hex chars
            let bytes = hex::decode(hex).ok()?;
            if bytes.len() == 16 {
                // /proc/net/tcp6 stores IPv6 in little-endian 4-byte words
                let mut segments = [0u16; 8];
                for i in 0..8 {
                    let offset = i * 4;
                    segments[i] = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
                }
                let ip = Ipv6Addr::from(segments);
                return Some(IpAddr::V6(ip));
            }
        }
        _ => {}
    }
    None
}

/// Maps TCP state from /proc (hex) to ConnectionState.
fn proc_tcp_state_to_connection_state(state: u8) -> ConnectionState {
    match state {
        0x01 => ConnectionState::Established,  // TCP_ESTABLISHED
        0x02 => ConnectionState::SynSent,      // TCP_SYN_SENT
        0x03 => ConnectionState::SynRecv,      // TCP_SYN_RECV
        0x04 => ConnectionState::FinWait1,     // TCP_FIN_WAIT1
        0x05 => ConnectionState::FinWait2,     // TCP_FIN_WAIT2
        0x06 => ConnectionState::TimeWait,     // TCP_TIME_WAIT
        0x07 => ConnectionState::Close,        // TCP_CLOSE
        0x08 => ConnectionState::CloseWait,    // TCP_CLOSE_WAIT
        0x09 => ConnectionState::LastAck,      // TCP_LAST_ACK
        0x0A => ConnectionState::Listen,       // TCP_LISTEN
        0x0B => ConnectionState::Closing,      // TCP_CLOSING
        _ => ConnectionState::Unknown,
    }
}

/// Reads a /proc/net file and returns parsed entries.
fn read_proc_net_file(path: &Path, protocol: &str) -> Vec<ProcNetEntry> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let reader = BufReader::new(file);
    reader
        .lines()
        .filter_map(|line| line.ok().and_then(|l| parse_proc_net_line(&l, protocol)))
        .collect()
}

/// Builds a mapping from socket inode to PID by scanning /proc/<pid>/fd.
fn build_inode_to_pid_map() -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let proc_dir = Path::new("/proc");
    if let Ok(entries) = fs::read_dir(proc_dir) {
        for entry in entries.flatten() {
            let pid_str = entry.file_name().to_string_lossy().into_owned();
            if let Ok(pid) = pid_str.parse::<u32>() {
                let fd_path = entry.path().join("fd");
                if let Ok(fd_entries) = fs::read_dir(fd_path) {
                    for fd_entry in fd_entries.flatten() {
                        if let Ok(target) = fs::read_link(fd_entry.path()) {
                            let target_str = target.to_string_lossy();
                            // Look for socket:[inode] pattern
                            if let Some(start) = target_str.find("socket:[") {
                                let end = target_str[start..].find(']').unwrap_or(target_str.len());
                                let inode_str = &target_str[start + 8..start + end];
                                if let Ok(inode) = inode_str.parse::<u64>() {
                                    map.insert(inode, pid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

/// Reads process information from /proc/<pid>/
fn read_process_info(pid: u32) -> Option<ProcessInfo> {
    let proc_pid = Path::new("/proc").join(pid.to_string());

    // Read exe symlink
    let exe_path = proc_pid.join("exe");
    let path = fs::read_link(&exe_path).ok()?;
    let process_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());

    // Read cmdline
    let cmdline_path = proc_pid.join("cmdline");
    let cmdline = fs::read_to_string(&cmdline_path)
        .ok()
        .map(|s| s.split('\0').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect())
        .unwrap_or_default();

    // Read stat for start time, CPU, memory
    let stat_path = proc_pid.join("stat");
    let (start_time, cpu_usage, memory_usage) = parse_stat_file(&stat_path).unwrap_or((SystemTime::now(), 0.0, 0));

    // Read status for user
    let status_path = proc_pid.join("status");
    let user = parse_uid_from_status(&status_path).unwrap_or_else(|| "unknown".to_string());

    Some(ProcessInfo {
        pid,
        name: process_name,
        path,
        cmdline,
        user,
        cpu_usage,
        memory_usage,
        start_time,
        signature: None, // TODO: ELF signature verification
        icon: None,      // TODO: .desktop icon resolution
    })
}

/// Parses /proc/<pid>/stat for start_time, CPU, memory.
fn parse_stat_file(path: &Path) -> Option<(SystemTime, f32, u64)> {
    let content = fs::read_to_string(path).ok()?;
    let parts: Vec<&str> = content.split_whitespace().collect();
    if parts.len() < 24 {
        return None;
    }

    // starttime is field 22 (1-indexed), in clock ticks
    let starttime_ticks = parts[21].parse::<u64>().ok()?;
    // utime (14) + stime (15) for CPU time
    let utime = parts[13].parse::<u64>().ok()?;
    let stime = parts[14].parse::<u64>().ok()?;
    // vsize (23) for virtual memory, rss (24) for resident
    let rss_pages = parts[23].parse::<u64>().ok()?;

    // Get clock ticks per second
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as u64;
    if clk_tck == 0 {
        return None;
    }

    // Convert starttime to SystemTime
    // starttime is time since boot in clock ticks
    let uptime = fs::read_to_string("/proc/uptime").ok()?.split_whitespace().next()?.parse::<f64>().ok()?;
    let starttime_secs = starttime_ticks as f64 / clk_tck as f64;
    let boot_time = SystemTime::now() - Duration::from_secs_f64(uptime);
    let start_time = boot_time + Duration::from_secs_f64(starttime_secs);

    // CPU usage as percentage (simplified - would need two samples for accurate %)
    let total_time = utime + stime;
    let cpu_usage = (total_time as f32 / clk_tck as f32) * 100.0 / uptime.max(1.0) as f32;

    // Memory in bytes (page size typically 4096)
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    let memory_usage = rss_pages * page_size;

    Some((start_time, cpu_usage, memory_usage))
}

/// Parses UID from /proc/<pid>/status and converts to username.
fn parse_uid_from_status(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        if line.starts_with("Uid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let uid = parts[1].parse::<u32>().ok()?;
                return Some(get_username_from_uid(uid));
            }
        }
    }
    None
}

/// Gets username from UID using getpwuid_r.
fn get_username_from_uid(uid: u32) -> String {
    use std::mem::MaybeUninit;
    use libc::{getpwuid_r, passwd};
    
    let mut buf = vec![0u8; 1024];
    let mut pwd: MaybeUninit<passwd> = MaybeUninit::uninit();
    let mut result: *mut passwd = std::ptr::null_mut();
    
    let ret = unsafe {
        getpwuid_r(uid, pwd.as_mut_ptr(), buf.as_mut_ptr() as *mut i8, buf.len(), &mut result)
    };
    
    if ret == 0 && !result.is_null() {
        let pwd = unsafe { &*result };
        if !pwd.pw_name.is_null() {
            return unsafe { CStr::from_ptr(pwd.pw_name) }
                .to_string_lossy()
                .into_owned();
        }
    }
    uid.to_string()
}

impl NetworkAdapter for LinuxAdapter {
    fn list_interfaces(&self) -> Result<Vec<NetworkInterface>, Box<dyn std::error::Error>> {
        let mut ifap: *mut ifaddrs = std::ptr::null_mut();
        unsafe {
            if getifaddrs(&mut ifap) != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }

        let mut interfaces = Vec::new();
        let mut current = ifap;
        while !current.is_null() {
            let iface = unsafe { *current };
            let name = unsafe { CStr::from_ptr(iface.ifa_name) }
                .to_string_lossy()
                .into_owned();

            if iface.ifa_addr.is_null() {
                current = unsafe { iface.ifa_next };
                continue;
            }

            let mut ip_addresses = Vec::new();

            unsafe {
                match (*iface.ifa_addr).sa_family as i32 {
                    AF_INET => {
                        let addr = &*(iface.ifa_addr as *const sockaddr_in);
                        let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                        ip_addresses.push(IpAddr::V4(ip));
                    }
                    AF_INET6 => {
                        let addr = &*(iface.ifa_addr as *const sockaddr_in6);
                        let mut segments = [0u16; 8];
                        for i in 0..8 {
                            segments[i] = u16::from_be(
                                ((addr.sin6_addr.s6_addr[i * 2] as u16) << 8)
                                    | addr.sin6_addr.s6_addr[i * 2 + 1] as u16,
                            );
                        }
                        let ip = Ipv6Addr::from(segments);
                        ip_addresses.push(IpAddr::V6(ip));
                    }
                    _ => {}
                }
            }

            if !ip_addresses.is_empty() {
                interfaces.push(NetworkInterface { name, ip_addresses });
            }

            current = unsafe { iface.ifa_next };
        }

        unsafe {
            freeifaddrs(ifap);
        }

        Ok(interfaces)
    }

    fn get_local_ip(&self) -> Result<IpAddr, Box<dyn std::error::Error>> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect("8.8.8.8:80")?;
        let local_addr = socket.local_addr()?;
        Ok(local_addr.ip())
    }

    fn is_port_open(&self, ip: IpAddr, port: u16, timeout: Duration) -> bool {
        let addr = format!("{}:{}", ip, port);
        let Ok(socket_addr) = addr.parse::<std::net::SocketAddr>() else {
            return false;
        };
        std::net::TcpStream::connect_timeout(&socket_addr, timeout).is_ok()
    }

    fn get_service_name(&self, port: u16, protocol: &str) -> Option<String> {
        // Try to read from /etc/services first
        if let Ok(content) = fs::read_to_string("/etc/services") {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let port_proto: Vec<&str> = parts[1].split('/').collect();
                    if port_proto.len() == 2 {
                        if let Ok(p) = port_proto[0].parse::<u16>() {
                            if p == port && protocol.eq_ignore_ascii_case(port_proto[1]) {
                                return Some(parts[0].to_string());
                            }
                        }
                    }
                }
            }
        }

        // Fallback to hardcoded common ports
        let services = [
            (20, "ftp", "ftp-data"), (21, "ftp", "ftp"), (22, "ssh", "ssh"),
            (23, "telnet", "telnet"), (25, "smtp", "smtp"), (53, "dns", "domain"),
            (80, "http", "http"), (110, "pop3", "pop3"), (143, "imap", "imap"),
            (443, "https", "https"), (465, "smtps", "smtps"), (587, "submission", "submission"),
            (993, "imaps", "imaps"), (995, "pop3s", "pop3s"), (3306, "mysql", "mysql"),
            (5432, "postgresql", "postgres"), (6379, "redis", "redis"),
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
        let mut connections = Vec::new();
        let inode_to_pid = build_inode_to_pid_map();

        // Read all protocol files
        let tcp_entries = read_proc_net_file(Path::new("/proc/net/tcp"), "TCP");
        let tcp6_entries = read_proc_net_file(Path::new("/proc/net/tcp6"), "TCP");
        let udp_entries = read_proc_net_file(Path::new("/proc/net/udp"), "UDP");
        let udp6_entries = read_proc_net_file(Path::new("/proc/net/udp6"), "UDP");

        let all_entries: Vec<ProcNetEntry> = tcp_entries
            .into_iter()
            .chain(tcp6_entries)
            .chain(udp_entries)
            .chain(udp6_entries)
            .collect();

        // Cache process info to avoid repeated reads
        let mut process_cache: HashMap<u32, ProcessInfo> = HashMap::new();

        for entry in all_entries {
            let pid = inode_to_pid.get(&entry.inode).copied().unwrap_or(0);
            
            let process_info = if pid > 0 {
                process_cache
                    .entry(pid)
                    .or_insert_with(|| read_process_info(pid).unwrap_or_else(|| ProcessInfo {
                        pid,
                        name: "unknown".to_string(),
                        path: PathBuf::from("unknown"),
                        cmdline: vec![],
                        user: "unknown".to_string(),
                        cpu_usage: 0.0,
                        memory_usage: 0,
                        start_time: SystemTime::now(),
                        signature: None,
                        icon: None,
                    }))
                    .clone()
            } else {
                ProcessInfo {
                    pid: 0,
                    name: "unknown".to_string(),
                    path: PathBuf::from("unknown"),
                    cmdline: vec![],
                    user: "unknown".to_string(),
                    cpu_usage: 0.0,
                    memory_usage: 0,
                    start_time: SystemTime::now(),
                    signature: None,
                    icon: None,
                }
            };

            let remote_addr = match (entry.remote_addr, entry.remote_port) {
                (Some(addr), Some(port)) if port != 0 => Some(std::net::SocketAddr::new(addr, port)),
                _ => None,
            };

            let local_addr = std::net::SocketAddr::new(entry.local_addr, entry.local_port);

            let state = if entry.protocol == "TCP" {
                proc_tcp_state_to_connection_state(entry.state)
            } else {
                ConnectionState::Unconnected
            };

            let duration = SystemTime::now()
                .duration_since(process_info.start_time)
                .unwrap_or_default();

            connections.push(Connection {
                protocol: entry.protocol,
                local_addr,
                remote_addr,
                state,
                pid: process_info.pid,
                process_name: process_info.name,
                process_path: process_info.path,
                process_icon: process_info.icon,
                duration,
                is_signed: None, // TODO: ELF signature verification
                user: process_info.user,
            });
        }

        Ok(connections)
    }

    fn get_process_info(&self, pid: u32) -> Result<ProcessInfo, Box<dyn std::error::Error>> {
        read_process_info(pid).ok_or_else(|| format!("Process {} not found", pid).into())
    }

    fn kill_process(&self, pid: u32, force: bool) -> Result<(), Box<dyn std::error::Error>> {
        let signal = if force { SIGKILL } else { SIGTERM };
        let ret = unsafe { kill(pid as i32, signal) };
        if ret == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error().into())
        }
    }

    fn get_process_icon(&self, _pid: u32) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        // TODO: resolve .desktop entry icons (linux/icon.rs)
        Ok(None)
    }

    fn check_signature(
        &self,
        _path: &Path,
    ) -> Result<SignatureStatus, Box<dyn std::error::Error>> {
        // TODO: ELF signature verification, best effort (linux/signature.rs)
        Err("Signature checking not yet implemented on Linux".into())
    }

    fn elevate_privileges(&self) -> Result<bool, Box<dyn std::error::Error>> {
        // Try pkexec first, then sudo
        let pkexec_result = std::process::Command::new("pkexec")
            .arg("--version")
            .output();
        
        if pkexec_result.is_ok() {
            // pkexec available, but we can't really test elevation without a GUI prompt
            // Return true to indicate it's available
            return Ok(true);
        }

        let sudo_result = std::process::Command::new("sudo")
            .args(["-n", "true"]) // non-interactive test
            .output();
        
        Ok(sudo_result.map(|o| o.status.success()).unwrap_or(false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4_hex() {
        // 0100007F -> 127.0.0.1 (little-endian)
        assert_eq!(parse_ip_hex("0100007F"), Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        // C0A80101 -> 192.168.1.1
        assert_eq!(parse_ip_hex("0101A8C0"), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_parse_proc_net_line_tcp() {
        let line = "  0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 54321 1 ffff880012345678 100 0 0 10 0";
        let entry = parse_proc_net_line(line, "TCP").unwrap();
        assert_eq!(entry.protocol, "TCP");
        assert_eq!(entry.local_addr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(entry.local_port, 8080);
        assert_eq!(entry.state, 0x0A); // TCP_LISTEN
        assert_eq!(entry.inode, 54321);
    }

    #[test]
    fn test_proc_tcp_state_mapping() {
        assert_eq!(proc_tcp_state_to_connection_state(0x01), ConnectionState::Established);
        assert_eq!(proc_tcp_state_to_connection_state(0x0A), ConnectionState::Listen);
        assert_eq!(proc_tcp_state_to_connection_state(0x06), ConnectionState::TimeWait);
        assert_eq!(proc_tcp_state_to_connection_state(0xFF), ConnectionState::Unknown);
    }
}