use super::{NetworkAdapter, NetworkInterface};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::Duration;
use std::ffi::CString;
use libc::{c_int, freeifaddrs, getifaddrs, ifaddrs, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6};

/// Linux-specific implementation of NetworkAdapter using getifaddrs.
#[derive(Debug, Clone, Copy)]
pub struct LinuxAdapter;

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

            // Skip if no address
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

            // Also check for additional addresses (if any) in the linked list of ifa_ifu?
            // The ifa_ifu union contains ifu_broadaddr and ifu_dstaddr, but we ignore for simplicity.
            // We only take the first address per family per interface for now.

            if !ip_addresses.is_empty() {
                interfaces.push(NetworkInterface {
                    name,
                    ip_addresses,
                });
            }

            current = unsafe { iface.ifa_next };
        }

        unsafe {
            freeifaddrs(ifap);
        }

        Ok(interfaces)
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