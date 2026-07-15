use crate::{NetworkAdapter, NetworkInterface};
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::Duration;
use windows::core::PWSTR;
use windows::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
};
use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
};

/// Windows-specific implementation of NetworkAdapter using the IP Helper API.
#[derive(Debug, Clone, Copy)]
pub struct WindowsAdapter;

/// Helper: convert a null-terminated PWSTR (wide string) to a Rust String.
/// Returns None if the pointer is null.
unsafe fn pwstr_to_string(ptr: PWSTR) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    // PWSTR.0 is *mut u16
    let raw = ptr.0;
    let mut len = 0usize;
    while *raw.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(raw, len);
    Some(String::from_utf16_lossy(slice))
}

impl NetworkAdapter for WindowsAdapter {
    fn list_interfaces(&self) -> Result<Vec<NetworkInterface>, Box<dyn std::error::Error>> {
        // Family: AF_UNSPEC (0) to get both IPv4 and IPv6.
        const FAMILY: u32 = AF_UNSPEC.0 as u32;

        let mut buf_size: u32 = 0;
        // First call to get required buffer size (returns ERROR_BUFFER_OVERFLOW).
        unsafe {
            GetAdaptersAddresses(
                FAMILY,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                None,
                &mut buf_size,
            );
        }

        // Allocate buffer and do the real call.
        let mut buf = vec![0u8; buf_size as usize];
        let mut adapters_vec = Vec::new();

        unsafe {
            let res = GetAdaptersAddresses(
                FAMILY,
                GAA_FLAG_INCLUDE_PREFIX,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut buf_size,
            );

            // ERROR_SUCCESS == 0
            if res != 0 {
                return Err(format!("GetAdaptersAddresses failed with error: {}", res).into());
            }

            let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
            while !adapter.is_null() {
                let a = &*adapter;

                // Skip if no unicast addresses.
                if a.FirstUnicastAddress.is_null() {
                    adapter = a.Next;
                    continue;
                }

                // Prefer FriendlyName, then Description, then AdapterName (ANSI).
                let name = pwstr_to_string(a.FriendlyName)
                    .or_else(|| pwstr_to_string(a.Description))
                    .unwrap_or_else(|| {
                        // AdapterName is a PSTR (*mut u8). Check null via .is_null() then cast to *const i8 for CStr.
                        if a.AdapterName.is_null() {
                            "<unknown>".to_string()
                        } else {
                            CStr::from_ptr(a.AdapterName.as_ptr() as *const i8)
                                .to_string_lossy()
                                .into_owned()
                        }
                    });

                let mut ip_addresses = Vec::new();

                // Iterate over unicast address linked list.
                let mut addr_ptr = a.FirstUnicastAddress;
                while !addr_ptr.is_null() {
                    let ua = &*addr_ptr;
                    let sockaddr = ua.Address.lpSockaddr;
                    if !sockaddr.is_null() {
                        // sa_family is ADDRESS_FAMILY (u16 newtype).
                        // Compare directly against AF_INET / AF_INET6 constants.
                        let family = (*sockaddr).sa_family;
                        if family == AF_INET {
                            let sin = &*(sockaddr as *const SOCKADDR_IN);
                            let ip = Ipv4Addr::from(sin.sin_addr.S_un.S_addr.to_ne_bytes());
                            ip_addresses.push(IpAddr::V4(ip));
                        } else if family == AF_INET6 {
                            let sin6 = &*(sockaddr as *const SOCKADDR_IN6);
                            let bytes = sin6.sin6_addr.u.Byte;
                            let mut segs = [0u16; 8];
                            for i in 0..8 {
                                segs[i] = u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
                            }
                            let ip = Ipv6Addr::from(segs);
                            ip_addresses.push(IpAddr::V6(ip));
                        }
                    }
                    addr_ptr = ua.Next;
                }

                if !ip_addresses.is_empty() {
                    adapters_vec.push(NetworkInterface { name, ip_addresses });
                }

                adapter = a.Next;
            }
        }

        Ok(adapters_vec)
    }

    fn get_local_ip(&self) -> Result<IpAddr, Box<dyn std::error::Error>> {
        // Try to get a non-loopback IP from our interfaces first.
        if let Ok(interfaces) = self.list_interfaces() {
            for iface in interfaces {
                for ip in &iface.ip_addresses {
                    if !ip.is_loopback() {
                        return Ok(*ip);
                    }
                }
            }
        }

        // Fallback: UDP socket trick.
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect("8.8.8.8:80")?;
        let local_addr = socket.local_addr()?;
        Ok(local_addr.ip())
    }

    fn is_port_open(&self, ip: IpAddr, port: u16, timeout: Duration) -> bool {
        let addr_str = format!("{}:{}", ip, port);
        let socket_addr: std::net::SocketAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(_) => return false,
        };
        match std::net::TcpStream::connect_timeout(&socket_addr, timeout) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn get_service_name(&self, port: u16, protocol: &str) -> Option<String> {
        let services = [
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
