//! Port scanning engine.

use std::net::IpAddr;
use std::time::{Duration, Instant};
use fyp_os::{NetworkAdapter, system_adapter};

/// Result of a port scan attempt.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub ip: IpAddr,
    pub port: u16,
    pub open: bool,
    pub service: Option<String>,
    pub latency_ms: Option<u64>,
}

/// Port scanner that uses a network adapter to check ports.
pub struct SearchEngine {
    adapter: Box<dyn NetworkAdapter>,
}

impl SearchEngine {
    /// Create a new search engine with the system adapter.
    pub fn new() -> Self {
        Self {
            adapter: system_adapter(),
        }
    }

    /// Scan a single port on a given IP address.
    pub fn scan_port(&self, ip: IpAddr, port: u16, timeout: Duration) -> ScanResult {
        let start = Instant::now();
        let open = self.adapter.is_port_open(ip, port, timeout);
        let latency = start.elapsed().as_millis() as u64;
        let service = if open {
            self.adapter.get_service_name(port, "tcp")
        } else {
            None
        };

        ScanResult {
            ip,
            port,
            open,
            service,
            latency_ms: Some(latency),
        }
    }

    /// Scan a range of ports on a given IP address.
    pub fn scan_range(&self, ip: IpAddr, start: u16, end: u16, timeout: Duration) -> Vec<ScanResult> {
        (start..=end)
            .map(|port| self.scan_port(ip, port, timeout))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_scan_port_closed() {
        let engine = SearchEngine::new();
        // Test a port that is likely closed on localhost
        let result = engine.scan_port(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
            std::time::Duration::from_millis(100),
        );
        // We don't assert the value because it depends on the environment, just that it returns a ScanResult
        assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(result.port, 12345);
        assert!(result.latency_ms.is_some());
    }

    #[test]
    fn test_scan_range() {
        let engine = SearchEngine::new();
        let results = engine.scan_range(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            12345,
            12347,
            std::time::Duration::from_millis(100),
        );
        assert_eq!(results.len(), 3);
        for (i, result) in results.iter().enumerate() {
            assert_eq!(result.port, 12345 + i as u16);
            assert_eq!(result.ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
            assert!(result.latency_ms.is_some());
        }
    }
}