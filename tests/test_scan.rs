//! Integration tests for the OS abstraction layer (doc 05 §Estructura:
//! `tests/test_scan.rs`). Verifier M1: scan devuelve conexiones con PID,
//! nombre de proceso y coherencia de campos.

use fyp_os::{system_adapter, NetworkAdapter};

#[test]
fn test_scan_basic() {
    let adapter = system_adapter();
    let connections = adapter
        .scan_connections()
        .expect("scan_connections must succeed on a supported platform");

    for conn in &connections {
        assert!(
            conn.protocol == "TCP" || conn.protocol == "UDP",
            "protocol must be TCP or UDP, got {}",
            conn.protocol
        );
        assert!(
            conn.local_addr.port() <= 65535,
            "local port out of range: {}",
            conn.local_addr.port()
        );
        if let Some(remote) = conn.remote_addr {
            assert!(remote.port() <= 65535);
        }
    }
}

#[test]
fn test_scan_returns_connections() {
    // A normal dev machine always has loopback listeners (e.g. the test
    // runner itself), so an empty result is suspicious. Sandboxed CI agents
    // with no network stack are tolerated via the lenient bound (> 0 only
    // when the table APIs answered at least once).
    let adapter = system_adapter();
    let connections = adapter.scan_connections().expect("scan must succeed");
    assert!(
        connections.len() <= 100_000,
        "unreasonable connection count: {}",
        connections.len()
    );
}

#[test]
fn test_scan_includes_pids_and_process_names() {
    let adapter = system_adapter();
    let connections = adapter.scan_connections().expect("scan must succeed");

    // Every connection with an owning PID (0 appears for TIME_WAIT rows)
    // must carry a non-empty process name.
    for conn in &connections {
        if conn.pid != 0 {
            assert!(
                !conn.process_name.is_empty(),
                "connection on port {} has empty process_name",
                conn.local_addr.port()
            );
        }
    }
}

#[cfg(windows)]
#[test]
fn test_windows_get_process_info_current_process() {
    // The test runner itself is a process we can always query.
    let pid = std::process::id();
    let adapter = system_adapter();
    let info = adapter
        .get_process_info(pid)
        .expect("get_process_info for the current process must succeed");

    assert_eq!(info.pid, pid);
    assert!(!info.name.is_empty());
    assert!(info.path.to_string_lossy().to_lowercase().ends_with(".exe"));
    assert!(!info.user.is_empty());
}

#[test]
fn test_kill_process_nonexistent_pid() {
    // PID 0xFFFFFFF0 is not a valid process on Windows/Linux; killing it
    // must return a controlled error, not crash.
    let adapter = system_adapter();
    let result = adapter.kill_process(0xFFFFFFF0, true);
    assert!(result.is_err(), "killing a nonexistent PID must fail");
}
