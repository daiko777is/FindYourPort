// Find Your Port - Desktop UI entry point.
// Wires the Slint UI (crates/fyp-ui/ui) to the platform network adapter.

use fyp_os::{system_adapter, Connection, ConnectionState, NetworkAdapter};
use fyp_ui::*;
use slint::{Color, ModelRc, SharedString, Timer, VecModel};
use std::sync::Mutex;
use std::time::Duration;

/// Latest full set of connections (used by search filtering).
static ALL_CONNECTIONS: Mutex<Vec<ConnectionRowData>> = Mutex::new(Vec::new());

/// Live toast queue.
static TOASTS: Mutex<Vec<ToastData>> = Mutex::new(Vec::new());

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = AppWindow::new()?;
    let adapter = system_adapter();

    // ── Initial scan ─────────────────────────────────────────────────────
    refresh(app.as_weak(), &*adapter);

    // ── Refresh ──────────────────────────────────────────────────────────
    app.on_refresh_connections({
        let weak = app.as_weak();
        move || {
            let weak = weak.clone();
            let _adapter = system_adapter();
            refresh(weak, &*_adapter);
        }
    });

    // ── Search ───────────────────────────────────────────────────────────
    app.on_search_changed({
        let weak = app.as_weak();
        move |query| {
            if let Some(app) = weak.upgrade() {
                apply_filter(&app, query.as_str());
            }
        }
    });

    // ── Security mode ────────────────────────────────────────────────────
    app.on_security_toggled({
        let weak = app.as_weak();
        move |enabled| {
            if let Some(app) = weak.upgrade() {
                app.set_security_mode(enabled);
                if enabled {
                    let alerts = ALL_CONNECTIONS
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|r| r.is_unsigned || is_risky_port(r.local_port.as_str()))
                        .count() as i32;
                    app.set_alert_count(alerts);
                    push_toast(&app, "Security Mode enabled", "warning");
                } else {
                    app.set_alert_count(0);
                    push_toast(&app, "Security Mode disabled", "info");
                }
            }
        }
    });

    // ── Settings ─────────────────────────────────────────────────────────
    app.on_settings_opened({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                app.set_settings_open(true);
            }
        }
    });

    // ── Row selection ────────────────────────────────────────────────────
    app.on_row_selected({
        let weak = app.as_weak();
        move |pid| {
            if let Some(app) = weak.upgrade() {
                if let Some(row) = find_connection(pid.as_str()) {
                    app.set_selected_connection(row);
                    app.set_detail_panel_open(true);
                }
            }
        }
    });

    // ── Kill flow ────────────────────────────────────────────────────────
    app.on_kill_requested({
        let weak = app.as_weak();
        move |pid| {
            if let Some(app) = weak.upgrade() {
                if let Some(row) = find_connection(pid.as_str()) {
                    app.set_kill_target_pid(SharedString::from(row.pid.as_str()));
                    app.set_kill_target_name(SharedString::from(row.process_name.as_str()));
                    app.set_kill_target_port(SharedString::from(row.local_port.as_str()));
                    app.set_kill_target_protocol(SharedString::from(row.protocol.as_str()));
                    app.set_confirm_kill_open(true);
                }
            }
        }
    });

    app.on_kill_confirmed({
        let weak = app.as_weak();
        move |pid| {
            if let Some(app) = weak.upgrade() {
                let target = pid.to_string();
                let adapter = system_adapter();
                let parsed = target.parse::<u32>().unwrap_or(0);
                match adapter.kill_process(parsed, false) {
                    Ok(_) => {
                        push_toast(&app, "Process terminated", "success");
                        refresh(app.as_weak(), &*adapter);
                    }
                    Err(e) => {
                        push_toast(&app, &format!("Kill failed: {}", e), "error");
                    }
                }
            }
        }
    });

    app.on_kill_cancelled({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                app.set_confirm_kill_open(false);
            }
        }
    });

    // ── Toast management ─────────────────────────────────────────────────
    app.on_toast_dismissed({
        let weak = app.as_weak();
        move |index| {
            if let Some(app) = weak.upgrade() {
                dismiss_toast(&app, index as usize);
            }
        }
    });

    // ── Detail panel actions ─────────────────────────────────────────────
    app.on_open_path({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                let sel = app.get_selected_connection();
                open_process_path(sel.process_path.as_str());
            }
        }
    });

    // ── Keyboard shortcuts ───────────────────────────────────────────────
    app.on_shortcut_refresh({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                app.invoke_refresh_connections();
            }
        }
    });

    app.on_shortcut_settings({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                app.set_settings_open(true);
            }
        }
    });

    app.on_shortcut_compact({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                app.set_compact_mode_open(!app.get_compact_mode_open());
            }
        }
    });

    app.on_shortcut_security({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                let next = !app.get_security_mode();
                app.invoke_security_toggled(next);
            }
        }
    });

    app.on_shortcut_escape({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                app.set_confirm_kill_open(false);
                app.set_settings_open(false);
                app.set_detail_panel_open(false);
                app.set_compact_mode_open(false);
            }
        }
    });

    app.on_shortcut_search({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                push_toast(&app, "Search: type to filter connections", "info");
            }
        }
    });

    app.on_shortcut_kill({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                let sel = app.get_selected_connection();
                if !sel.pid.is_empty() {
                    app.invoke_kill_requested(sel.pid);
                }
            }
        }
    });

    // ── Compact mode toggle from UI state ────────────────────────────────
    app.on_compact_mode_toggled({
        let weak = app.as_weak();
        move |open| {
            if let Some(app) = weak.upgrade() {
                app.set_compact_mode_open(open);
            }
        }
    });

    // ── System tray ────────────────────────────────────────────────────
    let tray = Tray::new()?;
    tray.on_activated_open({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                let _ = app.show();
            }
        }
    });
    tray.on_activated_refresh({
        let weak = app.as_weak();
        move || {
            if let Some(app) = weak.upgrade() {
                app.invoke_refresh_connections();
            }
        }
    });
    tray.on_activated_quit(|| {
        let _ = slint::quit_event_loop();
    });

    app.run()?;
    Ok(())
}

// ── Core logic ─────────────────────────────────────────────────────────

/// Scan the system and populate all connection-related UI state.
fn refresh(weak: slint::Weak<AppWindow>, adapter: &dyn NetworkAdapter) {
    let connections = adapter.scan_connections().unwrap_or_default();
    let rows: Vec<ConnectionRowData> = connections.iter().map(to_row).collect();
    let compact: Vec<CompactRowData> = connections.iter().map(to_compact_row).collect();

    {
        *ALL_CONNECTIONS.lock().unwrap() = rows.clone();
    }

    if let Some(app) = weak.upgrade() {
        app.set_connections(ModelRc::new(VecModel::from(rows.clone())));
        app.set_filtered_connections(ModelRc::new(VecModel::from(rows)));
        app.set_compact_rows(ModelRc::new(VecModel::from(compact)));
        app.set_connection_count(connections.len() as i32);
        app.set_last_refresh(SharedString::from(now_str()));
        app.set_status_text(SharedString::from("Ready"));
    }
}

/// Apply the search filter to the latest connection snapshot.
fn apply_filter(app: &AppWindow, query: &str) {
    let q = query.trim().to_lowercase();
    let rows = ALL_CONNECTIONS.lock().unwrap().clone();

    let filtered: Vec<ConnectionRowData> = if q.is_empty() {
        rows
    } else {
        rows.into_iter()
            .filter(|r| {
                r.protocol.to_lowercase().contains(&q)
                    || r.local_port.to_lowercase().contains(&q)
                    || r.local_addr.to_lowercase().contains(&q)
                    || r.remote_addr.to_lowercase().contains(&q)
                    || r.state.to_lowercase().contains(&q)
                    || r.process_name.to_lowercase().contains(&q)
                    || r.pid.to_lowercase().contains(&q)
            })
            .collect()
    };

    app.set_filtered_connections(ModelRc::new(VecModel::from(filtered)));
}

/// Find a connection row by its PID string.
fn find_connection(pid: &str) -> Option<ConnectionRowData> {
    ALL_CONNECTIONS
        .lock()
        .unwrap()
        .iter()
        .find(|r| r.pid.as_str() == pid)
        .cloned()
}

/// Map an OS `Connection` to the UI row struct.
fn to_row(c: &Connection) -> ConnectionRowData {
    let (state_label, state_color) = state_style(&c.state);
    ConnectionRowData {
        protocol: SharedString::from(c.protocol.clone()),
        local_port: SharedString::from(c.local_addr.port().to_string()),
        local_addr: SharedString::from(c.local_addr.to_string()),
        remote_addr: SharedString::from(
            c.remote_addr.map(|a| a.to_string()).unwrap_or_else(|| "—".into()),
        ),
        state: SharedString::from(state_label),
        state_color,
        process_name: SharedString::from(c.process_name.clone()),
        process_initial: SharedString::from(
            c.process_name.chars().next().unwrap_or('?').to_uppercase().to_string(),
        ),
        process_icon: SharedString::default(),
        pid: SharedString::from(c.pid.to_string()),
        is_suspicious: c.remote_addr.map(|a| a.ip().is_loopback()).unwrap_or(false),
        is_unsigned: c.is_signed == Some(false),
        process_path: SharedString::from(c.process_path.to_string_lossy().into_owned()),
        user: SharedString::from(c.user.clone()),
        duration_str: SharedString::from(format_duration(c.duration)),
    }
}

/// Map an OS `Connection` to the compact-widget row struct.
fn to_compact_row(c: &Connection) -> CompactRowData {
    let (state_label, state_color) = state_style(&c.state);
    CompactRowData {
        port: SharedString::from(c.local_addr.port().to_string()),
        process: SharedString::from(c.process_name.clone()),
        state: SharedString::from(state_label),
        state_color,
        pid: SharedString::from(c.pid.to_string()),
    }
}

/// Human-readable label + color for a connection state.
fn state_style(state: &ConnectionState) -> (&'static str, Color) {
    match state {
        ConnectionState::Listen => ("LISTEN", Color::from_rgb_u8(96, 165, 250)),
        ConnectionState::Established => ("ESTAB", Color::from_rgb_u8(74, 222, 128)),
        ConnectionState::SynSent => ("SYN_SENT", Color::from_rgb_u8(251, 146, 60)),
        ConnectionState::SynRecv => ("SYN_RECV", Color::from_rgb_u8(251, 146, 60)),
        ConnectionState::FinWait1 => ("FIN_WAIT1", Color::from_rgb_u8(129, 140, 248)),
        ConnectionState::FinWait2 => ("FIN_WAIT2", Color::from_rgb_u8(129, 140, 248)),
        ConnectionState::TimeWait => ("TIME_WAIT", Color::from_rgb_u8(251, 146, 60)),
        ConnectionState::CloseWait => ("CLOSE_WAIT", Color::from_rgb_u8(251, 146, 60)),
        ConnectionState::LastAck => ("LAST_ACK", Color::from_rgb_u8(129, 140, 248)),
        ConnectionState::Closing => ("CLOSING", Color::from_rgb_u8(129, 140, 248)),
        ConnectionState::Close => ("CLOSED", Color::from_rgb_u8(139, 143, 152)),
        ConnectionState::Unconnected => ("UDP", Color::from_rgb_u8(167, 139, 250)),
        ConnectionState::Unknown => ("?", Color::from_rgb_u8(139, 143, 152)),
    }
}

/// Ports commonly targeted by malware / often expected to be closed.
fn is_risky_port(port: &str) -> bool {
    matches!(port, "23" | "135" | "139" | "445" | "3389")
}

/// `1h 2m`, `5m 3s`, `9s` style formatting.
fn format_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}s", secs)
    }
}

/// Current wall-clock time as HH:MM:SS.
fn now_str() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() % 86400;
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

// ── Toasts ─────────────────────────────────────────────────────────────

/// Push a toast, auto-dismissing it after 4 seconds.
fn push_toast(app: &AppWindow, message: &str, kind: &str) {
    let mut toasts = TOASTS.lock().unwrap();
    toasts.push(ToastData {
        message: SharedString::from(message),
        toast_type: SharedString::from(kind),
        visible: true,
    });
    render_toasts(app);

    let idx = toasts.len() - 1;
    let weak = app.as_weak();
    Timer::single_shot(Duration::from_secs(4), move || {
        if let Some(app) = weak.upgrade() {
            dismiss_toast(&app, idx);
        }
    });
}

/// Remove a toast (by index) and re-render the queued list.
fn dismiss_toast(app: &AppWindow, index: usize) {
    let mut toasts = TOASTS.lock().unwrap();
    if index < toasts.len() {
        toasts.remove(index);
    }
    render_toasts(app);
}

/// Push the current toast queue into the UI model.
fn render_toasts(app: &AppWindow) {
    let toasts = TOASTS.lock().unwrap().clone();
    app.set_toasts(ModelRc::new(VecModel::from(toasts)));
}

// ── Platform helpers ───────────────────────────────────────────────────

/// Open the parent folder of a process executable (Explorer / xdg-open).
fn open_process_path(path: &str) {
    #[cfg(target_os = "windows")]
    {
        if !path.is_empty() && path != "unknown" && path != "—" {
            let _ = std::process::Command::new("explorer")
                .args(["/select,", path])
                .spawn();
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(dir) = std::path::Path::new(path).parent() {
            let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
        }
    }
}