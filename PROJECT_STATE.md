# Project State: Find Your Port

## Current Phase: UI wiring & polish (In Progress)

Find Your Port = desktop monitor of active TCP/UDP connections (who owns a port),
with one-click process termination, security alerts for risky ports, and a compact
widget view. Built with Rust + Slint (1.17), cross-platform (Windows/Linux).

## ✅ Completed

- Cargo workspace: `fyp-core`, `fyp-os`, `fyp-ui`, `fyp-cli` (builds clean, `clippy` clean, tests pass).
- `fyp-os` adapter trait `NetworkAdapter` + `Connection` model; `system_adapter()` factory.
  - Windows adapter: real network connections via IP Helper API, `ScanResult`/`MibState` mapping, `GetFileVersionInfo` for signing, `pid`/`user`/`duration` capture, `kill_process`.
  - Linux adapter: `/proc/net/{tcp,tcp6,udp,udp6}` parsing, process/user resolution, `kill_process`, tests.
- `fyp-core`: `AppState`, `SearchEngine`, `HistoryLogger`, `SettingsManager` (+ `SecurityAnalyzer`).
- `fyp-ui` (Slint):
  - `theme/design-tokens.slint` (dark/light), shared `types.slint` (`ConnectionRowData`, `CompactRowData`, `ToastData`).
  - Components: `header`, `footer`, `badge`, `toast`, `search-bar`, `connection-table`, `connection-row`, `detail-panel`, `kill-button`, `fyp-button`, `modals/{confirm-kill,settings}`, `views/compact-view`.
  - `app-window.slint`: connections table, search filter, confirm-kill modal, settings modal, detail panel, compact view, toasts, keyboard shortcuts (Ctrl+F/R/K/,/M/S, Esc).
- `main.rs` wiring: initial scan + `on_refresh_connections`; search filter over snapshot; security toggle counts alerts (unsigned / risky ports); kill flow (confirm → `kill_process` → toast → refresh); detail panel open-path (Explorer/xdg-open); toasts auto-dismiss after 4s; all shortcuts.
- System tray (`ui/tray.slint`, Slint builtin `SystemTrayIcon` via `system-tray` feature): icon in notification area, left-click / "Open" menu → show window, "Refresh connections" → re-scan, "Quit" → exit loop. Default `HideWindow` close behavior + visible tray keeps the event loop alive (close-to-tray).
- App launches (`cargo run -p fyp-ui` → window stays alive, no panic).
- UI cleanup pass (per user screenshot review): removed fake window buttons (─ □ ✕) from the header, removed placeholder Copy Path / Copy Cmd buttons and empty Started/CPU/RAM rows from the detail panel, removed dead Settings tabs (General/Shortcuts/About) and the inert "System" theme button, added a real `process_initial` tile (first letter) for process icons, and restructured `app-window.slint` into layered overlays (main layer, compact view, toasts overlay bottom-right, modals).

## 🎯 Next steps (todo, priority order)

1. Process icons in table rows (`process_icon` field is already plumbed, empty).
2. Security Mode polish: real alert list view for suspicious connections.
3. Elevation: relaunch as administrator (UAC) / pkexec when killing system processes is denied.
4. Compact mode UX polish (mini floating window).
5. Performance: async background refresh (< 100 ms for 10k connections).
6. Installers: Windows (exe/msi), Linux (deb/rpm/AppImage).
7. Docs: update README/CONTRIBUTING/CHANGELOG to match shipped scope; license audit.

## 📝 Known issues

- Process icon tile shows first letter (`process_initial`); real executable icon extraction still pending.
- `on_shortcut_search` shows a toast instead of focusing the search field.
- Search filter uses `to_lowercase()` on SharedString (works via `as_str()`; check no clone cost hotspot at scale).
- Tray: on Linux requires a StatusNotifierItem host (most DEs); left-click behavior varies by desktop. Auto-refresh timer in the tray ("Refresh" is manual only).