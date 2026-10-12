# Changelog
All notable changes to Find Your Port will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Fase 0: Setup (this commit)
- Workspace Cargo with 4 crates: `fyp-core`, `fyp-os`, `fyp-ui`, `fyp-cli`.
- `fyp-os`: OS-abstraction layer (`NetworkMonitor` trait, common types, Windows + Linux adapter skeletons).
- `fyp-core`: AppState, SearchEngine, HistoryLogger, SettingsManager, SecurityAnalyzer stubs.
- `fyp-ui`: Slint app-window skeleton, design tokens (dark / light), SearchBar, ConnectionTable, Badge, Toast components, ConfirmKill modal, Header / Footer.
- Cross-platform CI workflow (`.github/workflows/ci.yml`) with `cargo build`, `cargo test`, `cargo clippy`, `cargo fmt` jobs.
- Documentation: README, CONTRIBUTING, LICENSE (MIT), loop-engineering note in `docs/12_loop_engineering_note.md`.

### Added — System tray (Slint `SystemTrayIcon`)
- `fyp-ui/Cargo.toml`: enable `system-tray` feature on `slint`.
- `ui/tray.slint`: top-level `Tray inherits SystemTrayIcon` with tray icon, tooltip, and menu (Open / Refresh connections / Quit); left-click opens the app.
- `ui/assets/tray-icon.png` generated tray asset (embedded via `@image-url`).
- `main.rs`: tray wiring — Open/click → show window; Refresh → re-scan; Quit → `quit_event_loop()`. Close-to-tray via default `HideWindow` + visible tray keeping the event loop alive.
- `build.rs`: single `slint_build::compile` (two compiles would clobber `SLINT_INCLUDE_GENERATED`), `Tray` re-exported from `app-window.slint`.

### Changed — UI cleanup (per user screenshot review)
- Header: removed fake window controls (─ □ ✕).
- Detail panel: removed placeholder Copy Path / Copy Cmd buttons and empty Started/CPU/RAM rows.
- Settings modal: removed dead tabs (General/Shortcuts/About) and inert "System" theme button.
- Process icon: added `process_initial` tile (first letter) alongside `process_icon`.
- `app-window.slint`: restructured into explicit layers — main content layer, compact view, bottom-right toasts overlay, modals.

### Target v1.0.0 (planned per Implementation Plan §6)
- EADDRINUSE → kill flow end-to-end in < 5s on Windows and Linux.
- SearchEngine < 100 ms for 10k connections.
- Memory < 50 MB idle, < 100 MB under load.
- System tray integration.
- Dark theme complete, light theme functional.

---

*See `docs/06_Implementation_Plan_FindYourPort.md` for the full roadmap and `docs/11_Product_Strategy_Validation_FindYourPort.md` §10.2 for success conditions.*
