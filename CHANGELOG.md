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

### Target v1.0.0 (planned per Implementation Plan §6)
- EADDRINUSE → kill flow end-to-end in < 5s on Windows and Linux.
- SearchEngine < 100 ms for 10k connections.
- Memory < 50 MB idle, < 100 MB under load.
- System tray integration.
- Dark theme complete, light theme functional.

---

*See `docs/06_Implementation_Plan_FindYourPort.md` for the full roadmap and `docs/11_Product_Strategy_Validation_FindYourPort.md` §10.2 for success conditions.*
