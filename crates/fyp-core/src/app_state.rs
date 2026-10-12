//! App state shared across the application.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Shared application state.
#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<RwLock<AppStateInner>>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct AppStateInner {
    /// Currently selected network interface.
    pub selected_interface: Option<String>,
    /// Last scan results.
    pub last_scan_results: Vec<crate::search_engine::ScanResult>,
    /// Application settings.
    pub settings: crate::settings_manager::Settings,
    /// Cached process icons: PID -> icon bytes (RGBA), or None if unavailable.
    pub icons: Arc<RwLock<HashMap<u32, Option<Vec<u8>>>>,
}

impl AppState {
    /// Create a new default application state.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(AppStateInner::default())),
        }
    }

    /// Get a read-only guard to the inner state.
    pub fn read(&self) -> std::sync::RwLockReadGuard<'_, AppStateInner> {
        self.inner.read().expect("AppState poisoned")
    }

    /// Get a mutable guard to the inner state.
    pub fn write(&self) -> std::sync::RwLockWriteGuard<'_, AppStateInner> {
        self.inner.write().expect("AppState poisoned")
    }

    /// Update the process icon cache with new icon data.
    /// Useful after a scan completes to pre-load icons for the UI.
    pub fn update_process_icons(&self, icons: HashMap<u32, Option<Vec<u8>>>) {
        *self.icons.write().expect("AppState poisoned") = icons;
    }
}