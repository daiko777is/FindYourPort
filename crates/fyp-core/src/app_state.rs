//! App state shared across the application.

use std::sync::{Arc, RwLock};

/// Shared application state.
#[derive(Debug, Clone)]
pub struct AppState {
    inner: Arc<RwLock<AppStateInner>>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
#[allow(private_interfaces)]
struct AppStateInner {
    /// Currently selected network interface.
    pub selected_interface: Option<String>,
    /// Last scan results.
    pub last_scan_results: Vec<crate::search_engine::ScanResult>,
    /// Application settings.
    pub settings: crate::settings_manager::Settings,
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
}