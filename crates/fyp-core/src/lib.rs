//! Core library for Find Your Port.
//! Contains shared types, state, search engine, history logger, and settings manager.

pub mod app_state;
pub mod history_logger;
pub mod search_engine;
pub mod settings_manager;

pub use app_state::AppState;
pub use history_logger::{HistoryLogger, LogEntry};
pub use search_engine::SearchEngine;
pub use settings_manager::{Settings, SettingsManager};