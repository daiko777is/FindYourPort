//! History logger for scan results and application events.

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Local};

/// Log entry for a scan event.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: DateTime<Local>,
    pub event: String,
    pub details: Option<String>,
}

/// Manages the history log file.
pub struct HistoryLogger {
    log_path: PathBuf,
    entries: Arc<RwLock<Vec<LogEntry>>>,
}

impl HistoryLogger {
    /// Create a new history logger that logs to the given file path.
    pub fn new(log_path: PathBuf) -> io::Result<Self> {
        // Ensure the directory exists.
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let logger = HistoryLogger {
            log_path,
            entries: Arc::new(RwLock::new(Vec::new())),
        };

        // Load existing log entries from file.
        logger.load()?;

        Ok(logger)
    }

    /// Load log entries from the log file.
    fn load(&self) -> io::Result<()> {
        let file = OpenOptions::new().read(true).open(&self.log_path)?;
        let reader = BufReader::new(file);
        let mut entries = self.entries.write().expect("HistoryLogger poisoned");
        entries.clear();

        for line in reader.lines() {
            let line = line?;
            // Simple format: timestamp|event|details
            let parts: Vec<&str> = line.splitn(3, '|').collect();
            if parts.len() >= 2 {
                let timestamp = DateTime::parse_from_rfc3339(parts[0])
                    .ok()
                    .map(|dt| dt.with_timezone(&Local))
                    .unwrap_or_else(Local::now);
                let event = parts[1].to_string();
                let details = if parts.len() > 2 { Some(parts[2].to_string()) } else { None };
                entries.push(LogEntry {
                    timestamp,
                    event,
                    details,
                });
            }
        }
        Ok(())
    }

    /// Append a new log entry and persist it to the file.
    pub fn log(&self, event: impl Into<String>, details: impl Into<Option<String>>) -> io::Result<()> {
        let entry = LogEntry {
            timestamp: Local::now(),
            event: event.into(),
            details: details.into(),
        };

        // Append to in-memory buffer.
        {
            let mut entries = self.entries.write().expect("HistoryLogger poisoned");
            entries.push(entry.clone());
        }

        // Append to file.
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        writeln!(
            file,
            "{} | {} | {}",
            entry.timestamp.to_rfc3339(),
            entry.event,
            entry.details.as_deref().unwrap_or(""),
        )?;

        Ok(())
    }

    /// Get a copy of all log entries.
    pub fn get_entries(&self) -> Vec<LogEntry> {
        self.entries.read().expect("HistoryLogger poisoned").clone()
    }

    /// Clear the log file and in-memory entries.
    pub fn clear(&self) -> io::Result<()> {
        // Truncate the file.
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.log_path)?;
        file.set_len(0)?;

        // Clear in-memory entries.
        let mut entries = self.entries.write().expect("HistoryLogger poisoned");
        entries.clear();

        Ok(())
    }
}