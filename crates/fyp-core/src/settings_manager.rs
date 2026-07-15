//! Settings management for Find Your Port.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::path::PathBuf;
use std::fmt::Write; // For writeln! on String

/// Default settings for the application.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// Default timeout for port scans in seconds.
    pub timeout_seconds: u64,
    /// Whether to show closed ports in results.
    pub show_closed_ports: bool,
    /// Theme for the UI (light/dark).
    pub theme: String,
    /// Custom key-value settings.
    pub custom: HashMap<String, String>,
}

impl Settings {
    /// Create a new settings instance with default values.
    pub fn new() -> Self {
        Self {
            timeout_seconds: 5,
            show_closed_ports: false,
            theme: String::from("light"),
            custom: HashMap::new(),
        }
    }

    /// Load settings from a file.
    pub fn load<P: Into<PathBuf>>(path: P) -> io::Result<Self> {
        let path = path.into();
        if !path.exists() {
            // Return default if file doesn't exist.
            return Ok(Self::default());
        }

        let mut content = String::new();
        let mut file = OpenOptions::new().read(true).open(&path)?;
        file.read_to_string(&mut content)?;
        let mut settings = Settings::default();
        for line in content.lines() {
            if let Some((key, value)) = line.split_once('=') {
                match key.trim() {
                    "timeout_seconds" => {
                        if let Ok(val) = value.trim().parse::<u64>() {
                            settings.timeout_seconds = val;
                        }
                    }
                    "show_closed_ports" => {
                        if let Ok(val) = value.trim().parse::<bool>() {
                            settings.show_closed_ports = val;
                        }
                    }
                    "theme" => {
                        settings.theme = value.trim().to_string();
                    }
                    _ => {
                        settings.custom.insert(key.trim().to_string(), value.trim().to_string());
                    }
                }
            }
        }
        Ok(settings)
    }

    /// Save settings to a file.
    pub fn save<P: Into<PathBuf>>(&self, path: P) -> io::Result<()> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut content = String::new();
        writeln!(content, "timeout_seconds={}", self.timeout_seconds)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        writeln!(content, "show_closed_ports={}", self.show_closed_ports)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        writeln!(content, "theme={}", self.theme)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        for (k, v) in &self.custom {
            writeln!(content, "{}={}", k, v)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }
        fs::write(path, content)?;
        Ok(())
    }
}

/// Manages loading, saving, and accessing application settings.
pub struct SettingsManager {
    settings_path: PathBuf,
    settings: Settings,
}

impl SettingsManager {
    /// Create a new settings manager that loads/saves settings from the given file path.
    pub fn new(settings_path: PathBuf) -> io::Result<Self> {
        // Ensure the directory exists.
        if let Some(parent) = settings_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let mut manager = SettingsManager {
            settings_path,
            settings: Settings::default(),
        };

        // Load existing settings if any.
        manager.load()?;

        Ok(manager)
    }

    /// Load settings from the settings file.
    pub fn load(&mut self) -> io::Result<()> {
        self.settings = Settings::load(&self.settings_path)?;
        Ok(())
    }

    /// Save settings to the settings file.
    pub fn save(&self) -> io::Result<()> {
        self.settings.save(&self.settings_path)
    }

    /// Get a setting value by key.
    pub fn get(&self, key: &str) -> Option<String> {
        match key {
            "timeout_seconds" => Some(self.settings.timeout_seconds.to_string()),
            "show_closed_ports" => Some(self.settings.show_closed_ports.to_string()),
            "theme" => Some(self.settings.theme.clone()),
            _ => self.settings.custom.get(key).cloned(),
        }
    }

    /// Set a setting value by key.
    pub fn set(&mut self, key: &str, value: String) -> Result<(), String> {
        match key {
            "timeout_seconds" => {
                if let Ok(val) = value.parse::<u64>() {
                    self.settings.timeout_seconds = val;
                    Ok(())
                } else {
                    Err("timeout_seconds must be a u64".to_string())
                }
            }
            "show_closed_ports" => {
                if let Ok(val) = value.parse::<bool>() {
                    self.settings.show_closed_ports = val;
                    Ok(())
                } else {
                    Err("show_closed_ports must be a boolean".to_string())
                }
            }
            "theme" => {
                self.settings.theme = value;
                Ok(())
            }
            _ => {
                self.settings.custom.insert(key.to_string(), value);
                Ok(())
            }
        }
    }

    /// Remove a setting by key.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        match key {
            "timeout_seconds" => None,
            "show_closed_ports" => None,
            "theme" => None,
            _ => self.settings.custom.remove(key),
        }
    }

    /// Get a reference to the internal settings.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Get a mutable reference to the internal settings.
    pub fn settings_mut(&mut self) -> &mut Settings {
        &mut self.settings
    }
}