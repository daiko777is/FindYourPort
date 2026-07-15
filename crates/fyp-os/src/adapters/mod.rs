#[cfg(target_os = "windows")]
pub mod windows_adapter;

#[cfg(target_os = "linux")]
pub mod linux_adapter;