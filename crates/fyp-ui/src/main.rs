use fyp_os::{system_adapter, NetworkAdapter};
use fyp_ui::*;
use slint::{Model, ModelRc, SharedString, VecModel};
use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let adapter = system_adapter();
    let app = AppWindow::new()?;

    // ── Load interfaces on startup ──
    load_interfaces(&app, &*adapter);

    // ── Local IP ──
    match adapter.get_local_ip() {
        Ok(ip) => app.set_local_ip(SharedString::from(ip.to_string())),
        Err(_) => app.set_local_ip(SharedString::from("No encontrada")),
    }

    // ── Refresh button ──
    {
        let weak = app.as_weak();
        app.on_refresh_interfaces(move || {
            let weak = weak.clone();
            let adapter = system_adapter();
            if let Some(app) = weak.upgrade() {
                load_interfaces(&app, &*adapter);
                match adapter.get_local_ip() {
                    Ok(ip) => app.set_local_ip(SharedString::from(ip.to_string())),
                    Err(_) => app.set_local_ip(SharedString::from("No encontrada")),
                }
            }
        });
    }

    // ── Scan button ──
    {
        let weak = app.as_weak();
        app.on_scan_ports(move |start, end, timeout| {
            let weak = weak.clone();
            thread::spawn(move || {
                if let Some(app) = weak.upgrade() {
                    app.set_scanning(true);
                    app.set_status_text(SharedString::from("Escaneando..."));
                    app.set_open_count(0);

                    let mut results: Vec<PortResult> = Vec::new();
                    let mut open_count = 0;

                    let start_port = start as u16;
                    let end_port = end as u16;
                    let timeout_ms = timeout as u64;

                    for port in start_port..=end_port {
                        let addr = format!("127.0.0.1:{}", port);
                        if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
                            match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(timeout_ms)) {
                                Ok(_) => {
                                    let service = get_service_name(port);
                                    results.push(PortResult {
                                        port: SharedString::from(port.to_string()),
                                        service: SharedString::from(service),
                                        status: SharedString::from("ABIERTO"),
                                    });
                                    open_count += 1;
                                }
                                Err(_) => {}
                            }
                        }
                    }

                    app.set_scan_results(ModelRc::new(VecModel::from(results)));
                    app.set_open_count(open_count);
                    app.set_scanning(false);
                    app.set_status_text(SharedString::from(format!("Completado: {} puerto(s) abierto(s)", open_count)));
                }
            });
        });
    }

    app.run()?;
    Ok(())
}

fn load_interfaces(app: &AppWindow, adapter: &dyn NetworkAdapter) {
    let interfaces = adapter.list_interfaces().unwrap_or_default();
    let mut items: Vec<InterfaceItem> = Vec::new();
    for iface in interfaces {
        let ips_str = iface
            .ip_addresses
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        items.push(InterfaceItem {
            name: SharedString::from(iface.name),
            ips: SharedString::from(ips_str),
        });
    }
    app.set_interfaces(ModelRc::new(VecModel::from(items)));
}

fn get_service_name(port: u16) -> String {
    match port {
        20 => "FTP Data",
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        135 => "RPC",
        139 => "NetBIOS",
        3389 => "RDP",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        8080 => "HTTP Alt",
        _ => "unknown",
    }.to_string()
}
