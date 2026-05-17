/*************************************************************
 * Filename:        scanner.rs
 * Author:          machinageist
 * Date:            2026-05-01
 * Description:     Async scan logic with banner grabbing,
 *                  port state detection, concurrency cap,
 *                  randomised order, timing control, and
 *                  optional source port binding
 *************************************************************/
use rand::Rng;
use rand::seq::SliceRandom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpSocket, TcpStream};
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::services::service_name;

const BANNER_BUF_SIZE: usize = 1024;

// TCP port state as observed from a connect scan
#[derive(Clone, PartialEq)]
pub enum PortState {
    // Connection accepted
    Open,
    // Connection refused immediately (RST) — host is up, port is closed
    Closed,
    // No response within timeout — firewall likely dropping packets
    Filtered,
}

// Result for a single probed port
pub struct PortResult {
    pub port: u16,
    pub state: PortState,
    pub service: &'static str,
    pub banner: Option<String>,
}

// Read first bytes from a connected stream to identify the service
async fn grab_banner(stream: &mut TcpStream, timeout_duration: Duration) -> Option<String> {
    let mut buf = [0u8; BANNER_BUF_SIZE];
    match timeout(timeout_duration, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let s: String = String::from_utf8_lossy(&buf[..n])
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect();
            let s = s.trim().to_string();
            if s.is_empty() { None } else { Some(s) }
        }
        _ => None,
    }
}

// Open a TCP connection, optionally binding to a specific source port
// Binding to a well-known source port (53, 80) can bypass naive firewall rules
// that permit traffic from those ports without inspecting the destination
// Note: binding to ports < 1024 requires elevated privileges on most systems
async fn connect(target: SocketAddr, source_port: Option<u16>) -> std::io::Result<TcpStream> {
    match source_port {
        None => TcpStream::connect(target).await,
        Some(src_port) => {
            let socket = match target {
                SocketAddr::V4(_) => TcpSocket::new_v4()?,
                SocketAddr::V6(_) => TcpSocket::new_v6()?,
            };
            // SO_REUSEADDR alone is insufficient on macOS for concurrent binds to
            // the same local port. SO_REUSEPORT allows the OS to route by the full
            // 4-tuple (src_ip, src_port, dst_ip, dst_port), which is unique per
            // probe since each targets a different destination port.
            socket.set_reuseaddr(true)?;
            #[cfg(unix)]
            socket.set_reuseport(true)?;
            let local: SocketAddr = match target {
                SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), src_port),
                SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), src_port),
            };
            socket.bind(local)?;
            socket.connect(target).await
        }
    }
}

// Probe one port; distinguish open, closed (RST), and filtered (timeout)
async fn probe_port(
    ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
    source_port: Option<u16>,
) -> PortResult {
    let target = SocketAddr::new(ip, port);
    match timeout(timeout_duration, connect(target, source_port)).await {
        Ok(Ok(mut stream)) => {
            let banner = grab_banner(&mut stream, timeout_duration).await;
            PortResult {
                port,
                state: PortState::Open,
                service: service_name(port),
                banner,
            }
        }
        Ok(Err(_)) => PortResult {
            port,
            state: PortState::Closed,
            service: service_name(port),
            banner: None,
        },
        Err(_) => PortResult {
            port,
            state: PortState::Filtered,
            service: service_name(port),
            banner: None,
        },
    }
}

// Scan configuration passed from CLI args
pub struct ScanConfig {
    pub port_start: u16,
    pub port_end: u16,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub randomise: bool,
    pub delay_ms: u64,
    pub jitter_ms: u64,
    pub source_port: Option<u16>,
}

// Scan a port range on the target IP
// - randomise: shuffle port order to avoid sequential IDS signatures
// - delay_ms / jitter_ms: control probe rate for timing-based evasion
// - concurrency: cap simultaneous in-flight connections via JoinSet drain
// - source_port: optional source port binding for firewall evasion
pub async fn scan_ports(ip: IpAddr, cfg: &ScanConfig) -> Vec<PortResult> {
    let timeout_duration = Duration::from_millis(cfg.timeout_ms);
    let concurrency = cfg.concurrency.max(1);
    let mut rng = rand::thread_rng();

    let mut ports: Vec<u16> = (cfg.port_start..=cfg.port_end).collect();
    if cfg.randomise {
        ports.shuffle(&mut rng);
    }

    let mut set: JoinSet<PortResult> = JoinSet::new();
    // Pre-allocate for all ports to avoid incremental reallocation
    let mut results = Vec::with_capacity(ports.len());

    for port in ports {
        if cfg.delay_ms > 0 || cfg.jitter_ms > 0 {
            let j = if cfg.jitter_ms > 0 {
                rng.gen_range(0..=cfg.jitter_ms)
            } else {
                0
            };
            tokio::time::sleep(Duration::from_millis(cfg.delay_ms + j)).await;
        }

        // When at concurrency limit, harvest one completed result before spawning;
        // this replaces Arc<Semaphore> — no clones or permit allocations per port
        while set.len() >= concurrency {
            if let Some(Ok(r)) = set.join_next().await {
                results.push(r);
            }
        }

        let source_port = cfg.source_port;
        set.spawn(async move { probe_port(ip, port, timeout_duration, source_port).await });
    }

    // Drain all remaining in-flight tasks
    while let Some(Ok(r)) = set.join_next().await {
        results.push(r);
    }

    results.sort_by_key(|r| r.port);
    results
}
