// Author: Jeff
// Date: 2026-05-01
// Description: mg-scan public library API — exposes the scanner for use
//              by other workspace members and the RedBrowser Go engine

pub mod output;
pub mod scanner;
pub mod services;

// Re-export the core types so callers can write `use mg_scan::ScanConfig`
// without knowing which sub-module they live in
pub use scanner::{scan_ports, PortResult, PortState, ScanConfig};
pub use services::service_name;
