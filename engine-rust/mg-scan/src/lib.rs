/*******************************************************************
 * Filename:        lib.rs
 * Author:          Jeff
 * Date:            2026-05-01
 * Description:     mg-scan public library API — exposes the scanner for use
 *                  by other workspace members (primarily mg-recon orchestrator)
 * Notes:           Re-exports keep external callers isolated from sub-module paths.
 *******************************************************************/

pub mod output;
pub mod scanner;
pub mod services;

// Re-export the core types so callers can write `use mg_scan::ScanConfig`
// without knowing which sub-module they live in
pub use scanner::{scan_ports, PortResult, PortState, ScanConfig};
pub use services::service_name;
