/*****************************************************************************
 * Filename:        cli.rs
 * Author:          machinageist
 * Date:            2026-05-01
 * Description:     Argument parsing with clap
 *****************************************************************************/
use clap::{Parser, ValueEnum};

// Output format selection
#[derive(ValueEnum, Clone)]
pub enum OutputFormat {
    Table,
    Json,
}

// Internal clap struct for parsing command line arguments
#[derive(Parser)]
#[command(version, about = "Fast async port scanner with banner grabbing", long_about = None)]
struct CliArgs {
    /// Target host, IP, or CIDR range (e.g. 192.168.1.0/24)
    host: String,

    /// Port range to scan, e.g. 22-443
    #[arg(short, long, default_value = "1-65535")]
    ports: String,

    /// Connection timeout in milliseconds
    #[arg(short, long, default_value = "1000")]
    timeout: u64,

    /// Max simultaneous TCP connections
    #[arg(short, long, default_value = "1000")]
    concurrency: usize,

    /// Output format
    #[arg(short, long, value_enum, default_value = "table")]
    format: OutputFormat,

    /// Randomise probe order to avoid sequential pattern detection
    #[arg(long)]
    randomise: bool,

    /// Base delay between probes in milliseconds
    #[arg(long, default_value = "0")]
    delay: u64,

    /// Max random jitter added to each delay in milliseconds
    #[arg(long, default_value = "0")]
    jitter: u64,

    /// Bind probes to this source port (e.g. 53 or 80 for firewall evasion)
    #[arg(long)]
    source_port: Option<u16>,
}

// Parse port range string into start and end values
fn parse_port_range(range: &str) -> Result<(u16, u16), String> {
    let parts: Vec<&str> = range.splitn(2, '-').collect();

    if parts.len() != 2 {
        return Err(format!(
            "Invalid port range '{}': expected format start-end",
            range
        ));
    }

    let port_start = parts[0]
        .parse::<u16>()
        .map_err(|_| format!("Invalid start port '{}'", parts[0]))?;

    let port_end = parts[1]
        .parse::<u16>()
        .map_err(|_| format!("Invalid end port '{}'", parts[1]))?;

    if port_start > port_end {
        return Err(format!(
            "Start port {} is greater than end port {}",
            port_start, port_end
        ));
    }

    if port_start == 0 {
        return Err("Port 0 is not valid".to_string());
    }

    Ok((port_start, port_end))
}

// Public struct returned to the rest of the program
pub struct Args {
    pub host: String,
    pub port_start: u16,
    pub port_end: u16,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub format: OutputFormat,
    pub randomise: bool,
    pub delay_ms: u64,
    pub jitter_ms: u64,
    pub source_port: Option<u16>,
}

// Parse and validate command line arguments
pub fn get_args() -> Args {
    let cli = CliArgs::parse();

    if cli.concurrency == 0 {
        eprintln!("Error: concurrency must be at least 1");
        std::process::exit(1);
    }

    let (port_start, port_end) = parse_port_range(&cli.ports).unwrap_or_else(|e| {
        eprintln!("Error: {e}");
        std::process::exit(1);
    });

    Args {
        host: cli.host,
        port_start,
        port_end,
        timeout_ms: cli.timeout,
        concurrency: cli.concurrency,
        format: cli.format,
        randomise: cli.randomise,
        delay_ms: cli.delay,
        jitter_ms: cli.jitter,
        source_port: cli.source_port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_range() {
        assert_eq!(parse_port_range("22-443"), Ok((22, 443)));
    }

    #[test]
    fn single_port_range() {
        assert_eq!(parse_port_range("80-80"), Ok((80, 80)));
    }

    #[test]
    fn full_range() {
        assert_eq!(parse_port_range("1-65535"), Ok((1, 65535)));
    }

    #[test]
    fn reversed_range() {
        assert!(parse_port_range("443-22").is_err());
    }

    #[test]
    fn port_zero() {
        assert!(parse_port_range("0-1024").is_err());
    }

    #[test]
    fn missing_dash() {
        assert!(parse_port_range("80").is_err());
    }

    #[test]
    fn invalid_start() {
        assert!(parse_port_range("abc-443").is_err());
    }

    #[test]
    fn invalid_end() {
        assert!(parse_port_range("22-abc").is_err());
    }
}
