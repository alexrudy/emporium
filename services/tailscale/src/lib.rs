//! Minimal Tailscale Client with DNS updates for Linode
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;

use camino::Utf8PathBuf;

mod client;
mod error;

pub use self::client::{TailscaleClient, TailscaleConfiguration};
pub use self::error::TailscaleError;

/// Result type using TailscaleError
pub type Result<T> = std::result::Result<T, TailscaleError>;

/// A tailscale host address with both V4 and V6 addresses
#[derive(Debug)]
pub struct TailscaleAddress {
    v4: Ipv4Addr,
    v6: Ipv6Addr,
}

impl TailscaleAddress {
    /// Get the V4 address
    pub fn v4(&self) -> &Ipv4Addr {
        &self.v4
    }

    /// Get the V6 address
    pub fn v6(&self) -> &Ipv6Addr {
        &self.v6
    }
}

impl FromStr for TailscaleAddress {
    type Err = TailscaleError;

    fn from_str(s: &str) -> Result<Self> {
        let mut v4 = None;
        let mut v6 = None;

        for line in s.lines() {
            Ipv4Addr::from_str(line)
                .ok()
                .map(|addr| v4.get_or_insert(addr));
            Ipv6Addr::from_str(line)
                .ok()
                .map(|addr| v6.get_or_insert(addr));
        }

        match (v4, v6) {
            (Some(v4), Some(v6)) => Ok(TailscaleAddress { v4, v6 }),
            (None, _) => Err(TailscaleError::parsing("IPv4 address", s)),
            (_, None) => Err(TailscaleError::parsing("IPv6 address", s)),
        }
    }
}

/// IP address version
#[derive(Debug, Clone, Copy)]
pub enum IpVersion {
    /// V4 IP address
    V4,
    /// V6 IP address
    V6,
}

impl IpVersion {
    fn ip_arg(&self) -> &'static str {
        match self {
            IpVersion::V4 => "-4",
            IpVersion::V6 => "-6",
        }
    }
}

/// Get the IP addresses of the current host
pub async fn get_host_tailscale_addresses() -> Result<TailscaleAddress> {
    let stdout = run_tailscale_command(&["ip"]).await?;
    stdout.parse()
}

/// Run a single command and return the output
async fn run_command(command: &str, args: &[&str]) -> Result<String> {
    let current_directory =
        Utf8PathBuf::from_path_buf(std::env::current_dir().map_err(|e| {
            TailscaleError::conversion_with_source("current directory to UTF-8", e)
        })?)
        .map_err(|p| TailscaleError::conversion(format!("path to UTF-8: {:?}", p)))?;

    let mut cmd = std::process::Command::new(command);
    cmd.current_dir(current_directory);
    cmd.args(args);

    let name = command.to_owned();

    let stdout = tokio::task::spawn_blocking(move || {
        let output = cmd
            .output()
            .map_err(|e| TailscaleError::command_spawn(&name, e))?;

        if !output.status.success() {
            return Err(TailscaleError::command(&name, Some(output)));
        }

        String::from_utf8(output.stdout).map_err(|e| {
            TailscaleError::conversion_with_source(format!("command '{}' output to UTF-8", name), e)
        })
    })
    .await
    .map_err(|e| {
        TailscaleError::other_with_source(format!("Command '{}' task panicked", command), e)
    })??;

    Ok(stdout)
}

async fn run_tailscale_command(args: &[&str]) -> Result<String> {
    run_command("tailscale", args).await
}

/// Get the ip address of the current host in a specific version
pub async fn get_host_ip_address(version: IpVersion) -> Result<IpAddr> {
    let stdout = run_command(
        "ip",
        &[
            "--oneline",
            version.ip_arg(),
            "address",
            "show",
            "dev",
            "eth0",
            "scope",
            "global",
        ],
    )
    .await?;

    let item = stdout
        .split_ascii_whitespace()
        .nth(3)
        .ok_or_else(|| TailscaleError::parsing("IP address field", &stdout))?;

    let addr = match version {
        IpVersion::V4 => item
            .strip_suffix("/24")
            .unwrap_or(item)
            .parse::<Ipv4Addr>()
            .map_err(|e| TailscaleError::parsing_with_source("IPv4 address", item, e))?
            .into(),
        IpVersion::V6 => item
            .strip_suffix("/64")
            .unwrap_or(item)
            .parse::<Ipv6Addr>()
            .map_err(|e| TailscaleError::parsing_with_source("IPv6 address", item, e))?
            .into(),
    };

    Ok(addr)
}

#[cfg(test)]
mod test {
    use crate::TailscaleAddress;

    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    #[test]
    fn parse_tailscale_output() {
        let v4 = Ipv4Addr::new(100, 68, 243, 73);
        let v6 = Ipv6Addr::from_str("fd7a:115c:a1e0:ab12:4843:cd96:6244:f349").unwrap();

        let output = indoc::indoc! {"
            100.68.243.73
            fd7a:115c:a1e0:ab12:4843:cd96:6244:f349
        "};

        let addr: Result<TailscaleAddress, _> = output.parse();
        assert!(addr.is_ok());
        let addr = addr.unwrap();
        assert_eq!(addr.v4(), &v4);
        assert_eq!(addr.v6(), &v6);
    }
}
