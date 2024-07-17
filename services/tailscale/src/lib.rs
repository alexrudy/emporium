//! Minimal Tailscale Client with DNS updates for Linode
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;

use camino::Utf8PathBuf;
use eyre::Context;
use eyre::{eyre, Report, Result};

mod client;

pub use self::client::{TailscaleClient, TailscaleConfiguration};

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
    type Err = Report;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
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
            (None, _) => Err(eyre!("Missing IPV4")),
            (_, None) => Err(eyre!("Missing IPV6")),
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
pub async fn get_host_ip_addresses() -> Result<TailscaleAddress> {
    let stdout = run_tailscale_command(&["ip"]).await?;
    stdout.parse()
}

async fn run_tailscale_command(args: &[&str]) -> Result<String> {
    let current_directory = Utf8PathBuf::from_path_buf(std::env::current_dir()?)
        .map_err(|p| eyre!("Can't make current directory utf-8: {:?}", p))?;
    let mut cmd = std::process::Command::new("tailscale");
    cmd.current_dir(current_directory);
    cmd.args(args);

    let stdout = tokio::task::spawn_blocking(move || {
        let output = cmd.output().expect("Failed to execute tailscale");
        if !output.status.success() {
            return Err(eyre!("Failed to execute tailscale: {:?}", output));
        }

        Ok(String::from_utf8(output.stdout).expect("Failed to parse tailscale output"))
    })
    .await??;

    Ok(stdout)
}

/// Get the ip address of the current host in a specific version
pub async fn get_host_ip_address(version: IpVersion) -> Result<IpAddr> {
    let stdout = run_tailscale_command(&[
        "--oneline",
        version.ip_arg(),
        "address",
        "show",
        "dev",
        "eth0",
        "scope",
        "global",
    ])
    .await?;

    let item = stdout
        .split_ascii_whitespace()
        .nth(3)
        .ok_or_else(|| eyre!("Wrong number of output fields"))?;

    let addr = match version {
        IpVersion::V4 => item
            .strip_suffix("/24")
            .unwrap_or(item)
            .parse::<Ipv4Addr>()
            .with_context(|| format!("parsing {item} as IpV4"))?
            .into(),
        IpVersion::V6 => item
            .strip_suffix("/64")
            .unwrap_or(item)
            .parse::<Ipv6Addr>()
            .with_context(|| format!("parsing {item} as IpV6"))?
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
