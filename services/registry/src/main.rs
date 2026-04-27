//! Simple Docker Registry Binary
//!

use clap::{CommandFactory, Parser};
use registry::RegistryBuilder;
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};
use storage::StorageConfig;

#[derive(Debug, Parser)]
struct Args {
    /// Path to the configuration TOML file.
    #[clap(long, alias = "config")]
    configuration: PathBuf,

    /// Name of the storage bucket.
    #[clap(long)]
    bucket: Option<String>,

    /// Port for serving
    #[clap(short, long, default_value_t = 5000)]
    port: u16,

    /// Bind address for serving
    #[clap(short, long, default_value = "127.0.0.1")]
    bind: IpAddr,
}

#[derive(Debug, Deserialize)]
struct Configuration {
    storage: StorageConfig,
    bucket: Option<String>,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    match run().await {
        Ok(()) => {}
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1)
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let mut cmd = Args::command();
    let args = Args::parse();

    let configuration = load_configuration(&args.configuration).await?;
    let storage = configuration.storage.build().await?;

    let bucket = args.bucket.or(configuration.bucket).ok_or_else(|| {
        cmd.error(
            clap::error::ErrorKind::MissingRequiredArgument,
            "--bucket is required",
        )
    })?;

    // Build the registry service
    let app = RegistryBuilder::new()
        .storage(storage.into())
        .bucket(bucket)
        .build();

    let addr = SocketAddr::new(args.bind, args.port);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!("OCI Registry listening on http://{}", addr);

    // Serve the registry
    axum::serve(listener, app).await?;

    Ok(())
}

async fn load_configuration<P: AsRef<Path>>(
    path: P,
) -> Result<Configuration, Box<dyn std::error::Error + Send + Sync + 'static>> {
    let configuration = tokio::fs::read(path).await?;
    let cfg: Configuration = toml_edit::de::from_slice(&configuration)?;
    Ok(cfg)
}
