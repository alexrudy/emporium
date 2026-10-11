//! A reverse proxy with OAuth protection

use std::path::PathBuf;

use clap::Parser;
use eyre::Context as _;

use self::{config::Config, state::AppState};

mod app;
mod config;
mod proxy;
mod state;

#[cfg(test)]
mod tests;

#[derive(Debug, clap::Parser)]
struct Cli {
    /// Path to a configuration file
    #[clap(long)]
    config: Option<PathBuf>,

    /// Upstream authority
    upstream: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    install_tracing();

    let args = Cli::parse();

    let config = if let Some(path) = args.config {
        Config::from_file(path)?
    } else {
        Config::from_env()?
    };

    // `Debug`, not serde: `Secret`'s serializer emits the raw value, while
    // its `Debug` impl redacts it.
    tracing::debug!(?config, "loaded configuration");

    let state = AppState::new(config.clone(), args.upstream.parse()?).await?;
    let router = app::build(&state, &config).await?;

    let listener = tokio::net::TcpListener::bind(config.server.bind_addr)
        .await
        .with_context(|| format!("binding {bind_addr}", bind_addr = config.server.bind_addr))?;

    tracing::info!(
        "listening on {bind_addr}",
        bind_addr = config.server.bind_addr
    );
    axum::serve(listener, router.into_make_service()).await?;

    Ok(())
}

fn install_tracing() {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt;
    fmt().with_env_filter(EnvFilter::from_default_env()).init();
}
