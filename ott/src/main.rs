//! ott — OAuth Test Tool.
//!
//! Phase A: the skeleton. Binds an HTTP listener, exposes `/` and
//! `/healthz`, and leaves a TODO marker until Phase B wires
//! `oath::server`.

use axum::Router;
use axum::routing::get;
use eyre::Context as _;

mod config;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    install_tracing();

    let config = config::Config::from_env().wrap_err("loading configuration")?;
    tracing::info!(
        bind_addr = %config.bind_addr,
        data_dir = %config.data_dir.display(),
        "ott starting",
    );

    let app = Router::new()
        .route("/", get(home))
        .route("/healthz", get(health));

    let listener = tokio::net::TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("binding {}", config.bind_addr))?;
    tracing::info!(addr = %listener.local_addr()?, "listening");

    axum::serve(listener, app).await.wrap_err("axum::serve")?;
    Ok(())
}

async fn home() -> &'static str {
    "ott — sign-in flow not yet wired (Phase B)\n"
}

async fn health() -> &'static str {
    "ok\n"
}

fn install_tracing() {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt;
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,ott=debug")),
        )
        .init();
}
