//! ott — OAuth Test Tool.
//!
//! A reference axum application that exercises the
//! `oath::server` feature end-to-end. See `PLAN.md` and `README.md`
//! for setup.

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use eyre::Context as _;
use oath::server::{InMemorySessionStore, JsonFileUserStore, OAuth2Router};
use oath::{Scope, ScopeSet, TokenEndpoint};
use rust_embed::Embed;
use storage::LocalDriver;
use tower_http::trace::TraceLayer;

use crate::embed::EmbedServer;

mod auth;
mod config;
mod embed;
mod handlers;
mod state;
mod templates;
mod user;

use crate::state::AppState;
use crate::user::AppUser;

/// All files under `static/` are embedded into the binary and served
/// by the [`EmbedServer`] under `/static/`.
#[derive(Embed)]
#[folder = "static/"]
struct StaticAssets;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    install_tracing();

    let config = config::Config::from_env().wrap_err("loading configuration")?;
    tracing::info!(
        bind_addr = %config.bind_addr,
        data_dir = %config.data_dir,
        provider = %config.provider_name,
        redirect_uri = %config.redirect_uri(),
        "ott starting",
    );

    // Ensure the data dir exists so the `LocalDriver`-backed user
    // store has somewhere to write.
    tokio::fs::create_dir_all(config.data_dir.as_std_path())
        .await
        .wrap_err_with(|| format!("creating data_dir {}", config.data_dir))?;

    let driver = LocalDriver::new(config.data_dir.clone());
    let users: JsonFileUserStore<LocalDriver, AppUser> = JsonFileUserStore::new(driver, "users");

    let endpoint = TokenEndpoint::builder()
        .client_id(config.client_id.clone())
        .client_secret(config.client_secret.clone())
        .auth_uri(config.auth_uri.clone())
        .token_uri(config.token_uri.clone())
        .redirect_uri(config.redirect_uri())
        .build()
        .wrap_err("building TokenEndpoint")?;

    let sessions = InMemorySessionStore::default();

    // Build the OAuth2 sub-router from oath. It owns clones of the
    // session and user stores; the AppState below holds the same
    // clones so ott's handlers can read them.
    let oauth_router = OAuth2Router::new(
        endpoint,
        sessions.clone(),
        users.clone(),
        user::identity_resolver(),
        config.cookie_key.clone(),
    )
    .scopes(ensure_openid(config.scopes.clone()))
    .secure_cookies(config.secure_cookies)
    .into_router();

    let state = AppState {
        config: Arc::new(config),
        templates: Arc::new(templates::environment()),
        sessions,
        users,
    };
    let bind_addr = state.config.bind_addr;

    let static_server: EmbedServer<StaticAssets> = EmbedServer::with_prefix("static");

    let app = Router::new()
        .route("/", get(handlers::home))
        .route("/profile", get(handlers::profile))
        .route("/healthz", get(handlers::health))
        .route_service("/static/{*path}", static_server)
        .merge(oauth_router)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("binding {bind_addr}"))?;
    tracing::info!(addr = %listener.local_addr()?, "listening");

    axum::serve(listener, app).await.wrap_err("axum::serve")?;
    Ok(())
}

/// We rely on `parse_id_token` to extract identity, which means the
/// `id_token` *must* come back from the token endpoint — which in turn
/// means `openid` must be in the requested scope set. Add it
/// defensively if the operator forgot.
fn ensure_openid(mut scopes: ScopeSet) -> ScopeSet {
    if !scopes.iter().any(|s| s.as_str() == "openid") {
        let mut updated = ScopeSet::new();
        updated.push(Scope::from_static("openid"));
        for scope in scopes.iter() {
            updated.push(scope.clone());
        }
        scopes = updated;
    }
    scopes
}

fn install_tracing() {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt;
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,ott=debug,tower_http=info")),
        )
        .init();
}
