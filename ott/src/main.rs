//! ott — OAuth Test Tool.
//!
//! A reference axum application that exercises the
//! `oath::server` feature end-to-end. See `PLAN.md` and `README.md`
//! for setup.

use std::sync::Arc;

use axum::Router;
use axum::routing::get;
use eyre::Context as _;
use oath::provider::OAuthProviderConfig;
use oath::server::{InMemorySessionStore, JsonFileUserStore, OAuth2Router, Provider};
use oath::{Scope, ScopeSet};
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

use crate::state::{AppState, ProviderLink};
use crate::user::AppUser;

use self::handlers::render_errors;

/// All files under `static/` are embedded into the binary and served
/// by the [`EmbedServer`] under `/static/`.
#[derive(Embed)]
#[folder = "static/"]
struct StaticAssets;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    install_tracing();

    let config = load_config().wrap_err("loading configuration")?;
    tracing::info!(
        bind_addr = %config.bind_addr,
        data_dir = %config.data_dir,
        "ott starting",
    );

    // Ensure the data dir exists so the `LocalDriver`-backed user
    // store has somewhere to write.
    tokio::fs::create_dir_all(config.data_dir.as_std_path())
        .await
        .wrap_err_with(|| format!("creating data_dir {}", config.data_dir))?;

    let driver = LocalDriver::new(config.data_dir.clone());
    let users: JsonFileUserStore<LocalDriver, AppUser> = JsonFileUserStore::new(driver, "users");

    let sessions = InMemorySessionStore::default();

    // Build the OAuth2 sub-router from oath. It owns clones of the
    // session and user stores; the AppState below holds the same
    // clones so ott's handlers can read them.
    let mut oauth = OAuth2Router::<_, _, http::Uri>::multi_provider(
        sessions.clone(),
        users.clone(),
        user::identity_resolver(),
        config.cookie_key.clone(),
    )
    .scopes(ensure_openid(config.scopes.clone()))
    .secure_cookies(config.secure_cookies);
    let router_config = oauth.router_config().clone();

    if let Some(provider) = &config.root_provider {
        let endpoint =
            resolve_endpoint("default", provider, &router_config.callback_path()).await?;
        oauth = oauth.provider(customize(Provider::root(endpoint), provider));
    }
    for (id, provider) in &config.providers {
        let callback_path = router_config.provider_callback_path(id);
        let endpoint = resolve_endpoint(id.as_str(), provider, &callback_path).await?;
        oauth = oauth.provider(customize(Provider::new(id.clone(), endpoint), provider));
    }
    if let Some(default) = &config.default_provider {
        oauth = oauth.default_provider(default.clone());
    }

    let providers: Arc<[ProviderLink]> = oauth
        .providers()
        .map(|provider| ProviderLink {
            name: provider.display_name().to_owned(),
            login_path: provider.login_path(&router_config),
            callback_uri: config
                .public_uri(&provider.callback_path(&router_config))
                .to_string(),
        })
        .collect();
    for link in providers.iter() {
        tracing::info!(
            provider = %link.name,
            login = %link.login_path,
            redirect_uri = %link.callback_uri,
            "provider registered",
        );
    }

    let oauth_router = oauth.into_router();

    let state = AppState {
        config: Arc::new(config),
        templates: Arc::new(templates::environment()),
        sessions,
        users,
        providers,
        router_config: Arc::new(router_config),
    };
    let bind_addr = state.config.bind_addr;

    let static_server: EmbedServer<StaticAssets> = EmbedServer::with_prefix("static");

    let app = Router::new()
        .route("/", get(handlers::home))
        .route("/profile", get(handlers::profile))
        .route("/healthz", get(handlers::health))
        .route_service("/static/{*path}", static_server)
        .merge(oauth_router)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            render_errors,
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("binding {bind_addr}"))?;
    tracing::info!(addr = %listener.local_addr()?, "listening");

    axum::serve(listener, app).await.wrap_err("axum::serve")?;
    Ok(())
}

/// Load configuration from a TOML file when requested, otherwise from
/// process environment variables.
///
/// TOML mode is chosen by either `--config <path>` (or `-c <path>`,
/// `--config=<path>`) on the command line, or by `OTT_CONFIG=<path>`
/// in the environment. The CLI form takes precedence.
fn load_config() -> eyre::Result<config::Config> {
    if let Some(path) = config_path_from_args() {
        tracing::info!(path = %path.display(), "loading TOML config");
        return config::Config::from_toml_path(&path);
    }
    if let Ok(path) = std::env::var("OTT_CONFIG") {
        let path = std::path::PathBuf::from(path);
        tracing::info!(path = %path.display(), "loading TOML config (OTT_CONFIG)");
        return config::Config::from_toml_path(&path);
    }
    tracing::info!("loading config from process environment");
    config::Config::from_env()
}

fn config_path_from_args() -> Option<std::path::PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(rest) = arg.strip_prefix("--config=") {
            return Some(rest.into());
        }
        if let Some(rest) = arg.strip_prefix("-c=") {
            return Some(rest.into());
        }
        if arg == "--config" || arg == "-c" {
            return args.next().map(std::path::PathBuf::from);
        }
    }
    None
}

/// Build a provider's `TokenEndpoint`, fetching discovery metadata at
/// startup if it's configured with an issuer.
async fn resolve_endpoint(
    id: &str,
    provider: &OAuthProviderConfig,
    callback_path: &str,
) -> eyre::Result<oath::TokenEndpoint> {
    provider
        .provider(callback_path)
        .await
        .wrap_err_with(|| format!("setting up OAuth provider {id}"))
}

fn customize(provider: Provider, config: &OAuthProviderConfig) -> Provider {
    let provider = provider.with_display_name(config.provider_name.clone());
    match &config.scopes {
        Some(scopes) => provider.with_scopes(ensure_openid(scopes.clone())),
        None => provider,
    }
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
