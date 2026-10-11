//! The otunnel `axum::Router`: the OAuth2 routes under `/auth`, with every
//! other request forwarded to the upstream once the user is signed in.

use axum::Router;
use http::{HeaderName, StatusCode};
use hyperdriver::client::{
    conn::ConnectionManagerLayer,
    conn::{service::ClientExecutorService, transport::tcp::TcpTransport},
};
use hyperdriver::{
    client::conn::{dns::GaiResolver, protocol::Http1Builder},
    service::Http1ChecksLayer,
};
use hyproxy::{
    headers::{ConnectionHeaders, SetViaHeaderLayer, StripHopByHopLayer, via::ViaAddress},
    upgrade::ProxyUpgradeLayer,
};
use otool::{build_router, router_with_chooser};
use tower_http::{
    catch_panic::CatchPanicLayer, propagate_header::PropagateHeaderLayer,
    request_id::SetRequestIdLayer, sensitive_headers::SetSensitiveHeadersLayer, trace::TraceLayer,
};

use crate::config::Config;
use crate::proxy::{ProxyLayer, ProxyRequestId};
use crate::state::AppState;

/// Build the complete otunnel router.
pub async fn build(state: &AppState, config: &Config) -> Result<Router, otool::BuildError> {
    let middleware = tower::ServiceBuilder::new()
        .layer(CatchPanicLayer::new())
        .layer(SetSensitiveHeadersLayer::new(vec![
            http::header::AUTHORIZATION,
            http::header::COOKIE,
            http::header::SET_COOKIE,
            http::header::PROXY_AUTHORIZATION,
            http::header::WWW_AUTHENTICATE,
            http::header::PROXY_AUTHENTICATE,
        ]))
        .layer(PropagateHeaderLayer::new(HeaderName::from_static(
            "x-request-id",
        )))
        .layer(SetRequestIdLayer::new(
            HeaderName::from_static("x-proxy-request-id"),
            ProxyRequestId,
        ))
        .layer(TraceLayer::new_for_http());

    let service = tower::ServiceBuilder::new()
        .layer(axum::error_handling::HandleErrorLayer::new(
            |error| async move {
                tracing::error!(%error, "internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "An internal server error occured",
                )
            },
        ))
        .layer(ProxyLayer::new(state.clone()))
        // Outside `SetViaHeaderLayer`, so only client-sent headers are
        // stripped. Connection-scoped headers go too, except what an
        // upgrade (e.g. WebSockets) needs.
        .layer(StripHopByHopLayer::new().connection_headers(ConnectionHeaders::PreserveUpgrade))
        .layer(SetViaHeaderLayer::new(
            ViaAddress::named("otunnel").expect("valid Via name"),
        ))
        .layer(ProxyUpgradeLayer::new())
        .layer(ConnectionManagerLayer::new(
            TcpTransport::new(GaiResolver::new(), config.tcp.clone().into()),
            Http1Builder::new(),
        ))
        .layer(Http1ChecksLayer::new())
        .service(ClientExecutorService::new());

    Ok(
        router_with_chooser(build_router::<http::Uri>(&state.inner).await?)
            .fallback_service(service)
            .layer(middleware),
    )
}
