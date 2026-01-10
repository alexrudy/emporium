//! Basic OCI registry server example
//!
//! Run with: cargo run -p registry --example basic_server

use registry::RegistryBuilder;
use storage::MemoryStorage;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create an in-memory storage backend
    let storage = MemoryStorage::with_buckets(&["registry"]);

    // Build the registry service
    let app = RegistryBuilder::new()
        .storage(storage.into())
        .bucket("registry")
        .build();

    // Bind to address
    let addr = "127.0.0.1:5000";
    let listener = tokio::net::TcpListener::bind(addr).await?;

    tracing::info!("OCI Registry listening on http://{}", addr);
    tracing::info!("Try: curl http://{}/v2/", addr);

    // Serve the registry
    axum::serve(listener, app).await?;

    Ok(())
}
