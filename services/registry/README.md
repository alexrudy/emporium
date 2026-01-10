# OCI Container Registry

An [OCI Distribution Specification]-compliant container registry implementation in Rust.


```rust
use registry::RegistryBuilder;
use storage::MemoryStorage;

#[tokio::main]
async fn main() {
    // Create a storage backend
    let storage = MemoryStorage::with_buckets(&["registry"]);

    // Build the registry service
    let registry = RegistryBuilder::new()
        .storage(storage.into())
        .bucket("registry")
        .build();

    // Use with any tower-compatible server
    // For example, with axum:
    let listener = tokio::net::TcpListener::bind("0.0.0.0:5000")
        .await
        .unwrap();
    axum::serve(listener, registry).await.unwrap();
}
```

## API Endpoints

The registry implements the following OCI Distribution API endpoints:

- `GET /v2/` - API version check
- `GET /v2/<name>/blobs/<digest>` - Download a blob
- `HEAD /v2/<name>/blobs/<digest>` - Check if a blob exists
- `DELETE /v2/<name>/blobs/<digest>` - Delete a blob
- `POST /v2/<name>/blobs/uploads/` - Start a blob upload session
- `PUT /v2/<name>/blobs/uploads/<uuid>` - Complete a blob upload
- `DELETE /v2/<name>/blobs/uploads/<uuid>` - Cancel a blob upload
- `GET /v2/<name>/manifests/<reference>` - Download a manifest
- `HEAD /v2/<name>/manifests/<reference>` - Check if a manifest exists
- `PUT /v2/<name>/manifests/<reference>` - Upload a manifest
- `DELETE /v2/<name>/manifests/<reference>` - Delete a manifest
- `GET /v2/<name>/tags/list` - List tags for a repository

## Storage Layout

The registry uses the following storage layout:

```
blobs/
  sha256/
    <digest>           # Blob data stored by digest
manifests/
  <repository>/
    <digest>           # Manifest data stored by digest
tags/
  <repository>/
    <tag>              # Tag reference (contains digest)
```

[OCI Distribution Specification]: (https://github.com/opencontainers/distribution-spec)
