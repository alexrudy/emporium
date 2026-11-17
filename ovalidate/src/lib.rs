use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyperdriver::{Body, client::SharedClientService, service::ServiceExt};

use jaws::{
    algorithms,
    crypto::{rsa, sha2},
    key::DeserializeJWK,
};
use oath::{Error, ProviderMetadata};

pub struct OIDCValidator {
    provider: ProviderMetadata,
}

pub struct Key {
    verifier: Arc<dyn jaws::algorithms::TokenVerifier>,
}

pub struct Keys {
    keys: Vec<Key>,
}

fn default_transport() -> SharedClientService<Body, Body> {
    hyperdriver::Client::build_tcp_http()
        .with_default_tls()
        .build_service()
}

async fn collect_response(resp: http::Response<Body>) -> Result<Bytes, Error> {
    let (parts, body) = resp.into_parts();
    let status = parts.status;
    let collected = body
        .collect()
        .await
        .map_err(|e| Error::Transport(api_client::Error::ResponseBody(e)))?;
    let bytes = collected.to_bytes();

    if !status.is_success() {
        return Err(Error::BadResponse {
            status,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        });
    }

    Ok(bytes)
}

async fn fetch_keys_with_transport(
    transprot: &SharedClientService<Body, Body>,
    jwks_uri: &str,
) -> Result<Vec<Key>, Error> {
    let req = http::Request::get(jwks_uri).body(Body::empty()).unwrap();
    let resp = transprot
        .clone()
        .oneshot(req)
        .await
        .map_err(|error| Error::Transport(api_client::Error::Request(error)))?;

    let body = collect_response(resp).await?;
    let keys: serde_json::Value =
        serde_json::from_slice(&body).map_err(|e| Error::Deserialize {
            source: e,
            body: String::from_utf8_lossy(&body).into_owned(),
        })?;

    let keys = keys
        .as_object()
        .and_then(|ks| ks.get("keys"))
        .and_then(|keys| keys.as_array())
        .ok_or_else(|| {
            Error::Transport(api_client::Error::ResponseBody(
                "Invalid JWK Set response".into(),
            ))
        })?;

    let mut key_set = Vec::new();

    for key in keys {
        let value = key.clone();
        let alg = &value["alg"];

        match alg.as_str().unwrap() {
            "RS256" => {
                if let Ok(pk) = rsa::RsaPublicKey::from_value(value) {
                    key_set.push(Key {
                        verifier: Arc::new(rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pk)),
                    });
                }
            }
            _ => panic!("unsupported algorithm"),
        }
    }

    Ok(key_set)
}
