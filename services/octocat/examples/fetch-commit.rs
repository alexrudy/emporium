//! Fetch a single commit from a repository using the Github API.

use std::sync::Arc;

use api_client::response::ResponseBodyExt as _;
use eyre::Report;
use jaws::crypto::rsa::{self, pkcs1::DecodeRsaPrivateKey};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt::init();

    let key = {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../.github/app-key.pem");

        let dst = tokio::fs::read_to_string(path).await?;
        rsa::RsaPrivateKey::from_pkcs1_pem(&dst).expect("valid pkcs8 key")
    };

    let app = octocat::GithubApp::new(
        std::env::var("GITHUB_APP_ID").expect("GITHUB_APP_ID is set"),
        Arc::new(key),
    );

    let client = app
        .installation_for_repo("linode-sokka", "automoton")
        .await?;
    let commit = client
        .get(&format!(
            "repos/{}/{}/commits/{}",
            "linode-sokka", "automoton", "6377dc6de44e3557bfc1d0b186581d442a77f774"
        ))
        .send()
        .await
        .map_err(|error| Report::msg(format!("Request error: {error}")))?
        .json::<octocat::models::Commit>()
        .await
        .map_err(|error| Report::msg(format!("Deserialize: {error}")))?;

    println!("{}", serde_json::to_string_pretty(&commit).unwrap());

    Ok(())
}
