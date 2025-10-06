use reqwest::{redirect::Policy, ClientBuilder};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Metadata error: {msg}")]
pub struct MetaDataError {
    msg: String,
}

impl From<reqwest::Error> for MetaDataError {
    fn from(err: reqwest::Error) -> Self {
        MetaDataError {
            msg: err.to_string(),
        }
    }
}

#[derive(Deserialize)]
pub (crate) struct IssuerMetadata {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
    jwks_uri: String,
}

impl IssuerMetadata {
    pub async fn from_issuer(issuer_url: &str) -> Result<Self, MetaDataError> {
        let url = if issuer_url.ends_with('/') {
            format!("{}{}", issuer_url, ".well-known/openid-configuration")
        } else {
            format!("{}/{}", issuer_url, ".well-known/openid-configuration")
        };

        let client = ClientBuilder::new()
            .redirect(Policy::none())
            .build()?;

        let resp = client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await?
            .error_for_status()?
            .json::<IssuerMetadata>()
            .await?;

        Ok(resp)
    }
    
    pub fn authorization_endpoint(&self) -> &str {
        &self.authorization_endpoint
    }

    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }

    pub fn userinfo_endpoint(&self) -> &str {
        &self.userinfo_endpoint
    }

    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }
}


