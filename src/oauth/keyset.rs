use std::sync::Arc;

use jsonwebtoken::DecodingKey;
use thiserror::Error;

use crate::oauth::client::{create_http_client, CreateHttpClientError};

#[derive(Debug, Error)]
#[error("Get JWK error: {0}")]
pub struct GetKeyError(String);

impl From<CreateHttpClientError> for GetKeyError {
    fn from(err: CreateHttpClientError) -> Self {
        GetKeyError(err.to_string())
    }
}

#[derive(serde::Deserialize, Debug)]
pub struct KeyResponse {
    kid: String,
    kty: String,
    alg: String,
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
pub struct KeySetResponse {
    keys: Vec<KeyResponse>,
}

impl KeySetResponse {
    pub fn into_keys(self) -> Vec<Jwk> {
        self.keys.into_iter().map(|k| Jwk(Arc::new(k))).collect()
    }
}

pub struct Jwk(Arc<KeyResponse>);

impl Clone for Jwk {
    fn clone(&self) -> Self {
        Jwk(Arc::clone(&self.0))
    }
}

pub struct KeyFetcher {
    jwks_url: String,
}
impl KeyFetcher {
    pub fn new(jwks_url: &str) -> Self {
        KeyFetcher {
            jwks_url: jwks_url.to_owned(),
        }
    }
    pub async fn fetch_key(&self, key_id: &str) -> Result<Jwk, GetKeyError> {
        let client = create_http_client()?;

        let res = client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| GetKeyError(format!("HTTP request error: {}", e)))?;

        let keyset: KeySetResponse = res
            .json()
            .await
            .map_err(|e| GetKeyError(format!("Error parsing JWKs response: {}", e)))?;

        for key in keyset.into_keys() {
            if key.0.kid == key_id {
                return Ok(key);
            }
        }

        Err(GetKeyError("Key ID of the token was not found in JWKs".to_string()))
    }
}

pub trait Key {
    // Tightly coupled to jsonwebtoken DecodingKey for now
    fn to_decoding_key(&self, key_fetcher: &KeyFetcher) -> impl Future<Output = Result<DecodingKey, jsonwebtoken::errors::Error>>;
}