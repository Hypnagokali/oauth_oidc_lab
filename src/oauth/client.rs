use reqwest::{
    ClientBuilder,
    header::{HeaderMap, HeaderValue},
    redirect::Policy,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub (crate) struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
}

impl TokenRequest {
    pub fn new(grant_type: &str, redirect_uri: &str) -> Self {
        Self {
            grant_type: grant_type.to_string(),
            code: "".to_string(),
            redirect_uri: redirect_uri.to_string(),
            code_verifier: "".to_string(),
        }
    }

    pub fn set_code(&mut self, code: &str) {
        self.code = code.to_string();
    }

    pub fn set_code_verifier(&mut self, code_verifier: &str) {
        self.code_verifier = code_verifier.to_string();
    }

    pub fn to_urlencoded(&self) -> Result<String, serde_urlencoded::ser::Error> {
        serde_urlencoded::to_string(self)
    }
}

#[derive(Deserialize)]
pub (crate) struct TokenResponse {
    access_token: String,
    token_type: String,
    id_token: Option<String>,
    expires_in: Option<u64>,
    refresh_expires_in: Option<u64>,
    refresh_token: Option<String>,
    #[allow(dead_code)]
    scope: Option<String>,
}

impl TokenResponse {
    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    pub fn expires_in(&self) -> Option<u64> {
        self.expires_in
    }
    
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref()
    }

    pub fn refresh_expires_in(&self) -> Option<u64> {
        self.refresh_expires_in
    }

    pub fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("HTTP client creation error: {0}")]
pub struct CreateHttpClientError(String);

pub(crate) fn create_http_client() -> Result<reqwest::Client, CreateHttpClientError> {
    // TODO: make user agent configurable or change it to something more generic
    let mut headers = HeaderMap::new();
    headers.insert("Accept", HeaderValue::from_static("application/json"));
    headers.insert("User-Agent", HeaderValue::from_static("OAuth2TestApp"));

    let client = match ClientBuilder::new()
        .redirect(Policy::none())
        .default_headers(headers)
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            println!("Error building HTTP client: {}", e);
            return Err(CreateHttpClientError(format!(
                "Error building HTTP client: {}",
                e
            )));
        }
    };
    Ok(client)
}
