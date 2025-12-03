use std::sync::Arc;

use base64::{
    Engine,
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
};
use rand::{TryRngCore, rand_core::OsError, rngs::OsRng};
use serde::{Deserialize, de::DeserializeOwned};
use sha2::Digest;

use crate::{
    UserMapper,
    oauth::{
        client::{CreateHttpClientError, TokenResponse, create_http_client},
        config::{OAuthConfig, PkceMethod},
        identity::{DefaultTokenValidation, TokenValidationError, UserIdentity},
    },
};

pub struct AccessToken {
    raw_token: String,
    token_type: String,
    expires_in: Option<u64>,
}

impl AccessToken {
    pub fn raw_token(&self) -> &str {
        &self.raw_token
    }

    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    pub fn expires_in(&self) -> Option<u64> {
        self.expires_in
    }
}

pub struct RefreshToken {
    raw_token: String,
    expires_in: Option<u64>,
}

impl RefreshToken {
    pub fn raw_token(&self) -> &str {
        &self.raw_token
    }

    pub fn expires_in(&self) -> Option<u64> {
        self.expires_in
    }
}

pub struct IdToken {
    raw_token: String,
    // maybe different name? nonce for verification
    nonce: String,
}

pub struct TokenProvider {
    access_token: Arc<AccessToken>,
    id_token: Option<IdToken>, // no Arc needed, because the user cannot retrieve it directly
    refresh_token: Option<Arc<RefreshToken>>,
    config: Arc<OAuthConfig>,
}

impl TokenProvider {
    pub fn access_token(&self) -> Arc<AccessToken> {
        Arc::clone(&self.access_token)
    }

    pub fn refresh_token(&self) -> Option<Arc<RefreshToken>> {
        self.refresh_token.as_ref().map(Arc::clone)
    }

    pub async fn identity<C: DeserializeOwned>(
        &self,
    ) -> Result<UserIdentity<C>, TokenValidationError> {
        if let Some(id_token) = &self.id_token {
            let identity = UserIdentity::from_token(
                &id_token.raw_token,
                DefaultTokenValidation,
                &self.config,
                &id_token.nonce,
            )
            .await?;
            Ok(identity)
        } else {
            Err(TokenValidationError(
                "No ID token available for identity extraction".to_string(),
            ))
        }
    }

    // TODO: Replace Error type
    pub async fn user_info<UA: DeserializeOwned>(&self) -> Result<UA, TokenRequestError> {
        let client = create_http_client()?;

        let user_response_result = client
            .get(self.config.userinfo_endpoint())
            .header(
                "Authorization",
                format!(
                    "{} {}",
                    self.access_token.token_type, self.access_token.raw_token
                ),
            )
            .send()
            .await;

        let user_response = match user_response_result {
            Err(e) => {
                println!("Error during user info request: {}", e);
                return Err(TokenRequestError(format!(
                    "Error during user info request: {}",
                    e
                )));
            }
            Ok(response) => response,
        };

        // TODO: use logging crate here
        println!(
            "Response status from user info request: {}",
            user_response.status()
        );

        if user_response.status().as_u16() >= 400 {
            return Err(TokenRequestError(format!(
                "Couldn't fetch user info data: {}",
                user_response.status()
            )));
        }

        let user_body = match user_response.text().await {
            Ok(body) => body,
            Err(e) => {
                println!("Error reading user info response body: {}", e);
                return Err(TokenRequestError(format!(
                    "Error reading user info response body: {}",
                    e
                )));
            }
        };

        match serde_json::from_str::<UA>(&user_body) {
            Ok(json) => Ok(json),
            Err(e) => {
                println!(
                    "Error parsing user info response. Raw response body:\n{}",
                    user_body
                );
                Err(TokenRequestError(format!(
                    "Error parsing user info response: {}",
                    e
                )))
            }
        }
    }
}

impl From<(Arc<OAuthConfig>, TokenResponse, Option<String>)> for TokenProvider {
    fn from((config, response, nonce): (Arc<OAuthConfig>, TokenResponse, Option<String>)) -> Self {
        let access_token: AccessToken = AccessToken {
            raw_token: response.access_token().to_owned(),
            token_type: response.token_type().to_owned(),
            expires_in: response.expires_in(),
        };

        let id_token = response.id_token().map(|id_token_str| {
            IdToken {
                raw_token: id_token_str.to_owned(),
                // set nonce to an empty string if not provided (should be okay for now)
                nonce: nonce.unwrap_or_default(),
            }
        });

        let refresh_token = response
            .refresh_token()
            .map(|refresh_token_str| RefreshToken {
                raw_token: refresh_token_str.to_owned(),
                expires_in: response.refresh_expires_in(),
            });

        TokenProvider {
            access_token: Arc::new(access_token),
            id_token,
            refresh_token: refresh_token.map(Arc::new),
            config,
        }
    }
}

#[derive(Deserialize)]
pub struct AuthCodeResponse {
    code: String,
    state: String,
}

impl AuthCodeResponse {
    pub fn code(&self) -> &str {
        &self.code
    }

    pub fn state(&self) -> &str {
        &self.state
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Token request error: {0}")]
pub struct TokenRequestError(String);

impl From<CreateHttpClientError> for TokenRequestError {
    fn from(err: CreateHttpClientError) -> Self {
        TokenRequestError(err.to_string())
    }
}

pub struct OAuthProvider<U> {
    name: String,
    config: Arc<OAuthConfig>,
    user_mapper: Arc<dyn UserMapper<User = U>>,
}

impl<U> OAuthProvider<U> {
    pub fn new(
        name: &str,
        config: OAuthConfig,
        user_mapper: Arc<dyn UserMapper<User = U>>,
    ) -> Self {
        OAuthProvider {
            name: name.to_owned(),
            config: Arc::new(config),
            user_mapper,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn pkce_method(&self) -> &PkceMethod {
        self.config.pkce_method()
    }

    pub fn mapper(&self) -> Arc<dyn UserMapper<User = U>> {
        Arc::clone(&self.user_mapper)
    }

    pub fn is_openid(&self) -> bool {
        self.config.is_openid()
    }

    /// Build an authentication URL and generate state, pkce and optional nonce.
    /// Returns (redirect_url, state, pkce, nonce)
    pub fn build_authentication_url(
        &self,
    ) -> Result<(String, String, Option<String>, Option<String>), OsError> {
        let state = generate_random_code()?;

        let pkce = match self.config.pkce_method() {
            PkceMethod::None => None,
            PkceMethod::Plain => Some(("plain", generate_random_code()?)),
            PkceMethod::S256 => {
                let pkce = generate_random_code()?;
                let mut hasher = sha2::Sha256::new();
                hasher.update(pkce.as_bytes());
                let hash_bytes = hasher.finalize();
                Some(("S256", BASE64_URL_SAFE_NO_PAD.encode(hash_bytes)))
            }
        };

        let redirect_uri = urlencoding::encode(self.config.redirect_uri());

        // TODO: handle empty scopes
        let scope = self.config.scopes().join(" ");

        let pkce_param = match pkce {
            Some((method, ref value)) => {
                format!("&code_challenge_method={}&code_challenge={}", method, value)
            }
            None => "".to_owned(),
        };

        let mut url = format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}{}",
            self.config.auth_uri(),
            self.config.client_id(),
            redirect_uri,
            scope,
            state,
            pkce_param
        );

        let nonce = if self.config.is_openid() {
            let n = generate_random_code()?;
            url = format!("{}&nonce={}", url, n);
            Some(n)
        } else {
            None
        };

        Ok((url, state, pkce.map(|(_, value)| value), nonce))
    }

    pub async fn code_to_token_request(
        &self,
        code: &str,
        pkce: Option<String>,
        nonce: Option<String>,
    ) -> Result<TokenProvider, TokenRequestError> {
        let mut token_request = self.config.token_request();
        token_request.set_code(code);

        if let Some(pkce) = pkce {
            token_request.set_code_verifier(&pkce);
        }

        let body = match token_request.to_urlencoded() {
            Ok(body) => body,
            Err(e) => {
                println!("Error serializing token request: {}", e);
                return Err(TokenRequestError(format!(
                    "Error serializing token request: {}",
                    e
                )));
            }
        };

        let auth_header_value = format!(
            "Basic {}",
            BASE64_STANDARD.encode(format!(
                "{}:{}",
                self.config.client_id(),
                self.config.client_secret()
            ))
        );

        let client = create_http_client()?;

        let token_response_result = client
            .post(self.config.token_uri())
            .header("Authorization", auth_header_value)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await;

        let token_response = match token_response_result {
            Err(e) => {
                println!("Error during token request: {}", e);
                return Err(TokenRequestError(format!(
                    "Error during token request: {}",
                    e
                )));
            }
            Ok(response) => response,
        };

        println!("Token response status: {}", token_response.status());
        let status = token_response.status();

        let token_raw_response = match token_response.text().await {
            Ok(body) => body,
            Err(e) => {
                println!("Error parsing token response body: {}", e);
                return Err(TokenRequestError(format!(
                    "Error parsing token response body: {}",
                    e
                )));
            }
        };

        println!("raw token response:\n{}", token_raw_response);

        if status.as_u16() >= 400 {
            return Err(TokenRequestError(format!(
                "Token request failed: {} - {}",
                status, token_raw_response
            )));
        }

        let token_response = match serde_json::from_str::<TokenResponse>(&token_raw_response) {
            Ok(token_response) => token_response,
            Err(e) => {
                println!("Error deserializing token response: {}", e);
                return Err(TokenRequestError(format!(
                    "Error deserializing token response: {}",
                    e
                )));
            }
        };

        Ok((Arc::clone(&self.config), token_response, nonce).into())
    }
}

fn generate_random_code() -> Result<String, OsError> {
    let mut random_bytes = [0u8; 64];
    OsRng.try_fill_bytes(&mut random_bytes)?;
    Ok(BASE64_URL_SAFE_NO_PAD.encode(random_bytes))
}
