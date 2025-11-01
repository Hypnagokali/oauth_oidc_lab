use std::{env::{self, VarError}, sync::Arc};

use base64::{prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD}, Engine};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Digest;

use crate::oauth::{client::{create_http_client, CreateHttpClientError}, identity::{UserIdentity, UserIdentityError}, oidc::IssuerMetadata, userinfo::UserInfoAttributes};


#[derive(Serialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
}

impl TokenRequest {
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
struct TokenResponse {
    access_token: String,
    token_type: String,
    id_token: Option<String>,
    expires_in: Option<u64>,
    refresh_expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

pub struct AccessToken {
    raw_token: String,
    token_type: String,
    expires_in: Option<u64>,
}

pub struct RefreshToken {
    raw_token: String,
    expires_in: Option<u64>,
}

pub struct IdToken {
    raw_token: String,
    // maybe different name? nonce for verification
    nonce: String,
}

pub struct TokenProvider {
    access_token: AccessToken,
    id_token: Option<IdToken>,
    refresh_token: Option<RefreshToken>,
    config: Arc<OAuthConfig>,
}

#[derive(Debug, thiserror::Error)]
#[error("Token validation error: {0}")]
pub struct TokenValidationError(String);

impl From<UserIdentityError> for TokenValidationError {
    fn from(err: UserIdentityError) -> Self {
        TokenValidationError(err.to_string())
    }
}

impl TokenProvider {
    pub async fn identity<C: DeserializeOwned>(&self) -> Result<UserIdentity<C>, TokenValidationError> {
        if let Some(id_token) = &self.id_token {
            let identity = UserIdentity::from_token(&id_token.raw_token, &*self.config, &id_token.nonce)?;
            Ok(identity)
        } else {
            Err(TokenValidationError("No ID token available for identity extraction".to_string()))
        }
    }

    // TODO: Replace Error type
    pub async fn user_info<UA: UserInfoAttributes>(&self) -> Result<UA, TokenRequestError> {
        let client = create_http_client()?;

        let user_response_result = client.get(&self.config.userinfo_endpoint)
            .header("Authorization", format!("{} {}", self.access_token.token_type, self.access_token.raw_token))
            .send()
            .await;

        let user_response = match user_response_result {
            Err(e) => {
                println!("Error during user info request: {}", e);
                return Err(TokenRequestError(format!("Error during user info request: {}", e)));
            },
            Ok(response) => response,
        };

        // TODO: use logging crate here
        println!("Response status from user info request: {}", user_response.status());

        if user_response.status().as_u16() >= 400 {
            return Err(TokenRequestError(format!("Couldn't fetch user info data: {}", user_response.status())));
        }

        match user_response.json().await {
            Ok(json) => return Ok(json),
            Err(e) => {
                println!("Error parsing user info response: {}", e);
                return Err(TokenRequestError(format!("Error parsing user info response: {}", e)));
            }
        };
    }
}

impl From<(Arc<OAuthConfig>, TokenResponse, Option<&str>)> for TokenProvider {
    fn from((config, response, nonce): (Arc<OAuthConfig>, TokenResponse, Option<&str>)) -> Self {
        let access_token = AccessToken {
            raw_token: response.access_token,
            token_type: response.token_type,
            expires_in: response.expires_in,
        };

        let id_token = match response.id_token {
            Some(id_token_str) => Some(IdToken {
                raw_token: id_token_str,
                // set nonce to an empty string if not provided (should be okay for now)
                nonce: nonce.unwrap_or("").to_string(),
            }),
            None => None,
        };

        let refresh_token = match response.refresh_token {
            Some(refresh_token_str) => Some(RefreshToken {
                raw_token: refresh_token_str,
                expires_in: response.refresh_expires_in,
            }),
            None => None,
        };

        TokenProvider {
            access_token,
            id_token,
            refresh_token,
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
#[error("OAuthConfig error: {0}")]
pub struct OAuthConfigError(String);

impl From<VarError> for OAuthConfigError {
    fn from(err: VarError) -> Self {
        OAuthConfigError(err.to_string())
    }
}

#[derive(Debug)]
pub struct OAuthConfig {
    // ToDo: pkce and method needed
    client_id: String,
    client_secret: String,
    oauth_user_name: Option<String>,
    redirect_uri: String,
    auth_uri: String,
    token_uri: String,
    userinfo_endpoint: String,
    scopes: Vec<String>,
}


impl OAuthConfig {
    pub async fn from_env() -> Result<Self, OAuthConfigError> {
        let client_id = env::var("client_id")?;
        let client_secret = env::var("client_secret")?;
        let scopes_from_env = env::var("scopes").unwrap_or("".into());

        let scopes: Vec<String> = scopes_from_env.split(',').map(|s| s.trim().to_lowercase().to_string()).collect();
    
        if scopes_from_env.contains("openid") {
            match env::var("issuer_url") {
                Ok(issuer_url) => {
                    let meta_data = IssuerMetadata::from_issuer(&issuer_url).await.expect("Failed to fetch OIDC metadata");

                    let conf = OAuthConfig::new(
                        client_id,
                        client_secret,
                        None,
                        env::var("redirect_uri")?,
                        meta_data.authorization_endpoint().to_string(),
                        meta_data.token_endpoint().to_string(),
                        meta_data.userinfo_endpoint().to_string(),
                        scopes,
                    );

                    println!("{conf:?}");
                    return Ok(conf);
                }
                Err(_) => {
                    println!("Missing issuer_url. No provider discovery possible. OAuthConfig will now use manual vars instead.");
                }
            }
        }

        let oauth_user_name = env::var("oauth_user_name")?;
        let redirect_uri = env::var("redirect_uri")?;
        let auth_uri = env::var("auth_uri")?;
        let token_uri = env::var("token_uri")?;
        let user_info_endpoint = env::var("userinfo_endpoint")?;

        Ok(OAuthConfig::new(client_id, client_secret, Some(oauth_user_name), redirect_uri, auth_uri, token_uri, user_info_endpoint, scopes))
    }

    pub fn is_openid(&self) -> bool {
        self.scopes.iter().any(|s| s == "openid")
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn new(
        client_id: String,
        client_secret: String,
        oauth_user_name: Option<String>,
        redirect_uri: String,
        auth_uri: String,
        token_uri: String,
        userinfo_endpoint: String,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            oauth_user_name,
            redirect_uri,
            auth_uri,
            token_uri,
            userinfo_endpoint,
            scopes,
        }
    }

    fn token_request(&self) -> TokenRequest {
        TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: "".to_string(),
            redirect_uri: self.redirect_uri.clone(),
            code_verifier: "".to_string(),
        }
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

pub struct OAuthProvider {
    config: Arc<OAuthConfig>,
}

impl OAuthProvider {
    pub fn new(config: OAuthConfig) -> Self {
        OAuthProvider { 
            config: Arc::new(config),
        }
    }

    pub fn is_openid(&self) -> bool {
        self.config.is_openid()
    }

    pub fn build_authentication_url_with_nonce(&self, state: &str, pkce_challenge: &str, nonce: &str) -> String {
        let base_url = self.build_authentication_url(state, pkce_challenge);
        format!("{}&nonce={}", base_url, nonce)
    }

    pub fn build_authentication_url(&self, state: &str, pkce_challenge: &str) -> String {
        let mut hasher = sha2::Sha256::new();
        hasher.update(pkce_challenge.as_bytes());
        let hash_bytes = hasher.finalize();
        let pkce_hash_b64 = BASE64_URL_SAFE_NO_PAD.encode(hash_bytes);   

        let redirect_uri = urlencoding::encode(&self.config.redirect_uri);

        // TODO: handle empty scopes
        let scope = self.config.scopes.join(" ");

        // Hardcoded response_type=code and code_challenge_method=S256 for now
        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&code_challenge_method=S256&code_challenge={}",
            self.config.auth_uri,
            self.config.client_id,
            redirect_uri,
            scope,
            state,
            pkce_hash_b64
        )
    }

    pub async fn code_to_token_request(&self, code: &str, pkce: &str, nonce: Option<&str>) -> Result<TokenProvider, TokenRequestError> {
        let mut token_request = self.config.token_request();
        token_request.set_code(code);
        token_request.set_code_verifier(pkce);

        let body = match token_request.to_urlencoded() {
            Ok(body) => body,
            Err(e) => {
                println!("Error serializing token request: {}", e);
                return Err(TokenRequestError(format!("Error serializing token request: {}", e)));
            }
        };

        let auth_header_value = format!("Basic {}", BASE64_STANDARD.encode(format!("{}:{}", self.config.client_id, self.config.client_secret)));

        let client = create_http_client()?;

        let token_response_result = client.post(&self.config.token_uri)
            .header("Authorization", auth_header_value)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .send()
            .await;

        let token_response = match token_response_result {
            Err(e) => {
                println!("Error during token request: {}", e);
                return Err(TokenRequestError(format!("Error during token request: {}", e)));
            },
            Ok(response) => response,
        };
        

        println!("Token response status: {}", token_response.status());
        let status = token_response.status();

        let token_raw_response = match token_response.text().await {
            Ok(body) => body,
            Err(e) => {
                println!("Error parsing token response body: {}", e);
                return Err(TokenRequestError(format!("Error parsing token response body: {}", e)));
            }
        };

        println!("raw token response:\n{}", token_raw_response);

        if status.as_u16() >= 400 {
            return Err(TokenRequestError(format!("Token request failed: {} - {}", status, token_raw_response)));
        }

        let token_response = match serde_json::from_str::<TokenResponse>(&token_raw_response) {
            Ok(token_response) => {
                token_response
            },
            Err(e) => {
                println!("Error deserializing token response: {}", e);
                return Err(TokenRequestError(format!("Error deserializing token response: {}", e)));
            }
        };

        Ok((Arc::clone(&self.config), token_response, nonce).into())
    }
}


    