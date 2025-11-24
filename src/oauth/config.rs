use std::env::{self, VarError};

use crate::oauth::{client::TokenRequest, oidc::IssuerMetadata};

#[derive(Debug, PartialEq)]
pub enum PkceMethod {
    None,
    Plain,
    S256,
}

impl PkceMethod {
    pub fn is_required(&self) -> bool {
        self != &PkceMethod::None
    }
}

#[derive(Debug, thiserror::Error)]
#[error("OAuthConfig error: {0}")]
pub struct OAuthConfigError(pub String);

impl From<VarError> for OAuthConfigError {
    fn from(err: VarError) -> Self {
        OAuthConfigError(err.to_string())
    }
}

fn read_env_var(key: &str) -> Result<String, OAuthConfigError> {
    match env::var(key) {
        Ok(value) => Ok(value),
        Err(e) => Err(OAuthConfigError(format!(
            "Failed to read .env variable {}: {}",
            key, e
        ))),
    }
}

#[derive(Debug)]
pub struct OAuthConfig {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    auth_uri: String,
    token_uri: String,
    userinfo_endpoint: String,
    scopes: Vec<String>,
    pkce_method: PkceMethod,
    metadata: Option<IssuerMetadata>,
}

impl OAuthConfig {
    pub async fn from_env() -> Result<Self, OAuthConfigError> {
        Self::from_env_with_prefix("").await
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub (crate) fn client_secret(&self) -> &str {
        &self.client_secret
    }

    pub fn auth_uri(&self) -> &str {
        &self.auth_uri
    }

    pub fn token_uri(&self) -> &str {
        &self.token_uri
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub fn scopes(&self) -> &Vec<String> {
        &self.scopes
    }

    pub fn set_pkce_method(&mut self, method: PkceMethod) {
        self.pkce_method = method;
    }

    pub fn pkce_method(&self) -> &PkceMethod {
        &self.pkce_method
    }

    pub fn userinfo_endpoint(&self) -> &str {
        &self.userinfo_endpoint
    }

    pub fn is_openid(&self) -> bool {
        self.scopes.iter().any(|s| s == "openid")
    }

    pub(crate) fn metadata(&self) -> Option<&IssuerMetadata> {
        self.metadata.as_ref()
    }

    pub async fn from_env_with_prefix(provider_name: &str) -> Result<Self, OAuthConfigError> {
        let prefix = format!("{}_", provider_name.to_uppercase());

        let client_id = read_env_var(&format!("{}CLIENT_ID", prefix))?;
        let client_secret = read_env_var(&format!("{}CLIENT_SECRET", prefix))?;
        let scopes_from_env = read_env_var(&format!("{}SCOPES", prefix)).unwrap_or("".into());
        let host = read_env_var("HOST")?;

        let provider_name = provider_name.to_lowercase();
        let redirect_uri = format!("{}/login/oauth2/code/{}", host, provider_name);

        let scopes: Vec<String> = scopes_from_env
            .split(',')
            .map(|s| s.trim().to_lowercase().to_string())
            .collect();

        if scopes_from_env.contains("openid") {
            match env::var(format!("{}ISSUER_URL", prefix)) {
                Ok(issuer_url) => {
                    let metadata = IssuerMetadata::from_issuer(&issuer_url)
                        .await
                        .expect("Failed to fetch OIDC metadata");

                    let conf = OAuthConfig::new(
                        client_id,
                        client_secret,
                        redirect_uri,
                        metadata.authorization_endpoint().to_string(),
                        metadata.token_endpoint().to_string(),
                        metadata.userinfo_endpoint().to_string(),
                        scopes,
                        Some(metadata),
                        PkceMethod::None,
                    );

                    return Ok(conf);
                }
                Err(_) => {
                    println!(
                        "Missing {prefix}ISSUER_URL. No provider discovery possible. OAuthConfig will now use manual vars instead."
                    );
                }
            }
        }

        let auth_uri = env::var(format!("{}AUTH_URI", prefix))?;
        let token_uri = env::var(format!("{}TOKEN_URI", prefix))?;
        let user_info_endpoint = env::var(format!("{}USERINFO_ENDPOINT", prefix))?;

        Ok(OAuthConfig::new(
            client_id,
            client_secret,
            redirect_uri,
            auth_uri,
            token_uri,
            user_info_endpoint,
            scopes,
            None,
            PkceMethod::None,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        client_id: String,
        client_secret: String,
        redirect_uri: String,
        auth_uri: String,
        token_uri: String,
        userinfo_endpoint: String,
        scopes: Vec<String>,
        oidc_metadata: Option<IssuerMetadata>,
        pkce_method: PkceMethod,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_uri,
            auth_uri,
            token_uri,
            userinfo_endpoint,
            scopes,
            metadata: oidc_metadata,
            pkce_method,
        }
    }

    pub (crate)fn token_request(&self) -> TokenRequest {
        TokenRequest::new("authorization_code", &self.redirect_uri)
    }
}