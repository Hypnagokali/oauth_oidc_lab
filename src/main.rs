use std::pin::Pin;
use std::sync::Arc;

use actix_web::{App, HttpRequest, HttpResponseBuilder, HttpServer, Responder, get, web::Data};
use serde::Deserialize;

use crate::{
    frameworks::flow::{self, OAuthRoutes},
    oauth::{
        config::{OAuthConfig, PkceMethod},
        provider::{OAuthProvider, TokenProvider, TokenRequestError},
        registry::OAuthProviderRegistry,
    },
    session::{LoginSuccessHandler, SessionCreationError},
};

pub mod frameworks;
pub mod oauth;
pub mod session;

#[derive(Deserialize)]
pub struct MyUser {
    id: String,
    name: String,
    email: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("User mapping error: {0}")]
pub struct UserMappingError(pub String);

impl From<TokenRequestError> for UserMappingError {
    fn from(err: TokenRequestError) -> Self {
        UserMappingError(format!("Token request error: {}", err))
    }
}

pub trait UserMapper: Send + Sync {
    type User;
    fn to_user(
        &self,
        token_provider: TokenProvider,
    ) -> Pin<Box<dyn Future<Output = Result<Self::User, UserMappingError>> + Send>>;
}

/// UserInfo struct for GitHub's user info response.
#[derive(Deserialize)]
pub struct GitHubUserInfo {
    login: String,
    id: i64,
    email: Option<String>,
}

/// Mapper for GitHubUserInfo to User.
pub struct GitHubUserMapper;

impl UserMapper for GitHubUserMapper {
    type User = MyUser;

    fn to_user(
        &self,
        token_provider: TokenProvider,
    ) -> Pin<Box<dyn Future<Output = Result<Self::User, UserMappingError>> + Send>> {
        Box::pin(async move {
            let info: Result<GitHubUserInfo, _> = token_provider.user_info().await;
            info.map(|i| MyUser {
                name: i.login,
                id: i.id.to_string(),
                email: i.email,
            })
            .map_err(|e| e.into())
        })
    }
}

/// UserInfo struct for Keycloak's user info response.
#[derive(Deserialize)]
pub struct KcTestUserInfo {
    sub: String,
    name: String,
    email: Option<String>,
}

/// Mapper for KcTestUserInfo to User.
pub struct KeycloakUserMapper;

impl UserMapper for KeycloakUserMapper {
    type User = MyUser;
    fn to_user(
        &self,
        token_provider: TokenProvider,
    ) -> Pin<Box<dyn Future<Output = Result<Self::User, UserMappingError>> + Send>> {
        Box::pin(async move {
            let info: Result<KcTestUserInfo, _> = token_provider.user_info().await;
            info.map(|i: KcTestUserInfo| MyUser {
                id: i.sub,
                name: i.name,
                email: i.email,
            })
            .map_err(|e| e.into())
        })
    }
}

#[get("/")]
async fn login() -> impl Responder {
    use maud::html;
    html! {
        html {
            body {
                h1 { "Login page" }
                p { "This is a dummy site, nothing works at the moment" }
                div { a href="/login/oauth2/auth/github" { "Login with GitHub" } }
                div { a href="/login/oauth2/auth/keycloak" { "Login with Keycloak" } }
            }
        }
    }
}

pub struct SimpleLoginSuccessHandler;

impl LoginSuccessHandler<MyUser> for SimpleLoginSuccessHandler {
    async fn on_login_success(
        &self,
        _: HttpRequest,
        res: HttpResponseBuilder,
        user: &MyUser,
    ) -> Result<HttpResponseBuilder, SessionCreationError> {
        println!(
            "User logged in successfully: id={}, name={}, email={:?}",
            user.id, user.name, user.email
        );
        Ok(res)
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();

    let mut providers: Vec<OAuthProvider<MyUser>> = Vec::new();

    // GitHub provider with PKCE S256
    if let Ok(mut github_conf) = OAuthConfig::from_env_with_prefix("GITHUB").await {
        github_conf.set_pkce_method(PkceMethod::S256);

        let github_provider = OAuthProvider::new("github", github_conf, Arc::new(GitHubUserMapper));
        providers.push(github_provider);
    }

    // Keycloak provider
    if let Ok(keycloak_conf) = OAuthConfig::from_env_with_prefix("KEYCLOAK").await {
        let keycloak_provider =
            OAuthProvider::new("keycloak", keycloak_conf, Arc::new(KeycloakUserMapper));
        providers.push(keycloak_provider);
    }

    if providers.is_empty() {
        panic!("OAuth 2.0 providers configuration missing or invalid");
    }

    let registry = Data::new(OAuthProviderRegistry::from_vec(providers));

    HttpServer::new(move || {
        App::new().service(login).service(flow::oauth_scope(
            registry.clone(),
            OAuthRoutes::new(SimpleLoginSuccessHandler),
        ))
    })
    .workers(1)
    .bind(("127.0.0.1", 5656))?
    .run()
    .await
}
