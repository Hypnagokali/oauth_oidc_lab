use std::pin::Pin;
use std::sync::Arc;

use actix_web::{App, HttpRequest, HttpResponse, HttpResponseBuilder, HttpServer, Responder, cookie::{Cookie, SameSite, time::{Duration, OffsetDateTime}}, get, web::{self, Data, Query}};
use base64::{prelude::{BASE64_URL_SAFE_NO_PAD}, Engine};
use maud::{html, Markup};
use rand::{rand_core::OsError, TryRngCore};
use serde::Deserialize;

use crate::oauth::{
    provider::{AuthCodeResponse, TokenProvider, TokenRequestError, OAuthConfig, OAuthProvider}, registry::OAuthProviderRegistry, userinfo::UserInfoAttributes, util::is_equal_constant_time
};

pub mod oauth;

const PKCE_COOKIE_NAME: &str = "pkce";
const NONCE_COOKIE_NAME: &str = "nonce";
const STATE_COOKIE_NAME: &str = "state";

#[derive(Deserialize)]
pub struct KcTestUserInfo {
    name: String,
    email: String,
}

impl UserInfoAttributes for KcTestUserInfo {
    fn username(&self) -> String {
        self.name.clone()
    }
}

pub struct User {
    name: String,
    email: String,
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
    fn to_user(&self, token_provider: TokenProvider) -> Pin<Box<dyn Future<Output = Result<User, UserMappingError>> + Send>>;
}

pub struct GitHubUserMapper;

impl UserMapper for GitHubUserMapper {
    fn to_user(&self, token_provider: TokenProvider) -> Pin<Box<dyn Future<Output = Result<User, UserMappingError>> + Send>> {
        Box::pin(async move {
            let info: Result<GitHubUserInfo, _> = token_provider.user_info().await;
            info.map(|i| User {
                name: i.login,
                email: i.email,
            }).map_err(|e| e.into())
        })
    }
}

pub struct KeycloakUserMapper;

impl UserMapper for KeycloakUserMapper {
    fn to_user(&self, token_provider: TokenProvider) -> Pin<Box<dyn Future<Output = Result<User, UserMappingError>> + Send>> {
        Box::pin(async move {
            let info: Result<KcTestUserInfo, _> = token_provider.user_info().await;
            info.map(|i: KcTestUserInfo| User {
                name: i.name,
                email: i.email,
            }).map_err(|e| e.into())
        })
    }
}

#[derive(Deserialize)]
pub struct GitHubUserInfo {
    login: String,
    email: String,
}

// TODO: Is this still needed when there is a UserMapper?
impl UserInfoAttributes for GitHubUserInfo {
    fn username(&self) -> String {
        self.login.clone()
    }
}

fn base_cookie_attributes(cookie: &mut Cookie<'_>) {
    cookie.set_http_only(true);
    cookie.set_path("/");
    cookie.set_same_site(SameSite::Lax);
}

fn invalidate_cookie(cookie: &mut Cookie<'_>) {
    cookie.set_expires(OffsetDateTime::now_utc() - Duration::days(1));
    base_cookie_attributes(cookie);
}

fn invalidated_cookies(res: &mut HttpResponseBuilder) {
    let cookies = [PKCE_COOKIE_NAME, STATE_COOKIE_NAME, NONCE_COOKIE_NAME];
    for cookie in cookies.iter() {
        let mut c = Cookie::new(cookie.to_string(), "".to_string());
        invalidate_cookie(&mut c);
        res.cookie(c);
    }
}

fn unauthorized_error_and_invalidate_cookies(msg: &str) -> HttpResponse {
    let mut response = HttpResponse::Unauthorized();
    invalidated_cookies(&mut response);
    response.body(msg.to_string())
}

fn create_cookie(name: &str, value: &str) -> Cookie<'static> {
    let mut cookie = Cookie::new(name.to_owned(), value.to_owned());
    cookie.set_max_age(Duration::minutes(15));
    base_cookie_attributes(&mut cookie);
    cookie
}

fn generate_random_code() -> Result<String, OsError> {
    let mut random_bytes = [0u8; 64];
    rand::rngs::OsRng.try_fill_bytes(&mut random_bytes)?;
    let random_code = BASE64_URL_SAFE_NO_PAD.encode(random_bytes);

    Ok(random_code)
}

#[get("/login/oauth2/code/{provider}")]
async fn sso_callback(
    req: HttpRequest,
    path: web::Path<String>,
    response_query: Query<AuthCodeResponse>,
    registry: Data<OAuthProviderRegistry>
) -> impl Responder {
    let provider_name = path.into_inner();
    let provider = match registry.get_provider(&provider_name) {
        Some(p) => p,
        None => return unauthorized_error_and_invalidate_cookies("Invalid provider"),
    };

    let state_from_provider = response_query.state();

    let mut pkce_cookie = if let Some(pkce_cookie) = req.cookie(PKCE_COOKIE_NAME) {
        pkce_cookie
    } else {
        return unauthorized_error_and_invalidate_cookies("Missing PKCE cookie");
    };

    // TODO:
    // Redirect back to /login
    // max tries: about 3x and then return 401:
    let mut state_cookie = if let Some(state_cookie) = req.cookie(STATE_COOKIE_NAME) {
        if is_equal_constant_time(state_cookie.value(), state_from_provider) == false {
            return unauthorized_error_and_invalidate_cookies("Invalid state parameter");
        }
        state_cookie
    } else {
        return unauthorized_error_and_invalidate_cookies("Missing state cookie");
    };

    // TODO: refactor two wrapped ifs
    let nonce_cookie = if provider.is_openid() {
        let nonce_cookie = if let Some(nonce_cookie) = req.cookie(NONCE_COOKIE_NAME) {
            nonce_cookie
        } else {
            return unauthorized_error_and_invalidate_cookies("Missing nonce cookie");
        };
        Some(nonce_cookie)
    } else {
        None
    };

    let token_provider = match provider.code_to_token_request(
        response_query.code(),
        pkce_cookie.value(),
        nonce_cookie.as_ref().map(|c| c.value().to_owned()),
        ).await {
        Ok(prov) => prov,
        Err(e) => {
            println!("Error during token request: {}", e);
            return unauthorized_error_and_invalidate_cookies("Error during token request");
        }
    };

    let user = match provider.mapper().to_user(token_provider).await {
        Ok(user) => user,
        Err(e) => {
            println!("Error fetching user info: {}", e);
            return unauthorized_error_and_invalidate_cookies("Error fetching user info");
        }
    };

    let mut res = HttpResponse::Ok();

    invalidate_cookie(&mut pkce_cookie);
    invalidate_cookie(&mut state_cookie);
    res
        .cookie(pkce_cookie)
        .cookie(state_cookie);

    if let Some(mut nonce_cookie) = nonce_cookie {
        invalidate_cookie(&mut nonce_cookie);
        res.cookie(nonce_cookie);
    }

    // TODO: set session cookie and do redirect
    res
        // TODO: add cache control headers
        .body(format!("You are logged in. Hi {} ({})", user.name, user.email))
}

#[get("/login/oauth2/auth/{provider}")]
async fn login_provider(
    path: web::Path<String>,
    registry: Data<OAuthProviderRegistry>
) -> impl Responder {
    println!("GET /login/oauth2/auth/{}", path.as_str());
    let provider_name = path.into_inner();
    
    let provider = match registry.get_provider(&provider_name) {
        Some(p) => p,
        None => return HttpResponse::NotFound().body("Provider not found"),
    };

    let state = match generate_random_code() {
        Ok(code) => code,
        Err(e) => {
            println!("Error generating state parameter: {}", e);
            return HttpResponse::InternalServerError().body("Error generating state parameter");
        }
    };
    let state_cookie = create_cookie(STATE_COOKIE_NAME, &state);

    // build PKCE challenge
    let pkce = match generate_random_code() {
        Ok(code) => code,
        Err(e) => {
            println!("Error generating PKCE code verifier: {}", e);
            return HttpResponse::InternalServerError().body("Error generating PKCE code verifier");
        }
    };
    let pkce_cookie = create_cookie(PKCE_COOKIE_NAME, &pkce);

    if provider.is_openid() {
        let nonce = match generate_random_code() {
            Ok(code) => code,
            Err(e) => {
                println!("Error generating nonce: {}", e);
                return HttpResponse::InternalServerError().body("Error generating nonce");
            }
        };
        let nonce_cookie = create_cookie(NONCE_COOKIE_NAME, &nonce);

        let auth_redirect = provider.build_authentication_url_with_nonce(&state, &pkce, &nonce);

        HttpResponse::TemporaryRedirect()
            .append_header(("Location", auth_redirect))
            .append_header(("Cache-Control", "no-store"))
            .cookie(state_cookie)
            .cookie(pkce_cookie)
            .cookie(nonce_cookie)
            .finish()

    } else {
        let auth_redirect = provider.build_authentication_url(&state, &pkce);

        HttpResponse::TemporaryRedirect()
            .append_header(("Location", auth_redirect))
            .append_header(("Cache-Control", "no-store"))
            .cookie(state_cookie)
            .cookie(pkce_cookie)
            .finish()
    }
}

#[get("/")]
async fn login() -> Markup {
    html! {
        html {
            body {
                h1 { "Login page" }
                p { "This is a dummy site, nothing works at the moment" }
                div {
                    a href="/login/oauth2/auth/github" { "Login with GitHub" }
                }
                div {
                    a href="/login/oauth2/auth/keycloak" { "Login with Keycloak" }
                }
            }
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();

    let mut providers: Vec<OAuthProvider> = Vec::new();

    // GitHub provider
    if let Ok(github_conf) = OAuthConfig::from_env_with_prefix("GITHUB_").await {
        let github_provider = OAuthProvider::new("github", github_conf, Arc::new(GitHubUserMapper));
        providers.push(github_provider);
    }

    // Keycloak provider
    if let Ok(keycloak_conf) = OAuthConfig::from_env_with_prefix("KEYCLOAK_").await {
        let keycloak_provider = OAuthProvider::new("keycloak", keycloak_conf, Arc::new(KeycloakUserMapper));
        providers.push(keycloak_provider);
    }

    if providers.is_empty() {
        panic!("OAuth 2.0 providers configuration missing or invalid");
    }

    let registry = Data::new(OAuthProviderRegistry::from_vec(providers));

    HttpServer::new(move || {
            App::new()
                .service(login)
                .service(login_provider)
                .service(sso_callback)
                .app_data(registry.clone())
            
        })
        .workers(1)
        .bind(("127.0.0.1", 5656))?
        .run()
        .await
}