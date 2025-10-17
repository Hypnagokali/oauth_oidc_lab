use actix_web::{cookie::{time::{Duration, OffsetDateTime}, Cookie, SameSite}, get, web::{Data, Query}, App, HttpRequest, HttpResponse, HttpResponseBuilder, HttpServer, Responder};
use base64::{prelude::{BASE64_URL_SAFE_NO_PAD}, Engine};
use maud::{html, Markup};
use rand::{rand_core::OsError, TryRngCore};
use serde::Deserialize;

use crate::oauth::{provider::{OAuthConfig, OAuthProvider, OAuthResponse}, userinfo::UserInfoAttributes};

pub mod oauth;

const PKCE_COOKIE_NAME: &str = "pkce";
const NONCE_COOKIE_NAME: &str = "nonce";
const STATE_COOKIE_NAME: &str = "state";

#[derive(Deserialize)]
pub struct KcTestUserInfo {
    name: String,
}

impl UserInfoAttributes for KcTestUserInfo {
    fn name(&self) -> String {
        self.name.clone()
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

#[get("/login/oauth2/code")]
async fn sso_github(req: HttpRequest, response_query: Query<OAuthResponse>, provider: Data<OAuthProvider>) -> impl Responder {
    let state_from_provider = response_query.state();

    let mut pkce_cookie = if let Some (pkce_cookie) = req.cookie(PKCE_COOKIE_NAME) {
        pkce_cookie
    } else {
        return unauthorized_error_and_invalidate_cookies("Missing PKCE cookie");
    };

    // TODO:
    // Redirect back to /login
    // max tries: about 3x and then return 401:
    let mut state_cookie = if let Some(mut state_cookie) = req.cookie(STATE_COOKIE_NAME) {
        // ToDo: time constant comparison
        if state_cookie.value() != state_from_provider {
            return unauthorized_error_and_invalidate_cookies("Invalid state parameter");
        }
        state_cookie
    } else {
        return unauthorized_error_and_invalidate_cookies("Missing state cookie");
    };

    let mut nonce_cookie = if let Some(mut nonce_cookie) = req.cookie(NONCE_COOKIE_NAME) {
        nonce_cookie
    } else {
        return unauthorized_error_and_invalidate_cookies("Missing nonce cookie");
    };

    println!("SSO GitHub endpoint: code: {}, state: {}", response_query.code(), response_query.state());

    let user_info: KcTestUserInfo = match provider.code_to_token_request(response_query.code(), pkce_cookie.value(), nonce_cookie.value()).await {
        Ok(inf) => inf,
        Err(e) => {
            println!("Error during token request: {}", e);
            return unauthorized_error_and_invalidate_cookies("Error during token request");
        }
    };

    println!("After invalidation: pkce: {:?}, state: {:?}", pkce_cookie, state_cookie);

    HttpResponse::Ok()
        .cookie(pkce_cookie) // remove cookie
        .cookie(state_cookie) // remove cookie
        .body(format!("You are logged in. Hi {}", user_info.name()))
}

#[get("/login/oauth2/auth")]
async fn login_github(provider: Data<OAuthProvider>) -> impl Responder {
    println!("GET /login/oauth2/auth");
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
                    a href="/login/oauth2/auth" { "Login with Keycloak" }
                }
            }
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {    
    dotenv::dotenv().ok();
    let provider = Data::new(OAuthProvider::new(OAuthConfig::from_env().await.expect("OAuth 2.0 variables missing or invalid")));

    HttpServer::new(move || {
            App::new()
                .service(login)
                .service(login_github)
                .service(sso_github)
                .app_data(provider.clone())
            
        })
        .workers(1)
        .bind(("127.0.0.1", 5656))?
        .run()
        .await
}