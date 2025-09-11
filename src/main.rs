use std::env;

use actix_web::{cookie::{time::Duration, Cookie}, get, web::{Data, Query}, App, HttpRequest, HttpResponse, HttpServer, Responder};
use base64::{prelude::{BASE64_URL_SAFE_NO_PAD}, Engine};
use maud::{html, Markup};
use rand::TryRngCore;
use reqwest::{redirect::Policy, ClientBuilder};
use serde::Serialize;
use sha2::Digest;

struct OAuthConfig {
    client_id: String,
    client_secret: String,
    oauth_user_name: String,
    redirect_uri: String,
    auth_uri: String,
    token_uri: String,
}

#[derive(Serialize)]
struct CodeRequest {
    client_id: String,
    client_secret: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
}

impl CodeRequest {
    pub fn set_code(&mut self, code: &str) {
        self.code = code.to_string();
    }

    pub fn set_code_verifier(&mut self, code_verifier: &str) {
        self.code_verifier = code_verifier.to_string();
    }

    pub fn to_urlencoded(&self) -> String {
        serde_urlencoded::to_string(self).unwrap()
    }
}

#[derive(serde::Deserialize)]
struct OAuthResponse {
    code: String,
    state: String,
}

impl OAuthConfig {
    fn new(client_id: String, client_secret: String, oauth_user_name: String, redirect_uri: String, auth_uri: String, token_uri: String) -> Self {
        OAuthConfig {
            client_id,
            client_secret,
            oauth_user_name,
            redirect_uri,
            auth_uri,
            token_uri,
        }
    }

    fn token_request(&self) -> CodeRequest {
        CodeRequest {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            code: "".to_string(),
            redirect_uri: self.redirect_uri.clone(),
            code_verifier: "".to_string(),
        }
    }
}


fn generate_random_code() -> String {
    let random_bytes = [0u8; 32];
    rand::rngs::OsRng.try_fill_bytes(&mut random_bytes.clone()).unwrap();
    let random_code = BASE64_URL_SAFE_NO_PAD.encode(random_bytes);
    random_code
}

#[get("/sso-github")]
async fn sso_github(req: HttpRequest, response_query: Query<OAuthResponse>, oauth_config: Data<OAuthConfig>) -> impl Responder {
    let state_from_auth = &response_query.state;
    let state_cookie = req.cookie("state");
    let pkce_cookie = req.cookie("pkce");

    if pkce_cookie.is_none() {
        return HttpResponse::Unauthorized().body("Missing PKCE cookie");
    }

    if state_cookie.is_none() || state_cookie.unwrap().value() != state_from_auth {
        // Redirect back to /login/github
        // max tries: about 3x and then return 401:
        return HttpResponse::Unauthorized().body("Invalid state parameter");
    }

    println!("SSO GitHub endpoint hit: code: {}, state: {}", response_query.code, response_query.state);

    let mut code_request = oauth_config.token_request();
    code_request.set_code(&response_query.code);
    code_request.set_code_verifier(pkce_cookie.unwrap().value());

    let res = ClientBuilder::new()
        .redirect(Policy::none())
        .build()
        .unwrap()
        .post(&oauth_config.token_uri)
        .body(code_request.to_urlencoded())
        .send()
        .await.unwrap();

    println!("Token response: {}", res.status());

    let token = res.text().await.unwrap();
    
    HttpResponse::Ok().body(format!("Your token is: {}", token))
}

#[get("/login/github")]
async fn login_github(oauth_config: Data<OAuthConfig>) -> impl Responder {
    println!("GET /login/github");
    let mut state_cookie = Cookie::new("state", generate_random_code());
    state_cookie.set_http_only(true);
    state_cookie.set_max_age(Duration::minutes(15));

    // build PKCE challenge
    let pkce = generate_random_code();
    let mut hasher = sha2::Sha256::new();
    hasher.update(pkce.as_bytes());
    let hash_bytes = hasher.finalize();
    let pkce_hash_b64 = BASE64_URL_SAFE_NO_PAD.encode(hash_bytes);

    let mut pkce_cookie = Cookie::new("pkce", pkce);
    pkce_cookie.set_http_only(true);
    pkce_cookie.set_max_age(Duration::minutes(15));

    let redirect_uri = urlencoding::encode(&oauth_config.redirect_uri);
    
    let auth_redirect = format!(
        "{}?client_id={}&redirect_uri={}&scope=user:email&state=random_state_string&code_challenge_method=S256&code_challenge={}",
        oauth_config.auth_uri,
        oauth_config.client_id,
        redirect_uri,
        pkce_hash_b64
    );

    HttpResponse::TemporaryRedirect()
        .append_header(("Location", auth_redirect))
        .append_header(("Cache-Control", "no-store"))
        .cookie(state_cookie)
        .finish()
}

#[get("/")]
async fn login() -> Markup {
    html! {
        html {
            body {
                h1 { "Login page" }
                p { "This is a dummy site, nothing works at the moment" }
                div {
                    a href="/login/github" { "Login with GitHub" }
                }
                div {
                    a href="#" { "Login with Google" }
                }
            }
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {    
    dotenv::dotenv().ok();
    let client_id = env::var("client_id").expect("client_id must be set");
    let client_secret = env::var("client_secret").expect("client_secret must be set");
    let oauth_user_name = env::var("oauth_user_name").expect("oauth_user_name must be set");
    let redirect_uri = env::var("redirect_uri").expect("redirect_uri must be set");
    let auth_uri = env::var("auth_uri").expect("auth_uri must be set");
    let token_uri = env::var("token_uri").expect("token_uri must be set");
    let config: Data<OAuthConfig>= Data::new(OAuthConfig::new(client_id, client_secret, oauth_user_name, redirect_uri, auth_uri, token_uri));

    HttpServer::new(move || {
            App::new()
                .service(login)
                .service(login_github)
                .service(sso_github)
                .app_data(config.clone())
            
        })
        .bind(("127.0.0.1", 5656))?
        .run()
        .await
}
