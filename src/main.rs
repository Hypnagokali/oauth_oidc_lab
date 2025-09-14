use std::{collections::HashMap, env};

use actix_web::{cookie::{time::{Duration, OffsetDateTime}, Cookie, SameSite}, get, web::{Data, Query}, App, HttpRequest, HttpResponse, HttpServer, Responder};
use base64::{prelude::{BASE64_URL_SAFE_NO_PAD}, Engine};
use maud::{html, Markup};
use rand::{rand_core::OsError, TryRngCore};
use reqwest::{redirect::Policy, ClientBuilder};
use serde::Serialize;
use sha2::Digest;

const PKCE_COOKIE_NAME: &str = "pkce";
const STATE_COOKIE_NAME: &str = "state";

struct OAuthConfig {
    client_id: String,
    client_secret: String,
    oauth_user_name: String,
    redirect_uri: String,
    auth_uri: String,
    token_uri: String,
    user_info_endpoint: String,
}

#[derive(Serialize)]
struct TokenRequest {
    client_id: String,
    client_secret: String,
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

#[derive(serde::Deserialize)]
struct OAuthResponse {
    code: String,
    state: String,
}

impl OAuthConfig {
    fn new(client_id: String, client_secret: String, oauth_user_name: String, redirect_uri: String, auth_uri: String, token_uri: String, user_info_endpoint: String) -> Self {
        OAuthConfig {
            client_id,
            client_secret,
            oauth_user_name,
            redirect_uri,
            auth_uri,
            token_uri,
            user_info_endpoint,
        }
    }

    fn token_request(&self) -> TokenRequest {
        TokenRequest {
            client_id: self.client_id.clone(),
            client_secret: self.client_secret.clone(),
            code: "".to_string(),
            redirect_uri: self.redirect_uri.clone(),
            code_verifier: "".to_string(),
        }
    }
}

fn invalidate_cookie(cookie: &mut Cookie<'_>) {
    cookie.set_expires(OffsetDateTime::now_utc() - Duration::days(1));
}

fn create_cookie(name: &str, value: &str) -> Cookie<'static> {
    let mut cookie = Cookie::new(name.to_owned(), value.to_owned());
    cookie.set_max_age(Duration::minutes(15));
    cookie.set_http_only(true);
    cookie.set_path("/");
    cookie.set_same_site(SameSite::Lax);
    cookie
}

fn generate_random_code() -> Result<String, OsError> {
    let mut random_bytes = [0u8; 64];
    rand::rngs::OsRng.try_fill_bytes(&mut random_bytes)?;
    let random_code = BASE64_URL_SAFE_NO_PAD.encode(random_bytes);

    Ok(random_code)
}

#[get("/sso-github")]
async fn sso_github(req: HttpRequest, response_query: Query<OAuthResponse>, oauth_config: Data<OAuthConfig>) -> impl Responder {
    let state_from_provider = &response_query.state;

    let mut pkce_cookie = if let Some (pkce_cookie) = req.cookie(PKCE_COOKIE_NAME) {
        pkce_cookie
    } else {
        return HttpResponse::Unauthorized().body("Missing PKCE cookie");
    };

    // TODO:
    // Redirect back to /login/github
    // max tries: about 3x and then return 401:
    let mut state_cookie = if let Some(state_cookie) = req.cookie(STATE_COOKIE_NAME) {
        if state_cookie.value() != state_from_provider {
            return HttpResponse::Unauthorized().body("Invalid state parameter");
        }

        state_cookie
    } else {
        return HttpResponse::Unauthorized().body("Missing state cookie");
    };

    println!("SSO GitHub endpoint: code: {}, state: {}", response_query.code, response_query.state);

    let mut token_request = oauth_config.token_request();
    token_request.set_code(&response_query.code);
    token_request.set_code_verifier(pkce_cookie.value());

    let body = match token_request.to_urlencoded() {
        Ok(body) => body,
        Err(e) => {
            println!("Error serializing token request: {}", e);
            return HttpResponse::InternalServerError().body("Error serializing token request");
        }
    };

    let client = match ClientBuilder::new()
        .redirect(Policy::none())
        .build() {
            Ok(client) => client,
            Err(e) => {
                println!("Error building HTTP client: {}", e);
                return HttpResponse::InternalServerError().body("Error building HTTP client");
            }
    };


    let token_response_result = client.post(&oauth_config.token_uri)
        .body(body)
        .send()
        .await;

    let token_response = match token_response_result {
        Err(e) => {
            println!("Error during token request: {}", e);
            return HttpResponse::InternalServerError().body("Error during token request");
        },
        Ok(response) => response,
    };
    

    println!("Token response status: {}", token_response.status());

    let token = match token_response.text().await {
        Ok(body) => body,
        Err(e) => {
            println!("Error parsing token response body: {}", e);
            return HttpResponse::InternalServerError().body("Error parsing token response body");
        }
    };

    let user_response_result = client.get(&oauth_config.user_info_endpoint)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await;

    let user_response = match user_response_result {
        Err(e) => {
            println!("Error during user info request: {}", e);
            return HttpResponse::InternalServerError().body("Error during user info request");
        },
        Ok(response) => response,
    };

    println!("Response status from user info request: {}", user_response.status());

    if user_response.status().as_u16() >= 400 {
        return HttpResponse::InternalServerError().body("Couldn't fetch user info data.");
    }

    let raw_user_info: HashMap<String, serde_json::Value> = match user_response.json().await {
        Ok(json) => json,
        Err(e) => {
            println!("Error parsing user info response: {}", e);
            return HttpResponse::InternalServerError().body("Error parsing user info response");
        }
    };

    println!("raw_user_info:\n{:?}", raw_user_info);
    
    let user_info: HashMap<String, String> = raw_user_info.into_iter()
    .map(|(k, v)| (k, v.to_string()))
    .collect();

    println!("user_info:\n{:?}", user_info);

    invalidate_cookie(&mut pkce_cookie);    
    invalidate_cookie(&mut state_cookie);    
    HttpResponse::Ok()
        .cookie(pkce_cookie)
        .cookie(state_cookie)
        .body(format!("Your token is: {}", token))
}

#[get("/login/github")]
async fn login_github(oauth_config: Data<OAuthConfig>) -> impl Responder {
    println!("GET /login/github");
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

    let mut hasher = sha2::Sha256::new();
    hasher.update(pkce.as_bytes());
    let hash_bytes = hasher.finalize();
    let pkce_hash_b64 = BASE64_URL_SAFE_NO_PAD.encode(hash_bytes);

    let pkce_cookie = create_cookie(PKCE_COOKIE_NAME, &pkce);

    let redirect_uri = urlencoding::encode(&oauth_config.redirect_uri);
    
    let auth_redirect = format!(
        "{}?client_id={}&redirect_uri={}&scope=user:email&state={}&code_challenge_method=S256&code_challenge={}",
        oauth_config.auth_uri,
        oauth_config.client_id,
        redirect_uri,
        state,
        pkce_hash_b64
    );

    let c = create_cookie("Knubbel", "Hase");

    HttpResponse::TemporaryRedirect()
        .append_header(("Location", auth_redirect))
        .append_header(("Cache-Control", "no-store"))
        .cookie(state_cookie)
        .cookie(pkce_cookie)
        .cookie(c)
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
    let userinfo_endpoint = env::var("userinfo_endpoint").expect("userinfo_endpoint must be set");
    let config: Data<OAuthConfig>= Data::new(OAuthConfig::new(client_id, client_secret, oauth_user_name, redirect_uri, auth_uri, token_uri, userinfo_endpoint));

    HttpServer::new(move || {
            App::new()
                .service(login)
                .service(login_github)
                .service(sso_github)
                .app_data(config.clone())
            
        })
        .workers(1)
        .bind(("127.0.0.1", 5656))?
        .run()
        .await
}
