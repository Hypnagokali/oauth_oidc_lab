use std::env;

use actix_web::{get, web::{Data, Query, Redirect}, App, HttpResponse, HttpServer, Responder};
use maud::{html, Markup};

struct OAuthConfig {
    client_id: String,
    client_secret: String,
    oauth_user_name: String,
    redirect_uri: String,
}

#[derive(serde::Deserialize)]
struct OAuthResponse {
    code: String,
    state: String,
}

impl OAuthConfig {
    fn new(client_id: String, client_secret: String, oauth_user_name: String, redirect_uri: String) -> Self {
        OAuthConfig {
            client_id,
            client_secret,
            oauth_user_name,
            redirect_uri,
        }
    }
}

#[get("/sso-github")]
async fn sso_github(response_query: Query<OAuthResponse>) -> impl Responder {
    println!("SSO GitHub endpoint hit: code: {}, state: {}", response_query.code, response_query.state);
    HttpResponse::Ok().body("SSO GitHub endpoint hit")
}

#[get("/login/github")]
async fn login_github(oauth_config: Data<OAuthConfig>) -> impl Responder {
    let redirect_uri = urlencoding::encode(&oauth_config.redirect_uri);
    let s = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=user:email",
        oauth_config.client_id,
        redirect_uri
    );
    Redirect::to(s).temporary()
}

#[get("/")]
async fn login() -> Markup {
    html! {
        html {
            body {
                h1 { "Login page" }
                p { "This is a dummy site, nothing works at the moment" }
                div {
                    a href="#" { "Login with GitHub" }
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
    let oauth_user_name = env::var("oauth-user-name").expect("oauth-user-name must be set");
    let redirect_uri = env::var("redirect-uri").expect("redirect-uri must be set");
    let config: Data<OAuthConfig>= Data::new(OAuthConfig::new(client_id, client_secret, oauth_user_name, redirect_uri));

    HttpServer::new(move || {
            App::new()
                .service(login)
                .app_data(config.clone())
            
        })
        .bind(("127.0.0.1", 5656))?
        .run()
        .await
}
