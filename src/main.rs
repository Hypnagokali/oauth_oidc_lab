use actix_web::{get, App, HttpServer};
use maud::{html, Markup};

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
    HttpServer::new(|| {
            App::new()
                .service(login)
        })
        .bind(("127.0.0.1", 5656))?
        .run()
        .await
}
