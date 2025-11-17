use crate::oauth::util::is_equal_constant_time;
use actix_web::web::Data;
use actix_web::{
    HttpRequest, HttpResponse, HttpResponseBuilder, Responder,
    cookie::{
        Cookie, SameSite,
        time::{Duration, OffsetDateTime},
    },
    get, web,
};

use crate::oauth::provider::AuthCodeResponse;
use crate::oauth::registry::OAuthProviderRegistry;

const PKCE_COOKIE_NAME: &str = "pkce";
const NONCE_COOKIE_NAME: &str = "nonce";
const STATE_COOKIE_NAME: &str = "state";

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

/// This is the callback handler that exchanges the code for a token and then uses the provider's
/// configured `UserMapper` to map the TokenProvider into a `User`.
#[get("/login/oauth2/code/{provider}")]
async fn sso_callback(
    req: HttpRequest,
    path: web::Path<String>,
    response_query: web::Query<AuthCodeResponse>,
    registry: Data<OAuthProviderRegistry>,
) -> impl Responder {
    let provider_name = path.into_inner();
    let provider = match registry.get_provider(&provider_name) {
        Some(p) => p,
        None => return unauthorized_error_and_invalidate_cookies("Invalid provider"),
    };

    let pkce_cookie = if let Some(pkce_cookie) = req.cookie(PKCE_COOKIE_NAME) {
        pkce_cookie
    } else {
        return unauthorized_error_and_invalidate_cookies("Missing PKCE cookie");
    };

    let state_cookie = if let Some(state_cookie) = req.cookie(STATE_COOKIE_NAME) {
        state_cookie
    } else {
        return unauthorized_error_and_invalidate_cookies("Missing state cookie");
    };

    let nonce_cookie = req.cookie(NONCE_COOKIE_NAME);
    if provider.is_openid() && nonce_cookie.is_none() {
        return unauthorized_error_and_invalidate_cookies("Missing nonce cookie");
    }

    if !is_equal_constant_time(state_cookie.value(), response_query.state()) {
        return unauthorized_error_and_invalidate_cookies("Invalid state parameter");
    }

    let token_provider_res = provider
        .code_to_token_request(
            response_query.code(),
            pkce_cookie.value(),
            nonce_cookie.map(|s| s.to_string()),
        )
        .await;

    let token_provider = match token_provider_res {
        Ok(tp) => tp,
        Err(e) => {
            println!("Error during token request: {}", e);
            return unauthorized_error_and_invalidate_cookies("Cannot exchange code for token");
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

    invalidated_cookies(&mut res);

    let email = match &user.email {
        Some(e) => e.as_str(),
        None => "no email provided",
    };
    res.body(format!(
        "You are logged in. Hi {} (id={}, email={})",
        user.name, user.id, email
    ))
}

/// Authentication initiation endpoint. Redirects the user to the provider's authentication URL.
#[get("/login/oauth2/auth/{provider}")]
async fn login_provider(
    path: web::Path<String>,
    registry: Data<OAuthProviderRegistry>,
) -> impl Responder {
    let provider_name = path.into_inner();

    let provider = match registry.get_provider(&provider_name) {
        Some(p) => p,
        None => return HttpResponse::NotFound().body("Provider not found"),
    };

    // Delegate generation of redirect URL and parameters to the provider.
    let (auth_redirect, state, pkce, nonce) = match provider.build_authentication_url() {
        Ok(v) => v,
        Err(e) => {
            println!("Error generating auth parameters: {}", e);
            return HttpResponse::InternalServerError().body("Error generating auth parameters");
        }
    };

    let state_cookie = create_cookie(STATE_COOKIE_NAME, &state);
    let pkce_cookie = create_cookie(PKCE_COOKIE_NAME, &pkce);

    if let Some(nonce_val) = nonce {
        let nonce_cookie = create_cookie(NONCE_COOKIE_NAME, &nonce_val);
        HttpResponse::TemporaryRedirect()
            .append_header(("Location", auth_redirect))
            .append_header(("Cache-Control", "no-store"))
            .cookie(state_cookie)
            .cookie(pkce_cookie)
            .cookie(nonce_cookie)
            .finish()
    } else {
        HttpResponse::TemporaryRedirect()
            .append_header(("Location", auth_redirect))
            .append_header(("Cache-Control", "no-store"))
            .cookie(state_cookie)
            .cookie(pkce_cookie)
            .finish()
    }
}

/// Configuration function to create an scope with OAuth endpoints.
pub fn oauth_scope(registry: Data<OAuthProviderRegistry>) -> actix_web::Scope {
    web::scope("")
        .app_data(registry)
        .service(login_provider)
        .service(sso_callback)
}
