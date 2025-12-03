use std::vec;

use crate::oauth::util::is_equal_constant_time;
use crate::session::LoginSuccessHandler;
use actix_web::Resource;
use actix_web::dev::{AppService, HttpServiceFactory};
use actix_web::guard::Get;
use actix_web::http::header::{CacheControl, CacheDirective};
use actix_web::web::Data;
use actix_web::{
    HttpRequest, HttpResponse, HttpResponseBuilder, Responder,
    cookie::{
        Cookie, SameSite,
        time::{Duration, OffsetDateTime},
    },
    web,
};
use serde::de::DeserializeOwned;

use crate::oauth::provider::AuthCodeResponse;
use crate::oauth::registry::OAuthProviderRegistry;

const PKCE_COOKIE_NAME: &str = "pkce";
const NONCE_COOKIE_NAME: &str = "nonce";
const STATE_COOKIE_NAME: &str = "state";

struct DefaultRedirect {
    url: String,
}

impl DefaultRedirect {
    fn new(url: String) -> Self {
        DefaultRedirect { url }
    }
}

pub struct OAuthRoutes<U, S: LoginSuccessHandler<U>> {
    login_success_handler: S,
    default_redirect_after_login: Option<DefaultRedirect>,
    _phantom: std::marker::PhantomData<U>,
}

impl<U: DeserializeOwned, S: LoginSuccessHandler<U>> OAuthRoutes<U, S> {
    pub fn new(login_success_handler: S) -> Self {
        OAuthRoutes {
            login_success_handler,
            default_redirect_after_login: None,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn with_default_redirect_after_login(mut self, redirect_url: String) -> Self {
        self.default_redirect_after_login = Some(DefaultRedirect::new(redirect_url));
        self
    }
}

impl<U: 'static, S: LoginSuccessHandler<U> + 'static> HttpServiceFactory for OAuthRoutes<U, S> {
    fn register(self, config: &mut AppService) {
        Resource::new("/login/oauth2/code/{provider}")
            .name("actix_auth_endpoint")
            .guard(Get())
            .to(sso_callback::<U, S>)
            .app_data(Data::new(self.login_success_handler))
            .app_data(Data::new(self.default_redirect_after_login))
            .register(config);

        Resource::new("/login/oauth2/auth/{provider}")
            .name("actix_auth_endpoint")
            .guard(Get())
            .to(login_provider::<U>)
            .register(config);
    }
}

/// This is the callback handler that exchanges the code for a token and then uses the provider's
/// configured `UserMapper` to map the TokenProvider into a `User`.
async fn sso_callback<U, S: LoginSuccessHandler<U>>(
    req: HttpRequest,
    path: web::Path<String>,
    login_success_handler: Data<S>,
    response_query: web::Query<AuthCodeResponse>,
    registry: Data<OAuthProviderRegistry<U>>,
    default_redirect_after_login: Data<Option<DefaultRedirect>>,
) -> impl Responder {
    let provider_name = path.into_inner();
    let provider = match registry.get_provider(&provider_name) {
        Some(p) => p,
        None => return unauthorized_error_and_invalidate_cookies("Invalid provider"),
    };

    let pkce_cookie = req.cookie(PKCE_COOKIE_NAME);

    if pkce_cookie.is_none() && provider.pkce_method().is_required() {
        return unauthorized_error_and_invalidate_cookies("Missing PKCE cookie");
    }

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
            pkce_cookie.map(|v| v.to_string()),
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

    let user: U = match provider.mapper().to_user(token_provider).await {
        Ok(user) => user,
        Err(e) => {
            println!("Error fetching user info: {}", e);
            return unauthorized_error_and_invalidate_cookies("Error fetching user info");
        }
    };

    let mut res = HttpResponse::TemporaryRedirect();
    res.insert_header(CacheControl(vec![
        CacheDirective::NoStore,
        CacheDirective::MaxAge(0),
    ]));

    let redirect = match default_redirect_after_login.as_ref() {
        Some(red) => red.url.to_string(),
        None => "/".to_string(),
    };

    res.insert_header(("Location", redirect));

    invalidated_cookies(&mut res);

    match login_success_handler
        .on_login_success(req, res, &user)
        .await
    {
        Ok(mut res) => res.finish(),
        Err(_) => unauthorized_error_and_invalidate_cookies("Session creation error"),
    }
}

/// Authentication initiation endpoint. Redirects the user to the provider's authentication URL.
async fn login_provider<U>(
    path: web::Path<String>,
    registry: Data<OAuthProviderRegistry<U>>,
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

    let mut res_builder = HttpResponse::TemporaryRedirect();

    res_builder
        .append_header(("Location", auth_redirect))
        .append_header(("Cache-Control", "no-store"));

    let state_cookie = create_cookie(STATE_COOKIE_NAME, &state);
    res_builder.cookie(state_cookie);

    if let Some(pkce_val) = pkce {
        let pkce_cookie = create_cookie(PKCE_COOKIE_NAME, &pkce_val);
        res_builder.cookie(pkce_cookie);
    }

    if let Some(nonce_val) = nonce {
        let nonce_cookie = create_cookie(NONCE_COOKIE_NAME, &nonce_val);
        res_builder.cookie(nonce_cookie);
    }

    res_builder.finish()
}

/// Configuration function to create an scope with OAuth endpoints.
pub fn oauth_scope<U: 'static, S: LoginSuccessHandler<U> + 'static>(
    registry: Data<OAuthProviderRegistry<U>>,
    oauth_routes: OAuthRoutes<U, S>,
) -> actix_web::Scope {
    web::scope("").app_data(registry).service(oauth_routes)
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
