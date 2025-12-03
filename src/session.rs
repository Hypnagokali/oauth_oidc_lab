use actix_web::{HttpRequest, HttpResponseBuilder};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("Session creation error: {msg}")]
pub struct SessionCreationError {
    msg: String,
}

pub trait LoginSuccessHandler<U> {
    fn on_login_success(
        &self,
        req: HttpRequest,
        res: HttpResponseBuilder,
        user: &U,
    ) -> impl Future<Output = Result<HttpResponseBuilder, SessionCreationError>>;
}
