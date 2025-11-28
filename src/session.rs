use actix_web::{HttpRequest, HttpResponseBuilder};
use thiserror::Error;

use crate::User;

#[derive(Debug, Error)]
#[error("Session creation error: {msg}")]
pub struct SessionCreationError {
    msg: String,
}

pub trait LoginSuccessHandler {
    // type U: DeserializeOwned + 'static;
    fn on_login_success(
        &self,
        req: HttpRequest,
        res: HttpResponseBuilder,
        user: &User,
    ) -> impl Future<Output = Result<HttpResponseBuilder, SessionCreationError>>;
}

