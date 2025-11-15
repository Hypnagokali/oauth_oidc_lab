use reqwest::{
    ClientBuilder,
    header::{HeaderMap, HeaderValue},
    redirect::Policy,
};

#[derive(Debug, thiserror::Error)]
#[error("HTTP client creation error: {0}")]
pub struct CreateHttpClientError(String);

pub(crate) fn create_http_client() -> Result<reqwest::Client, CreateHttpClientError> {
    // TODO: make user agent configurable or change it to something more generic
    let mut headers = HeaderMap::new();
    headers.insert("Accept", HeaderValue::from_static("application/json"));
    headers.insert("User-Agent", HeaderValue::from_static("OAuth2TestApp"));

    let client = match ClientBuilder::new()
        .redirect(Policy::none())
        .default_headers(headers)
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            println!("Error building HTTP client: {}", e);
            return Err(CreateHttpClientError(format!(
                "Error building HTTP client: {}",
                e
            )));
        }
    };
    Ok(client)
}
