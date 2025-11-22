use jsonwebtoken::{DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde_json::Value;
use thiserror::Error;

use crate::oauth::{
    keyset::{GetKeyError, KeyFetcher},
    provider::OAuthConfig,
    util::is_equal_constant_time,
};

pub struct UserIdentity<C> {
    id_token: String,
    claims: C,
}

#[derive(Debug, Error)]
#[error("Token validation error: {0}")]
pub struct TokenValidationError(pub(crate) String);

impl From<jsonwebtoken::errors::Error> for TokenValidationError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        TokenValidationError(err.to_string())
    }
}

impl From<GetKeyError> for TokenValidationError {
    fn from(err: crate::oauth::keyset::GetKeyError) -> Self {
        TokenValidationError(err.to_string())
    }
}

impl From<serde_json::Error> for TokenValidationError {
    fn from(err: serde_json::Error) -> Self {
        TokenValidationError(err.to_string())
    }
}

pub trait TokenValidation {
    fn validation(
        &self,
        id_token: &str,
        config: &OAuthConfig,
    ) -> impl Future<Output = Result<(DecodingKey, Validation), TokenValidationError>>;
}

pub struct DefaultTokenValidation;

impl TokenValidation for DefaultTokenValidation {
    #[allow(clippy::manual_async_fn)]
    fn validation(
        &self,
        id_token: &str,
        config: &OAuthConfig,
    ) -> impl Future<Output = Result<(DecodingKey, Validation), TokenValidationError>> {
        async move {
            let metadata = config.metadata()
            .ok_or_else(|| TokenValidationError("OIDC metadata not available. Can't create UserIdentity if its not an OIDC provider".to_owned()))?;

            let key_fetcher = KeyFetcher::new(metadata.jwks_uri());

            let header = jsonwebtoken::decode_header(id_token)?;
            let kid = header
                .kid
                .ok_or_else(|| TokenValidationError("Missing kid in JWT header".to_owned()))?;
            let key = key_fetcher.fetch_key(&kid).await?.to_decoding_key()?;

            let mut validation = Validation::default();
            validation.set_audience(&[config.client_id()]);

            Ok((key.0, validation))
        }
    }
}

impl<C: DeserializeOwned> UserIdentity<C> {
    pub fn id_token(&self) -> &str {
        &self.id_token
    }

    pub fn claims(&self) -> &C {
        &self.claims
    }

    pub async fn from_token<V: TokenValidation>(
        id_token: &str,
        validation: V,
        config: &OAuthConfig,
        nonce: &str,
    ) -> Result<Self, TokenValidationError> {
        let key_and_validation = validation.validation(id_token, config).await?;
        let raw: Value =
            jsonwebtoken::decode::<Value>(id_token, &key_and_validation.0, &key_and_validation.1)?
                .claims;

        let token_nonce = raw
            .get("nonce")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TokenValidationError("Nonce claim missing in ID token".to_string()))?;

        if !is_equal_constant_time(token_nonce, nonce) {
            return Err(TokenValidationError(
                "Nonce mismatch in ID token".to_string(),
            ));
        }

        let claims = serde_json::from_value::<C>(raw)?;

        Ok(UserIdentity {
            id_token: id_token.into(),
            claims,
        })
    }
}

#[cfg(test)]
mod tests {

    use jsonwebtoken::{DecodingKey, Validation};

    use crate::oauth::{
        identity::{TokenValidation, TokenValidationError},
        provider::{OAuthConfig, PkceMethod},
    };

    use super::UserIdentity;

    struct TestValidation;
    impl TokenValidation for TestValidation {
        fn validation(
            &self,
            _id_token: &str,
            _config: &OAuthConfig,
        ) -> impl Future<Output = Result<(DecodingKey, Validation), TokenValidationError>> {
            async move {
                let key = DecodingKey::from_secret("".as_ref());
                let mut validation = Validation::default();
                validation.insecure_disable_signature_validation();
                validation.validate_exp = false;
                validation.validate_aud = false;
                Ok((key, validation))
            }
        }
    }

    #[derive(serde::Deserialize, Debug)]
    struct MyClaims {
        sub: String,
        name: String,
    }

    #[actix_rt::test]
    async fn test_parse_id_token() {
        let config = OAuthConfig::new(
            "oidc_test".into(),
            "".into(),
            "".into(),
            "".into(),
            "".into(),
            "".into(),
            Vec::new(),
            None,
            PkceMethod::None
        );

        let id_token = concat!(
            "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJTcThVTFhoN1dpemprRjFWMnUtSnRvdkVSSDBDZlZJdVlFUEswLWZ2UGtNIn0.",
            "eyJleHAiOjE3NjAxNzk2NTAsImlhdCI6MTc2MDE3OTM1MCwiYXV0aF90aW1lIjoxNzYwMTc5MzEwLCJqdGkiOiIxZTZhNjNiNy0wMmIzLTczMTctMGIzMC0zMT",
            "ZlZmE1YjJlZDIiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojg3ODYvcmVhbG1zL3Rlc3QiLCJhdWQiOiJvaWRjX3Rlc3QiLCJzdWIiOiJhNWI2NDB",
            "mYy00MmY2LTQ2MTctYjcxYi0zMjZlZGZlZDE4ZTkiLCJ0eXAiOiJJRCIsImF6cCI6Im9pZGNfdGVzdCIsIm5vbmNlIjoibVRRVno4YzNHZlRXaUZtYTJwRXFMWlVHV3hxVlB3",
            "eVpteEtIWnFhMzM3d1dqZF9zZWhyOEZhTFhWaFhCaHF3VDVGWGtKMF80RHFQcUE2azVweDBMeWciLCJzaWQiOiJlOGFkNmRiZC0xMDcyLTRkYTgtOWZkNi1iM2I2ZTcyZTY",
            "4YWIiLCJhdF9oYXNoIjoiRV9WNjZXaFRVVW5ZVy1WY3FaMm5qZyIsImFjciI6IjAiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkhhbnMgSGFzZSIsInByZWZlcn",
            "JlZF91c2VybmFtZSI6ImhhbnMuaGFzZUBleGFtcGxlLm9yZyIsImdpdmVuX25hbWUiOiJIYW5zIiwiZmFtaWx5X25hbWUiOiJIYXNlIiwiZW1haWwiOiJoYW5zLmhhc2VAZXhhbXBsZS5vcmcifQ.",
            "fGOSvo8gEjmmdhZF8g3ABB3YJlkDot3et3PE9HAHlKwdNHYKQ07R8egi6r7JsPInaMkV-NfztY2mh15jzILVRMdAbflYhH12fzo9BuvqsGQNG-",
            "LV_ootJHTXhI72WXTl7I5pelYj4Pp-UnZr2wNKhNkEND3p1CjPlaAgX-EL9Mxrw4k0OybJneYDejSOx4IEIM7w92y8Tyw18tBQHWzSmrrr1Fu6Eb3M_",
            "WkdsXNIiiVwYjHxMA50YrLX8VcUJODuPIp4QorfWLxXswksOHW2UMpEklx7qNr-ps42MgQ40zTJZR_fOYHn5hPlauwKfqgkGmuHdkFQeftWlXfSgs10Yg"
        );

        let user_identity = UserIdentity::<MyClaims>::from_token(
            id_token,
            TestValidation,
            &config,
            "mTQVz8c3GfTWiFma2pEqLZUGWxqVPwyZmxKHZqa337wWjd_sehr8FaLXVhXBhqwT5FXkJ0_4DqPqA6k5px0Lyg"
        ).await.unwrap();
        assert_eq!(
            user_identity.claims.sub,
            "a5b640fc-42f6-4617-b71b-326edfed18e9"
        );
        assert_eq!(user_identity.claims.name, "Hans Hase");
    }
}
