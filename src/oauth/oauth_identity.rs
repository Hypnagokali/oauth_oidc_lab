use std::str::FromStr;

use jsonwebtoken::{DecodingKey, Validation};
use serde::de::DeserializeOwned;
use thiserror::Error;

pub struct UserIdentity<C> {
    id_token: String,
    claims: C,
}

#[derive(Debug, Error)]
#[error("Parsing UserIdentity error: {0}")]
pub struct UserIdentityError(String);

impl From<jsonwebtoken::errors::Error> for UserIdentityError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        UserIdentityError(err.to_string())
    }
}

impl<C: DeserializeOwned> UserIdentity<C> {   
    // TODO: Jwks as parameter (Jwks trait (visitor pattern?))
    fn from_token(id_token: &str) -> Result<Self, UserIdentityError> {
        let mut validation = Validation::default();
        // only for testing
        validation.insecure_disable_signature_validation();
        validation.validate_aud = false;
        validation.validate_exp = false;
        let claims = jsonwebtoken::decode::<C>(id_token, &DecodingKey::from_secret(b""), &validation)?.claims;

        Ok(UserIdentity {
            id_token: id_token.into(),
            claims,
        })
    }
}

#[cfg(test)]
mod tests {

    use super::UserIdentity;

    #[derive(serde::Deserialize, Debug)]
    struct MyClaims {
        sub: String,
        name: String,
    }

    #[test]
    fn test_parse_id_token() {
        let id_token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJTcThVTFhoN1dpemprRjFWMnUtSnRvdkVSSDBDZlZJdVlFUEswLWZ2UGtNIn0.eyJleHAiOjE3NjAxNzk2NTAsImlhdCI6MTc2MDE3OTM1MCwiYXV0aF90aW1lIjoxNzYwMTc5MzEwLCJqdGkiOiIxZTZhNjNiNy0wMmIzLTczMTctMGIzMC0zMTZlZmE1YjJlZDIiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojg3ODYvcmVhbG1zL3Rlc3QiLCJhdWQiOiJvaWRjX3Rlc3QiLCJzdWIiOiJhNWI2NDBmYy00MmY2LTQ2MTctYjcxYi0zMjZlZGZlZDE4ZTkiLCJ0eXAiOiJJRCIsImF6cCI6Im9pZGNfdGVzdCIsIm5vbmNlIjoibVRRVno4YzNHZlRXaUZtYTJwRXFMWlVHV3hxVlB3eVpteEtIWnFhMzM3d1dqZF9zZWhyOEZhTFhWaFhCaHF3VDVGWGtKMF80RHFQcUE2azVweDBMeWciLCJzaWQiOiJlOGFkNmRiZC0xMDcyLTRkYTgtOWZkNi1iM2I2ZTcyZTY4YWIiLCJhdF9oYXNoIjoiRV9WNjZXaFRVVW5ZVy1WY3FaMm5qZyIsImFjciI6IjAiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkhhbnMgSGFzZSIsInByZWZlcnJlZF91c2VybmFtZSI6ImhhbnMuaGFzZUBleGFtcGxlLm9yZyIsImdpdmVuX25hbWUiOiJIYW5zIiwiZmFtaWx5X25hbWUiOiJIYXNlIiwiZW1haWwiOiJoYW5zLmhhc2VAZXhhbXBsZS5vcmcifQ.fGOSvo8gEjmmdhZF8g3ABB3YJlkDot3et3PE9HAHlKwdNHYKQ07R8egi6r7JsPInaMkV-NfztY2mh15jzILVRMdAbflYhH12fzo9BuvqsGQNG-LV_ootJHTXhI72WXTl7I5pelYj4Pp-UnZr2wNKhNkEND3p1CjPlaAgX-EL9Mxrw4k0OybJneYDejSOx4IEIM7w92y8Tyw18tBQHWzSmrrr1Fu6Eb3M_WkdsXNIiiVwYjHxMA50YrLX8VcUJODuPIp4QorfWLxXswksOHW2UMpEklx7qNr-ps42MgQ40zTJZR_fOYHn5hPlauwKfqgkGmuHdkFQeftWlXfSgs10Yg";
        let user_identity = UserIdentity::<MyClaims>::from_token(id_token).unwrap();
        assert_eq!(user_identity.claims.sub, "a5b640fc-42f6-4617-b71b-326edfed18e9");
        assert_eq!(user_identity.claims.name, "Hans Hase");
    }
    
}