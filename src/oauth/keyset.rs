use std::sync::Arc;

use jsonwebtoken::{Algorithm, DecodingKey};
use thiserror::Error;
use crate::oauth::client::{create_http_client, CreateHttpClientError};

#[derive(Debug, Error)]
#[error("Get JWK error: {0}")]
pub struct GetKeyError(String);

impl From<CreateHttpClientError> for GetKeyError {
    fn from(err: CreateHttpClientError) -> Self {
        GetKeyError(err.to_string())
    }
}

impl From<jsonwebtoken::errors::Error> for GetKeyError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        GetKeyError(err.to_string())
    }
}

#[derive(serde::Deserialize, Debug)]
pub struct KeyResponse {
    kid: String,
    kty: String,
    alg: String,
    n: Option<String>,
    e: Option<String>,
    #[allow(dead_code)]
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
pub struct KeySetResponse {
    keys: Vec<KeyResponse>,
}

impl KeySetResponse {
    pub fn into_keys(self) -> Vec<Jwk> {
        self.keys.into_iter().map(|k| Jwk(Arc::new(k))).collect()
    }
}

pub struct Jwk(Arc<KeyResponse>);

impl Clone for Jwk {
    fn clone(&self) -> Self {
        Jwk(Arc::clone(&self.0))
    }
}

pub struct KeyFetcher {
    jwks_url: String,
}
impl KeyFetcher {
    pub fn new(jwks_url: &str) -> Self {
        KeyFetcher {
            jwks_url: jwks_url.to_owned(),
        }
    }
    pub async fn fetch_key(&self, key_id: &str) -> Result<Jwk, GetKeyError> {
        let client = create_http_client()?;

        let res = client
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| GetKeyError(format!("HTTP request error: {}", e)))?;

        let keyset: KeySetResponse = res
            .json()
            .await
            .map_err(|e| GetKeyError(format!("Error parsing JWKs response: {}", e)))?;

        for key in keyset.into_keys() {
            if key.0.kid == key_id {
                return Ok(key);
            }
        }

        Err(GetKeyError("Key ID of the token was not found in JWKs".to_string()))
    }
}

impl Jwk {
    pub fn to_decoding_key(self) -> Result<(DecodingKey, Algorithm), GetKeyError> {
        match self.0.kty.as_str() {
            "RSA" => {
                let n = self.0.n.as_ref().ok_or_else(|| {
                    GetKeyError("Missing 'n' parameter for RSA key".to_string())
                })?;
                let e = self.0.e.as_ref().ok_or_else(|| {
                    GetKeyError("Missing 'e' parameter for RSA key".to_string())
                })?;
                let key = DecodingKey::from_rsa_components(n, e)
                    .map_err(|e| GetKeyError(format!("Error creating RSA decoding key: {}", e)))?;
                Ok((key, self.0.alg.parse()?))
            }
            "EC" => {
                let x = self.0.x.as_ref().ok_or_else(|| {
                    GetKeyError("Missing 'x' parameter for EC key".to_string())
                })?;
                let y = self.0.y.as_ref().ok_or_else(|| {
                    GetKeyError("Missing 'y' parameter for EC key".to_string())
                })?;
                let key = DecodingKey::from_ec_components(x, y)
                    .map_err(|e| GetKeyError(format!("Error creating EC decoding key: {}", e)))?;
                Ok((key, self.0.alg.parse()?))
            }
            _ => Err(GetKeyError(format!(
                "Unsupported key type: {}",
                self.0.kty
            ))),
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use p256::{ecdsa::SigningKey, elliptic_curve::SecretKey, pkcs8::{EncodePrivateKey}, NistP256};
    use rand_core::OsRng;
    use rsa::{pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts, RsaPrivateKey, RsaPublicKey};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        exp: usize,
    }

    // EC helpers
    fn sign_with_ec(pkcs8: &[u8]) -> Result<String, jsonwebtoken::errors::Error> {
        let encoding_key = EncodingKey::from_ec_der(pkcs8);
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("test-ec".to_string());

        let claims = Claims {
            sub: "test-sub".to_string(),
            exp: 0,
        };

        jsonwebtoken::encode(&header, &claims, &encoding_key)
    }

    fn create_jwk_ec(secret: SecretKey<NistP256>) -> Jwk {
        let signing_key: SigningKey = secret.into();
        let verify_key = signing_key.verifying_key();
        let encoded = verify_key.to_encoded_point(false);

        let x = encoded.x().unwrap();
        let y = encoded.y().unwrap();

        let x_b64 = BASE64_URL_SAFE_NO_PAD.encode(x);
        let y_b64 = BASE64_URL_SAFE_NO_PAD.encode(y);

        let key_response = KeyResponse {
            kid: "test-ec".to_string(),
            kty: "EC".to_string(),
            alg: "ES256".to_string(),
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: Some(x_b64),
            y: Some(y_b64),
        };

        Jwk(Arc::new(key_response))
    }

    // RSA helpers
    fn create_token_signed_with_rsa(pkcs1: &[u8], alg: Algorithm) -> Result<String, jsonwebtoken::errors::Error> {
        let encoding_key = EncodingKey::from_rsa_der(pkcs1);
        let mut header = Header::new(alg);
        header.kid = Some("test-rsa".to_string());

        let claims = Claims {
            sub: "test-sub".to_string(),
            exp: 0,
        };

        jsonwebtoken::encode(&header, &claims, &encoding_key)
    }

    fn create_jwk_rsa(pk: RsaPublicKey, alg: Algorithm) -> Jwk {
        let alg_str = match alg {
            Algorithm::RS256 => "RS256", 
            Algorithm::RS384 => "RS384",
            Algorithm::RS512 => "RS512",
            _ => panic!("Unsupported algorithm for RSA JWK"),
        };

        let e = pk.e();
        let n = pk.n();
        let e_b64 = BASE64_URL_SAFE_NO_PAD.encode(e.to_bytes_be());
        let n_b64 = BASE64_URL_SAFE_NO_PAD.encode(n.to_bytes_be());
        let key_response = KeyResponse {
            kid: "test-rsa".to_string(),
            kty: "RSA".to_string(),
            alg: alg_str.to_string(),
            n: Some(n_b64),
            e: Some(e_b64),
            crv: None,
            x: None,
            y: None,
        };

        Jwk(Arc::new(key_response))
    }

    fn create_token(secret: SecretKey<NistP256>) -> String {
        let pkcs8 = secret.to_pkcs8_der().unwrap();
        let token = sign_with_ec(&pkcs8.to_bytes()).expect("failed to sign token");
        token
    }

    #[actix_rt::test]
    async fn test_rsa256_jwk_to_decoding_key() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let token = create_token_signed_with_rsa(private_key.to_pkcs1_der().unwrap().as_bytes(), Algorithm::RS256).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let jwk = create_jwk_rsa(public_key, Algorithm::RS256);

        // Act: Convert JWK to DecodingKey
        let res = jwk.to_decoding_key();

        // Asserts:
        assert!(res.is_ok(), "to_decoding_key failed: {:?}", res.err());
        
        let (key, alg) = res.unwrap();
        assert_eq!(alg, Algorithm::RS256);

        // verify token with decoding key and algorithm
        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.validate_aud = false;
        validation.validate_exp = false;
        let token_data = jsonwebtoken::decode::<Claims>(&token, &key, &validation).unwrap();
        assert_eq!(token_data.claims.sub, "test-sub");
    }

    #[actix_rt::test]
    async fn test_rsa512_jwk_to_decoding_key() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let token = create_token_signed_with_rsa(private_key.to_pkcs1_der().unwrap().as_bytes(), Algorithm::RS512).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let jwk = create_jwk_rsa(public_key, Algorithm::RS512);

        // Act: Convert JWK to DecodingKey
        let res = jwk.to_decoding_key();

        // Asserts:
        assert!(res.is_ok(), "to_decoding_key failed: {:?}", res.err());
        
        let (key, alg) = res.unwrap();
        assert_eq!(alg, Algorithm::RS512);

        // verify token with decoding key and algorithm
        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.validate_aud = false;
        validation.validate_exp = false;
        let token_data = jsonwebtoken::decode::<Claims>(&token, &key, &validation).unwrap();
        assert_eq!(token_data.claims.sub, "test-sub");
    }


    #[actix_rt::test]
    async fn test_ec_jwk_to_decoding_key() {
        // Arrange:
        // Secret to sign the token
        let secret: SecretKey<NistP256> = SecretKey::random(&mut OsRng);
        // get test token
        let token = create_token(secret.clone());
        // get JWK
        let jwk = create_jwk_ec(secret);

        // Act: Convert JWK to DecodingKey
        let res = jwk.to_decoding_key();

        // Asserts:
        assert!(res.is_ok(), "to_decoding_key failed: {:?}", res.err());
        
        let (key, alg) = res.unwrap();
        assert_eq!(alg, Algorithm::ES256);

        // verify token with decoding key and algorithm
        let mut validation = jsonwebtoken::Validation::new(alg);
        validation.validate_aud = false;
        validation.validate_exp = false;
        let token_data = jsonwebtoken::decode::<Claims>(&token, &key, &validation).unwrap();
        assert_eq!(token_data.claims.sub, "test-sub");

    }
}