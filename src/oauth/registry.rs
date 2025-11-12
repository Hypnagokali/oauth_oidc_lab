use std::collections::HashMap;
use std::sync::Arc;

use crate::{GitHubUserMapper, KeycloakUserMapper, UserMapper, oauth::provider::{OAuthConfig, OAuthConfigError, OAuthProvider}};

#[derive(Debug, thiserror::Error)]
#[error("Provider registry error: {0}")]
pub struct ProviderRegistryError(pub String);

pub struct OAuthProviderRegistry {
    providers: Arc<HashMap<String, OAuthProvider>>,
}

impl OAuthProviderRegistry {
    fn new(providers: HashMap<String, OAuthProvider>) -> Self {
        Self {
            providers: Arc::new(providers)
        }
    }

    pub fn get_provider(&self, name: &str) -> Option<&OAuthProvider> {
        self.providers.get(name)
    }

    pub async fn from_env() -> Result<Self, OAuthConfigError> {
        let env_vars: Vec<(String, String)> = std::env::vars().collect();
        let provider_prefixes: Vec<String> = env_vars.iter()
            .filter(|(key, _)| key.ends_with("_CLIENT_ID"))
            .map(|(key, _)| {
                let prefix_end = key.len() - "CLIENT_ID".len();
                key[..prefix_end].to_string()
            })
            .collect();

        let mut providers = HashMap::new();

        for prefix in provider_prefixes {
            if prefix.is_empty() {
                continue;
            }

            let name = prefix.trim_end_matches('_').to_lowercase();
            
            let config = OAuthConfig::from_env_with_prefix(&prefix).await?;

            // Just a quick fix for now :)
            let mapper: Arc<dyn UserMapper> = match name.as_ref() {
                "github" => Arc::new(GitHubUserMapper),
                "keycloak" => Arc::new(KeycloakUserMapper),
                not_found => panic!("No UserMapper found for {}", not_found)
            };

            providers.insert(name, OAuthProvider::new(config, mapper));

        }

        if providers.is_empty() {
            return Err(OAuthConfigError("No OAuth providers found in environment variables".to_string()));
        }

        Ok(Self::new(providers))
    }
}