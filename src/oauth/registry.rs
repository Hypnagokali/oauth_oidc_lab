use std::collections::HashMap;
use std::sync::Arc;

use crate::oauth::provider::OAuthProvider;

#[derive(Debug, thiserror::Error)]
#[error("Provider registry error: {0}")]
pub struct ProviderRegistryError(pub String);

pub struct OAuthProviderRegistry {
    providers: Arc<HashMap<String, OAuthProvider>>,
}

impl OAuthProviderRegistry {
    pub fn from_vec(providers: Vec<OAuthProvider>) -> Self {
        let map: HashMap<String, OAuthProvider> = providers
            .into_iter()
            .map(|p| (p.name().to_string(), p))
            .collect();
        Self {
            providers: Arc::new(map),
        }
    }

    pub fn get_provider(&self, name: &str) -> Option<&OAuthProvider> {
        self.providers.get(name)
    }
}
