use std::collections::HashMap;
use std::sync::Arc;

use crate::oauth::provider::OAuthProvider;

#[derive(Debug, thiserror::Error)]
#[error("Provider registry error: {0}")]
pub struct ProviderRegistryError(pub String);

pub struct OAuthProviderRegistry<U> {
    providers: Arc<HashMap<String, OAuthProvider<U>>>,
}

impl<U> OAuthProviderRegistry<U> {
    pub fn from_vec(providers: Vec<OAuthProvider<U>>) -> Self {
        let map: HashMap<String, OAuthProvider<U>> = providers
            .into_iter()
            .map(|p| (p.name().to_string(), p))
            .collect();
        Self {
            providers: Arc::new(map),
        }
    }

    pub fn get_provider(&self, name: &str) -> Option<&OAuthProvider<U>> {
        self.providers.get(name)
    }
}
