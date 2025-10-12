use serde::de::DeserializeOwned;

pub trait UserInfoAttributes: DeserializeOwned {
    fn name(&self) -> String;
}
