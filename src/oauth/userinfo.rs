use serde::de::DeserializeOwned;

pub trait UserInfoAttributes: DeserializeOwned {
    fn username(&self) -> String;
}
