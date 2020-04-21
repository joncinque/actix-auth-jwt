use std::hash::Hash;
use std::fmt::Display;
use bson::{Bson, DecoderResult, EncoderResult};
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use validator::Validate;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Status {
    Confirmed,
    Unconfirmed,
    Suspended,
    Deleted,
}

pub trait User
    where Self: Serialize + DeserializeOwned + Send + Sync {
    type Key: Clone + Eq + Hash + Display + From<String> + Send + Sync;
    type Id: Clone + Eq + Hash + Display + From<String> + Send + Sync;

    fn generate_id() -> Self::Id;

    fn key(&self) -> &Self::Key;
    fn id(&self) -> &Self::Id;

    fn status(&self) -> &Status;
    fn set_status(&mut self, status: Status);

    fn password(&self) -> &str;
    fn set_password(&mut self, hash: String);

    fn email(&self) -> &str;

    fn to_bson(&self) -> EncoderResult<Bson> {
        bson::to_bson(self)
    }

    fn from_bson(doc: Bson) -> DecoderResult<Self> {
        bson::from_bson::<Self>(doc)
    }

    type RegisterDto: DeserializeOwned + Validate;
    fn from(registration: Self::RegisterDto) -> Self;

    type UpdateDto: DeserializeOwned + Validate;
    fn update(&mut self, update: Self::UpdateDto);

    type UpdatePasswordDto: DeserializeOwned + Validate;
    fn update_password(&mut self, update_password: Self::UpdatePasswordDto);
}
