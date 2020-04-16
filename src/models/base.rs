use bson::{Bson, DecoderResult, EncoderResult};
use serde::Serialize;
use serde::de::DeserializeOwned;
use validator::Validate;

pub trait User
    where Self: Serialize + DeserializeOwned + Send + Sync {
    fn get_key(&self) -> &str;

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
