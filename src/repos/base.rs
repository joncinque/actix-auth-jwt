use async_trait::async_trait;

use crate::errors::AuthApiError;
use crate::models::base::User;

#[async_trait]
pub trait UserRepo<U>
    where U: User {
    async fn get_by_key(&self, key: &U::Key) -> Option<&U>;
    async fn get_by_id(&self, id: &U::Id) -> Option<&U>;

    async fn insert(&mut self, user: U) -> Result<(), AuthApiError>;
    async fn remove(&mut self, id: &U::Id) -> Result<U, AuthApiError>;
    async fn update(&mut self, user: U) -> Result<(), AuthApiError>;
    async fn confirm(&mut self, id: &U::Id) -> Result<(), AuthApiError>;

    async fn password_reset(&mut self, key: &U::Key) -> Result<U::Id, AuthApiError>;
    async fn password_reset_confirm(&mut self, id: &U::Id, password: &str) -> Result<(), AuthApiError>;

    type Config: Send + Sync + Clone;
    fn from(config: &Self::Config) -> Self;
}
