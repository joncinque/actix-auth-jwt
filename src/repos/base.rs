use async_trait::async_trait;
use std::time::SystemTime;

use crate::errors::AuthApiError;
use crate::models::base::User;

#[async_trait]
pub trait UserRepo<U>
    where U: User {
    async fn get_by_key(&self, key: &U::Key) -> Result<&U, AuthApiError>;
    async fn get_by_id(&self, id: &U::Id) -> Result<&U, AuthApiError>;

    async fn insert(&mut self, user: U) -> Result<(), AuthApiError>;
    async fn remove(&mut self, id: &U::Id) -> Result<U, AuthApiError>;
    async fn update(&mut self, user: U) -> Result<(), AuthApiError>;
    async fn confirm(&mut self, id: &U::Id) -> Result<(), AuthApiError>;

    async fn password_reset(&mut self, key: &U::Key, time: SystemTime) -> Result<String, AuthApiError>;
    async fn password_reset_confirm(&mut self, id: &str, password: String, time: SystemTime) -> Result<(), AuthApiError>;
}
