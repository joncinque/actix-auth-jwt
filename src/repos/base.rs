use async_trait::async_trait;

use crate::errors::AuthApiError;
use crate::models::base::User;

#[async_trait]
pub trait UserRepo<T>
    where T: User {
    async fn get(&self, key: &str) -> Option<&T>;
    async fn insert(&mut self, user: T) -> Result<(), AuthApiError>;
    async fn remove(&mut self, key: &str) -> Result<T, AuthApiError>;
    async fn update(&mut self, user: T) -> Result<(), AuthApiError>;
}
