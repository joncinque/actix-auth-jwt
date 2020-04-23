use async_trait::async_trait;

use crate::errors::AuthApiError;
use crate::models::base::User;

#[async_trait]
pub trait UserRepo<T>
    where T: User {
    async fn get(&self, key: &T::Key) -> Option<&T>;
    async fn insert(&mut self, user: T) -> Result<(), AuthApiError>;
    async fn remove(&mut self, key: &T::Key) -> Result<T, AuthApiError>;
    async fn update(&mut self, user: T) -> Result<(), AuthApiError>;

    async fn insert_unconfirmed(&mut self, user: T) -> Result<T::Id, AuthApiError>;
    async fn confirm(&mut self, id: &T::Id) -> Result<(), AuthApiError>;

    async fn password_reset(&mut self, key: &T::Key) -> Result<T::Id, AuthApiError>;
    async fn password_reset_confirm(&mut self, id: &T::Id, password: &str) -> Result<(), AuthApiError>;

    type Config: Send + Sync + Clone;
    fn new(config: &Self::Config) -> Self;
}
