use async_trait::async_trait;

use crate::jwts::types::{Jti, Claims};
use crate::errors::AuthApiError;
use crate::models::base::User;

#[derive(Debug, PartialEq)]
pub enum JwtStatus {
    Outstanding,
    Blacklisted,
    NotFound,
}

pub trait JwtBlacklistConfig { }

/// Trait for a repository of JWTs that have been created by the system
#[async_trait]
pub trait JwtBlacklist<U>
    where U: User {
    /// Get the status of a token based only on its JTI
    async fn status(&self, jti: &Jti) -> JwtStatus;
    /// Move the token from outstanding to the blacklist
    async fn blacklist(&mut self, jti: Jti) -> Result<(), AuthApiError>;
    /// Add the token into the collection of outstanding tokens
    async fn insert_outstanding(&mut self, token: Claims<U>) -> Result<(), AuthApiError>;
}
