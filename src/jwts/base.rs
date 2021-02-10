//! JWT Blacklist requirements

use {
    crate::{
        errors::AuthApiError,
        jwts::types::{Claims, Jti},
        models::base::User,
    },
    async_trait::async_trait,
    serde::{Deserialize, Serialize},
};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub enum JwtStatus {
    Outstanding,
    Blacklisted,
    NotFound,
}

/// Trait for a repository of JWTs that have been created by the system
#[async_trait]
pub trait JwtBlacklist<U>
where
    U: User,
{
    /// Get the status of a token based only on its JTI
    async fn status(&self, jti: &Jti) -> JwtStatus;
    /// Move the token from outstanding to the blacklist
    async fn blacklist(&mut self, jti: Jti) -> Result<(), AuthApiError>;
    /// Add the token into the collection of outstanding tokens
    async fn insert_outstanding(&mut self, token: Claims<U>) -> Result<(), AuthApiError>;
}
