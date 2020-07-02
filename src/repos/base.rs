//! General trait for the user repo, which could be contained in memory, in a
//! database, a flat file, whichever you prefer!
use async_trait::async_trait;
use std::time::SystemTime;

use crate::errors::AuthApiError;
use crate::models::base::User;

/// UserRepo contains all of the requirements for managing a user
#[async_trait]
pub trait UserRepo<U>
    where U: User {
    /// Get a User based in the human-provided key, most useful on login
    async fn get_by_key(&self, key: &U::Key) -> Result<&U, AuthApiError>;
    /// Get a User based on the machine-generated id, useful everywhere a User
    /// needs to be fetched from a JWT
    async fn get_by_id(&self, id: &U::Id) -> Result<&U, AuthApiError>;

    /// Add a new User, returning Err if the key or id already exists
    async fn insert(&mut self, user: U) -> Result<(), AuthApiError>;
    /// Remove an existing User based on Id
    async fn remove(&mut self, id: &U::Id) -> Result<U, AuthApiError>;
    /// Update an existing User based on Id
    async fn update(&mut self, user: U) -> Result<(), AuthApiError>;
    /// Confirm the registration of a User, usually coming from an emailed link
    async fn confirm(&mut self, id: &U::Id) -> Result<(), AuthApiError>;

    /// Reset user password without being logged in, used for forgotten passwords.
    /// The time parameter is used to expire a reset requests later.
    async fn password_reset(&mut self, key: &U::Key, time: SystemTime) -> Result<String, AuthApiError>;
    /// Confirm the reset of the password, along with the new password.  If the
    /// provided time is more than 10 minutes after the initial request, the
    /// reset will fail.
    /// TODO allow for tweaking the 10 minute reset
    async fn password_reset_confirm(&mut self, id: &str, password: String, time: SystemTime) -> Result<(), AuthApiError>;
}
