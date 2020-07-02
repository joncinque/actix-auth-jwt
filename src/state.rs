//! All state needs for Auth routes

use std::sync::Arc;

use crate::emails::EmailSender;
use crate::jwts::authenticator::JwtAuthenticator;
use crate::models::base::User;
use crate::passwords::PasswordHasher;
use crate::repos::base::UserRepo;
use crate::repos::inmemory::InMemoryUserRepo;
use crate::types::{shareable_data, ShareableData};
use crate::extractors::JwtUserIdConfig;

pub struct AuthState<U> where U: User + 'static {
    pub user_repo: ShareableData<dyn UserRepo<U>>,
    pub hasher: Arc<PasswordHasher>,
    pub sender: ShareableData<EmailSender>,
    pub authenticator: ShareableData<JwtAuthenticator<U>>,
    pub extractor: JwtUserIdConfig<U>,
}

impl<U> AuthState<U> where U: User + 'static {
    pub fn new(
        user_repo: ShareableData<dyn UserRepo<U>>,
        sender: ShareableData<EmailSender>,
        authenticator: ShareableData<JwtAuthenticator<U>>,
        hasher: Arc<PasswordHasher>) -> Self {
        let extractor = JwtUserIdConfig::<U> { authenticator: authenticator.clone() };
        AuthState { user_repo, hasher, sender, authenticator, extractor }
    }
}

impl<U> Clone for AuthState<U> where U: User + 'static {
    fn clone(&self) -> Self {
        AuthState::<U> {
            user_repo: self.user_repo.clone(),
            hasher: self.hasher.clone(),
            sender: self.sender.clone(),
            authenticator: self.authenticator.clone(),
            extractor: self.extractor.clone(),
        }
    }
}

impl<U> Default for AuthState<U> where U: User {
    fn default() -> Self {
        let user_repo: InMemoryUserRepo<U> = Default::default();
        let user_repo = shareable_data(user_repo);
        let sender: EmailSender = Default::default();
        let sender = shareable_data(sender);
        let authenticator: JwtAuthenticator<U> = Default::default();
        let authenticator = shareable_data(authenticator);
        let extractor = JwtUserIdConfig::<U> { authenticator: authenticator.clone() };
        let hasher: Arc<PasswordHasher> = Arc::new(Default::default());
        AuthState { user_repo, hasher, sender, authenticator, extractor }
    }
}
