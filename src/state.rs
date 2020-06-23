use lettre::stub::StubTransport;
use std::sync::Arc;

use crate::emails::EmailSender;
use crate::jwts::authenticator::JwtAuthenticator;
use crate::models::base::User;
use crate::passwords::PasswordHasher;
use crate::repos::base::UserRepo;
use crate::repos::inmemory::InMemoryUserRepo;
use crate::transports::{EmptyResultTransport, InMemoryTransport};
use crate::types::{shareable_data, ShareableData};
use crate::extractors::JwtUserIdConfig;

pub struct AuthState<U>
where U: User + 'static {
    pub user_repo: ShareableData<dyn UserRepo<U>>,
    pub hasher: Arc<PasswordHasher>,
    pub sender: ShareableData<EmailSender>,
    pub authenticator: ShareableData<JwtAuthenticator<U>>,
    pub extractor: JwtUserIdConfig<U>,
}

impl<U> Clone for AuthState<U>
where U: User + 'static {
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

pub fn inmemory_repo<T: User + 'static>() -> ShareableData<InMemoryUserRepo<T>> {
    shareable_data(Default::default())
}

pub fn inmemory_transport() -> ShareableData<InMemoryTransport> {
    shareable_data(Default::default())
}

pub fn stub_transport() -> ShareableData<StubTransport> {
    shareable_data(StubTransport::new_positive())
}

pub fn test_sender(transport: ShareableData<EmptyResultTransport>) -> ShareableData<EmailSender> {
    shareable_data(EmailSender::new(String::from("admin@example.com"), transport))
}

pub fn test_authenticator<U: User + 'static>() -> ShareableData<JwtAuthenticator<U>> {
    shareable_data(JwtAuthenticator::default())
}

pub fn state<U>(
    user_repo: ShareableData<dyn UserRepo<U>>,
    sender: ShareableData<EmailSender>,
    authenticator: ShareableData<JwtAuthenticator<U>>) -> AuthState<U>
    where U: User {
    let hasher: Arc<PasswordHasher> = Arc::new(Default::default());
    let extractor = JwtUserIdConfig::<U> { authenticator: authenticator.clone() };
    AuthState { user_repo, hasher, sender, authenticator, extractor }
}
