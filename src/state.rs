use lettre::stub::StubTransport;

use crate::emails::EmailSender;
use crate::jwts::authenticator::{JwtAuthenticator, JwtAuthenticatorConfig};
use crate::jwts::base::JwtBlacklist;
use crate::jwts::inmemory::InMemoryJwtBlacklist;
use crate::models::base::User;
use crate::passwords::{self, PasswordHasher, PasswordVerifier};
use crate::repos::base::UserRepo;
use crate::repos::inmemory::InMemoryUserRepo;
use crate::transports::{EmptyResultTransport, InMemoryTransport};
use crate::types::{shareable_data, ShareableData};

pub struct AuthState<U, R, B>
    where U: User, R: UserRepo<U>, B: JwtBlacklist<U> {
    pub user_repo: ShareableData<R>,
    pub hasher: PasswordHasher,
    pub verifier: PasswordVerifier,
    pub sender: ShareableData<EmailSender>,
    pub authenticator: ShareableData<JwtAuthenticator<U, B>>,
}

pub fn inmemory_repo<T: User + 'static>() -> ShareableData<InMemoryUserRepo<T>> {
    let config = ();
    shareable_data(<InMemoryUserRepo<T> as UserRepo<T>>::from(&config))
}

pub fn inmemory_transport() -> ShareableData<InMemoryTransport> {
    shareable_data(InMemoryTransport::new_positive())
}

pub fn stub_transport() -> ShareableData<StubTransport> {
    shareable_data(StubTransport::new_positive())
}

pub fn test_sender(transport: ShareableData<EmptyResultTransport>) -> ShareableData<EmailSender> {
    email_sender(String::from("admin@example.com"), transport)
}

pub fn test_authenticator<U: User + 'static>() -> ShareableData<JwtAuthenticator<U, InMemoryJwtBlacklist<U>>> {
    let blacklist_config = ();
    let blacklist = <InMemoryJwtBlacklist<U> as JwtBlacklist<U>>::from(&blacklist_config);
    let auth_config: JwtAuthenticatorConfig = Default::default();
    shareable_data(JwtAuthenticator::from(auth_config, blacklist))
}

pub fn email_sender(from: String, transport: ShareableData<EmptyResultTransport>) -> ShareableData<EmailSender> {
    shareable_data(EmailSender::new(from, transport))
}

pub fn state<U, R, B>(
    user_repo: ShareableData<R>,
    sender: ShareableData<EmailSender>,
    authenticator: ShareableData<JwtAuthenticator<U, B>>) -> AuthState<U, R, B>
    where U: User,
          R: UserRepo<U>,
          B: JwtBlacklist<U> {
    let hasher = passwords::empty_password_hasher();
    let verifier = passwords::empty_password_verifier();
    AuthState { user_repo, hasher, verifier, sender, authenticator, }
}
