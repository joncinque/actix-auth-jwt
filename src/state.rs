use lettre::stub::StubTransport;

use crate::emails::EmailSender;
use crate::transports::{EmptyResultTransport, InMemoryTransport};
use crate::models::base::User;
use crate::repos::base::UserRepo;
use crate::repos::inmemory::InMemoryUserRepo;
use crate::passwords::{self, PasswordHasher, PasswordVerifier};
use crate::types::{shareable_data, ShareableData};

pub struct AuthState<T> {
    pub user_repo: ShareableData<T>,
    pub hasher: PasswordHasher,
    pub verifier: PasswordVerifier,
    pub sender: ShareableData<EmailSender>,
}

pub fn inmemory_repo<T: User + 'static>() -> ShareableData<InMemoryUserRepo<T>> {
    let config = ();
    shareable_data(InMemoryUserRepo::<T>::new(&config))
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

pub fn email_sender(from: String, transport: ShareableData<EmptyResultTransport>) -> ShareableData<EmailSender> {
    shareable_data(EmailSender::new(from, transport))
}

pub fn state<T>(
    user_repo: ShareableData<T>,
    sender: ShareableData<EmailSender>)
    -> AuthState<T> {
    let hasher = passwords::empty_password_hasher();
    let verifier = passwords::empty_password_verifier();
    AuthState { user_repo, hasher, verifier, sender, }
}
