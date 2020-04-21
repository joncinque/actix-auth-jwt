use std::sync::{Arc, RwLock};

use crate::emails::EmailSender;
use crate::transports::{EmptyResultTransport, InMemoryTransport};
use crate::models::base::User;
use crate::repos::base::UserRepo;
use crate::repos::inmemory::InMemoryUserRepo;
use crate::passwords::{self, PasswordHasher, PasswordVerifier};
use crate::types::ShareableData;

pub struct AuthState<T: User> {
    pub user_repo: ShareableData<dyn UserRepo<T>>,
    pub hasher: PasswordHasher,
    pub verifier: PasswordVerifier,
    pub sender: ShareableData<EmailSender>,
}

pub fn inmemory_repo<T: User + 'static>() -> ShareableData<dyn UserRepo<T>> {
    Arc::new(RwLock::new(InMemoryUserRepo::<T>::new()))
}

pub fn inmemory_sender(transport: ShareableData<EmptyResultTransport>) -> ShareableData<EmailSender> {
    let from = String::from("admin@example.com");
    Arc::new(RwLock::new(EmailSender::new(from, transport)))
}

pub fn inmemory_transport() -> ShareableData<InMemoryTransport> {
    Arc::new(RwLock::new(InMemoryTransport::new_positive()))
}

pub fn state<T: User>(
    user_repo: ShareableData<dyn UserRepo<T>>,
    sender: ShareableData<EmailSender>)
    -> AuthState<T> {
    let hasher = passwords::empty_password_hasher();
    let verifier = passwords::empty_password_verifier();
    AuthState { user_repo, hasher, verifier, sender, }
}
