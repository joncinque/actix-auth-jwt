use std::sync::Arc;

use crate::emails::EmailSender;
use crate::jwts::authenticator::JwtAuthenticator;
use crate::models::base::User;
use crate::passwords::PasswordHasher;
use crate::repos::base::UserRepo;
use crate::types::ShareableData;

/// Configuration to be created by hand at the top-level, from secret stores
/// or .env files, and then passed to `config_data_factory`, which handles
/// creation of all components whenever required by Actix.
pub type ShareableClosure<T> = Arc<Box<dyn Fn() -> T + Send + Sync + 'static>>;

/// Struct explaining how to create the state of the App, provided through
/// closures.  See examples for how to do this.
pub struct AppConfig<U>
where
    U: User,
{
    pub user_repo: ShareableClosure<ShareableData<dyn UserRepo<U>>>,
    pub sender: ShareableClosure<ShareableData<EmailSender>>,
    pub hasher: ShareableClosure<Arc<PasswordHasher>>,
    pub authenticator: ShareableClosure<ShareableData<JwtAuthenticator<U>>>,
}

/// Manually implement Clone to satisfy moving AppConfig into async domains
impl<U> Clone for AppConfig<U>
where
    U: User,
{
    fn clone(&self) -> AppConfig<U> {
        AppConfig {
            user_repo: self.user_repo.clone(),
            sender: self.sender.clone(),
            hasher: self.hasher.clone(),
            authenticator: self.authenticator.clone(),
        }
    }
}
