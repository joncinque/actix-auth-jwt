use crate::repos::base::UserRepo;
use crate::models::base::User;
use crate::emails::EmailConfig;
use crate::passwords::PasswordHasherConfig;
use crate::jwts::base::{JwtAuthenticatorConfig, JwtBlacklist};

pub struct AppConfig<U, R, B>
    where
        U: User,
        R: UserRepo<U>,
        B: JwtBlacklist<U> {
    pub user_repo: R::Config,
    pub sender: EmailConfig,
    pub hasher: PasswordHasherConfig,
    pub authenticator: JwtAuthenticatorConfig,
    pub blacklist: B::Config,
}

impl<U, R, B> Clone for AppConfig<U, R, B>
    where
        U: User,
        R: UserRepo<U>,
        B: JwtBlacklist<U> {
    fn clone(&self) -> AppConfig<U, R, B> {
        AppConfig {
            user_repo: self.user_repo.clone(),
            sender: self.sender.clone(),
            hasher: self.hasher.clone(),
            authenticator: self.authenticator.clone(),
            blacklist: self.blacklist.clone(),
        }
    }
}
