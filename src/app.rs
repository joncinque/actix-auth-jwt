use actix_web::web::{self, ServiceConfig};

use crate::config::AppConfig;
use crate::emails::EmailSender;
use crate::jwts::base::{JwtAuthenticator, JwtBlacklist};
use crate::service::auth_service;
use crate::state::AuthState;
use crate::models::base::User;
use crate::repos::base::UserRepo;
use crate::passwords;

use crate::types::{shareable_data, PinFutureObj};

pub type DataFactoryFunc<U, R, B> = Box<dyn Fn() -> PinFutureObj<std::io::Result<AuthState<U, R, B>>>>;

/// Actix-specific helper for creating the `data_factory` as required by the
/// routes within the service.  Since actix may create multiple versions of this
/// across tasks and threads, everything must be Box'ed and Pin'ed safely.
pub fn config_data_factory<U, R, B>(config: AppConfig<U, R, B>) -> DataFactoryFunc<U, R, B>
    where
        U: User + 'static,
        R: UserRepo<U> + 'static,
        B: JwtBlacklist<U> + 'static, {
    Box::new(move || {
        let user_repo = shareable_data(R::from(&config.user_repo));
        let hasher = passwords::argon2_password_hasher(&config.hasher);
        let verifier = passwords::argon2_password_verifier(&config.hasher);
        let sender = shareable_data(EmailSender::from(&config.sender));
        let blacklist = B::from(&config.blacklist);
        let authenticator = shareable_data(JwtAuthenticator::from(&config.authenticator, blacklist));
        Box::pin(async move {
            Ok(AuthState { user_repo, hasher, verifier, sender, authenticator, })
        })
    })
}

/// Actix-specific helper for adding the auth service's routes to the app
pub fn config_app<U, R, B>() -> Box<dyn Fn(&mut ServiceConfig)>
    where U: User + 'static, R: UserRepo<U> + 'static, B: JwtBlacklist<U> + 'static {
    Box::new(move |cfg: &mut ServiceConfig| {
        cfg.service(auth_service::<U, R, B>(web::scope("/auth")));
    })
}
