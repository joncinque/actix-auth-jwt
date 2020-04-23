use actix_web::web::{self, ServiceConfig};

use crate::config::AppConfig;
use crate::emails::EmailSender;
use crate::service::auth_service;
use crate::state::AuthState;
use crate::models::base::User;
use crate::repos::base::UserRepo;
use crate::passwords;

use crate::types::{shareable_data, PinFutureObj};

pub type DataFactoryFunc<T> = Box<dyn Fn() -> PinFutureObj<std::io::Result<AuthState<T>>>>;

pub fn config_data_factory<T, U>(config: AppConfig<T, U>) -> DataFactoryFunc<U>
    where
        T: User + 'static,
        U: UserRepo<T> + 'static {
    Box::new(move || {
        let user_repo = shareable_data(U::from(&config.user_repo));
        let hasher = passwords::argon2_password_hasher(&config.hasher);
        let verifier = passwords::argon2_password_verifier(&config.hasher);
        let sender = shareable_data(EmailSender::from(&config.sender));
        Box::pin(async move {
            Ok(AuthState { user_repo, hasher, verifier, sender, })
        })
    })
}

pub fn config_app<T: User + 'static, U: UserRepo<T> + 'static>() -> Box<dyn Fn(&mut ServiceConfig)> {
    Box::new(move |cfg: &mut ServiceConfig| {
        cfg.service(auth_service::<T, U>(web::scope("/auth")));
    })
}
