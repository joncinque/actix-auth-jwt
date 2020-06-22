use actix_web::web::{self, ServiceConfig};

use crate::config::AppConfig;
use crate::service::auth_service;
use crate::state::AuthState;
use crate::models::base::User;
use crate::repos::base::UserRepo;
use crate::extractors::JwtUserIdConfig;

use crate::types::PinFutureObj;

pub type DataFactoryFunc<U, R> = Box<dyn Fn() -> PinFutureObj<std::io::Result<AuthState<U, R>>>>;

/// Actix-specific helper for creating the `data_factory` as required by the
/// routes within the service.  Since actix may create multiple versions of this
/// across tasks and threads, everything must be Box'ed and Pin'ed safely.
pub fn config_data_factory<U, R>(config: AppConfig<U, R>) -> DataFactoryFunc<U, R>
    where
        U: User + 'static,
        R: UserRepo<U> + 'static, {
    Box::new(move || {
        let user_repo = (config.user_repo)();
        let hasher = (config.hasher)();
        let sender = (config.sender)();
        let authenticator = (config.authenticator)();
        let extractor = JwtUserIdConfig::<U> { authenticator: authenticator.clone() };
        Box::pin(async move {
            Ok(AuthState { user_repo, hasher, sender, authenticator, extractor, })
        })
    })
}

/// Actix-specific helper for adding the auth service's routes to the app
pub fn config_app<U, R>() -> Box<dyn Fn(&mut ServiceConfig)>
    where U: User + 'static, R: UserRepo<U> + 'static {
    Box::new(move |cfg: &mut ServiceConfig| {
        cfg.service(auth_service::<U, R>(web::scope("/auth")));
    })
}
