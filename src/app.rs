use {
    crate::{
        config::AppConfig, extractors::JwtUserIdConfig, models::base::User, service::auth_service,
        state::AuthState, types::PinFutureObj,
    },
    actix_web::web::{self, ServiceConfig},
};

pub type DataFactoryFunc<U> = Box<dyn Fn() -> PinFutureObj<std::io::Result<AuthState<U>>>>;

/// Actix-specific helper for creating the `data_factory` as required by the
/// routes within the service.  Since actix may create multiple versions of this
/// across tasks and threads, everything must be Box'ed and Pin'ed safely.
pub fn config_data_factory<U>(config: AppConfig<U>) -> DataFactoryFunc<U>
where
    U: User + 'static,
{
    Box::new(move || {
        let user_repo = (config.user_repo)();
        let hasher = (config.hasher)();
        let sender = (config.sender)();
        let authenticator = (config.authenticator)();
        let extractor = JwtUserIdConfig::<U> {
            authenticator: authenticator.clone(),
        };
        Box::pin(async move {
            user_repo.write().await.start().await.unwrap();
            Ok(AuthState {
                user_repo,
                hasher,
                sender,
                authenticator,
                extractor,
            })
        })
    })
}

/// Actix-specific helper for adding the auth service's routes to the app
pub fn config_app<U>() -> Box<dyn Fn(&mut ServiceConfig)>
where
    U: User + 'static,
{
    Box::new(move |cfg: &mut ServiceConfig| {
        cfg.service(auth_service::<U>(web::scope("/auth")));
    })
}
