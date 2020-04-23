use actix_web::web::{self, ServiceConfig};
use dotenv::dotenv;
use dotenv_codegen::dotenv;

use crate::config::AppConfig;
use crate::service::auth_service;
use crate::state::{self, AuthState};
use crate::models::base::User;
use crate::repos::base::UserRepo;
use crate::passwords;

use crate::types::{shareable_data, PinFutureObj};

pub type DataFactoryFunc<T> = Box<dyn Fn() -> PinFutureObj<std::io::Result<AuthState<T>>>>;

pub fn config_data_factory<T, U>(config: AppConfig<T, U>) -> DataFactoryFunc<U>
    where
        T: User + 'static,
        U: UserRepo<T> + 'static {
    dotenv().ok();
    Box::new(move || {
        let user_repo = shareable_data(U::new(&config.user_repo));
        let secret_key = String::from(dotenv!("HASHER_SECRET_KEY"));
        let hasher = passwords::argon2_password_hasher(secret_key.clone());
        let verifier = passwords::argon2_password_verifier(secret_key.clone());
        let transport  = state::inmemory_transport();
        let from_email = String::from(dotenv!("FROM_EMAIL"));
        let sender = state::email_sender(from_email, transport);
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
