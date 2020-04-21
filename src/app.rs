use actix_web::web::{self, ServiceConfig};
use dotenv::dotenv;
use dotenv_codegen::dotenv;

use crate::service::auth_service;
use crate::state::{self, AuthState};
use crate::models::base::User;
use crate::passwords;

pub async fn data_factory<T: User + 'static>() -> std::io::Result<AuthState<T>> {
    dotenv().ok();
    let user_repo = state::inmemory_repo();
    let secret_key = String::from(dotenv!("HASHER_SECRET_KEY"));
    let hasher = passwords::argon2_password_hasher(secret_key.clone());
    let verifier = passwords::argon2_password_verifier(secret_key.clone());
    let transport  = state::inmemory_transport();
    let sender = state::inmemory_sender(transport);
    Ok(AuthState { user_repo, hasher, verifier, sender })
}

pub fn config_app<T: User + 'static>() -> Box<dyn Fn(&mut ServiceConfig)> {
    Box::new(move |cfg: &mut ServiceConfig| {
        cfg.service(auth_service::<T>(web::scope("/auth")));
    })
}
