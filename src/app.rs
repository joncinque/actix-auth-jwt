use std::sync::Mutex;
use actix_web::web::{self, ServiceConfig};

use crate::auth_service::make_auth_service;
use crate::app_state::AuthState;
use crate::models::base::User;
use crate::repos::base::UserRepo;
use crate::repos::inmemory::InMemoryUserRepo;

pub async fn data_factory<T: User + 'static>() -> std::io::Result<AuthState<T>> {
    let user_repo: Mutex<Box<dyn UserRepo<T>>> = Mutex::new(Box::new(InMemoryUserRepo::<T>::new()));
    Ok(AuthState { user_repo })
}

pub fn config_app<T: User + 'static>() -> Box<dyn Fn(&mut ServiceConfig)> {
    Box::new(move |cfg: &mut ServiceConfig| {
        cfg.service(make_auth_service::<T>(web::scope("/auth")));
    })
}
