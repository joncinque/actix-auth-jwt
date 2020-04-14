use actix_web::web::{self, ServiceConfig};

use crate::auth_service::make_auth_service;
use crate::app_state::AppState;
use crate::db::{AbstractUser, InMemoryUserRepo};

pub async fn state_factory<'a, T: AbstractUser<'a>>() -> std::io::Result<AppState<'a, T>> {
    let user_repo = Box::new(InMemoryUserRepo::<'a, T>::new());
    Ok(AppState { user_repo })
}

pub fn config_app<'a, T: AbstractUser<'a>>() -> Box<dyn Fn(&mut ServiceConfig)> {
    Box::new(move |cfg: &mut ServiceConfig| {
        cfg.service(make_auth_service::<T>(web::scope("/auth")));
    })
}
