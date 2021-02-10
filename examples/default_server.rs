use actix_web::middleware::{Logger, NormalizePath};
use actix_web::{App, HttpServer};
use std::sync::Arc;

use actix_auth_jwt::app;
use actix_auth_jwt::config::AppConfig;
use actix_auth_jwt::emails::EmailSender;
use actix_auth_jwt::jwts::authenticator::JwtAuthenticator;
use actix_auth_jwt::models::simple::SimpleUser;
use actix_auth_jwt::passwords::PasswordHasher;
use actix_auth_jwt::repos::inmemory::InMemoryUserRepo;
use actix_auth_jwt::types::shareable_data;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let config = AppConfig {
        user_repo: Arc::new(Box::new(|| {
            shareable_data(InMemoryUserRepo::<SimpleUser>::default())
        })),
        sender: Arc::new(Box::new(move || shareable_data(EmailSender::default()))),
        hasher: Arc::new(Box::new(move || {
            Arc::new(PasswordHasher::argon2(String::from("secret")))
        })),
        authenticator: Arc::new(Box::new(
            move || shareable_data(JwtAuthenticator::default()),
        )),
    };

    HttpServer::new(move || {
        App::new()
            .data_factory(app::config_data_factory::<SimpleUser>(config.clone()))
            .wrap(Logger::default())
            .wrap(NormalizePath)
            .configure(app::config_app::<SimpleUser>())
    })
    .bind("127.0.0.1:7878")?
    .run()
    .await
}
