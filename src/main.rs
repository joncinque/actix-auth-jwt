use actix_web::{App, HttpServer};
use actix_web::middleware::{Logger, NormalizePath};
use dotenv::dotenv;
use dotenv_codegen::dotenv;
use jsonwebtoken::Algorithm;
use std::time::Duration;

use actix_auth_jwt::app;
use actix_auth_jwt::config::AppConfig;
use actix_auth_jwt::emails::{EmailConfig, EmailTransportType};
use actix_auth_jwt::jwts::base::JwtAuthenticatorConfig;
use actix_auth_jwt::jwts::inmemory::InMemoryJwtBlacklist;
use actix_auth_jwt::models::simple::SimpleUser;
use actix_auth_jwt::passwords::PasswordHasherConfig;
use actix_auth_jwt::repos::inmemory::InMemoryUserRepo;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_mongo=debug,actix_web=info");
    std::env::set_var("RUST_BACKTRACE", "1");

    type SimpleRepo = InMemoryUserRepo<SimpleUser>;
    type SimpleBlacklist = InMemoryJwtBlacklist<SimpleUser>;

    env_logger::init();
    dotenv().ok();

    let secret_key = String::from(dotenv!("HASHER_SECRET_KEY"));
    let from = String::from(dotenv!("FROM_EMAIL"));
    let iss = String::from(dotenv!("JWT_ISS"));
    let secret = String::from(dotenv!("JWT_SECRET_KEY"));

    let config = AppConfig {
        user_repo: (),
        sender: EmailConfig {
            from: from,
            transport_type: EmailTransportType::InMemory,
        },
        hasher: PasswordHasherConfig {
            secret_key,
        },
        authenticator: JwtAuthenticatorConfig {
            alg: Algorithm::HS512,
            iss,
            secret,
            access_key_lifetime: Duration::from_secs(60 * 60),
            refresh_key_lifetime: Duration::from_secs(60 * 60 * 24),
        },
        blacklist: (),
    };

    HttpServer::new(move || {
        App::new()
            .data_factory(
                app::config_data_factory::<SimpleUser, SimpleRepo, SimpleBlacklist>(config.clone()))
            .wrap(Logger::default())
            .wrap(NormalizePath)
            .configure(app::config_app::<SimpleUser, SimpleRepo, SimpleBlacklist>())
    })
    .bind("127.0.0.1:7878")?
    .run()
    .await
}
