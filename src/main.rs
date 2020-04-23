use actix_web::{App, HttpServer};
use actix_web::middleware::{Logger, NormalizePath};

use actix_auth_jwt::app;
use actix_auth_jwt::config::AppConfig;
use actix_auth_jwt::emails::{EmailConfig, EmailTransportType};
use actix_auth_jwt::models::simple::SimpleUser;
use actix_auth_jwt::repos::inmemory::InMemoryUserRepo;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_mongo=debug,actix_web=info");
    std::env::set_var("RUST_BACKTRACE", "1");

    type SimpleRepo = InMemoryUserRepo<SimpleUser>;

    env_logger::init();
    let config = AppConfig {
        user_repo: (),
        sender: EmailConfig {
            from: String::from("admin@example.com"),
            transport_type: EmailTransportType::InMemory,
        }
    };

    HttpServer::new(move || {
        App::new()
            .data_factory(
                app::config_data_factory::<SimpleUser, SimpleRepo>(config.clone()))
            .wrap(Logger::default())
            .wrap(NormalizePath)
            .configure(app::config_app::<SimpleUser, SimpleRepo>())
    })
    .bind("127.0.0.1:7878")?
    .run()
    .await
}
