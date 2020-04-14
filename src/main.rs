use actix_web::{App, HttpServer};
use actix_web::middleware::{Logger, NormalizePath};

use actix_auth_jwt::app;

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_mongo=debug,actix_web=info");
    std::env::set_var("RUST_BACKTRACE", "1");

    env_logger::init();

    HttpServer::new(|| {
        App::new()
            .data_factory(app::data_factory)
            .wrap(Logger::default())
            .wrap(NormalizePath)
            .configure(app::config_app())
    })
    .bind("127.0.0.1:7878")?
    .run()
    .await
}
