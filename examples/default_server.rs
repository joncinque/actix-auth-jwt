use {
    actix_auth_jwt::{
        app, config::AppConfig, emails::EmailSender, jwts::authenticator::JwtAuthenticator,
        models::simple::SimpleUser, passwords::PasswordHasher, repos::inmemory::InMemoryUserRepo,
        types::shareable_data,
    },
    actix_web::{
        middleware::{Logger, NormalizePath},
        App, HttpServer,
    },
    std::sync::Arc,
};

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
            .wrap(NormalizePath::default())
            .configure(app::config_app::<SimpleUser>())
    })
    .bind("127.0.0.1:7878")?
    .run()
    .await
}
