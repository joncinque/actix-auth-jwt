use {
    actix_auth_jwt::{
        app,
        config::AppConfig,
        emails::EmailSender,
        jwts::{authenticator::JwtAuthenticator, inmemory::InMemoryJwtBlacklist},
        models::simple::SimpleUser,
        passwords::PasswordHasher,
        repos::inmemory::InMemoryUserRepo,
        transports::InMemoryTransport,
        types::shareable_data,
    },
    actix_web::{
        middleware::{Logger, NormalizePath},
        App, HttpServer,
    },
    dotenv::dotenv,
    dotenv_codegen::dotenv,
    jsonwebtoken::Algorithm,
    std::sync::Arc,
    std::time::Duration,
};

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_web=info");
    std::env::set_var("RUST_BACKTRACE", "1");

    type SimpleBlacklist = InMemoryJwtBlacklist<SimpleUser>;

    env_logger::init();
    dotenv().ok();

    let secret_key = String::from(dotenv!("HASHER_SECRET_KEY"));
    let from = String::from(dotenv!("FROM_EMAIL"));
    let iss = String::from(dotenv!("JWT_ISS"));
    let secret = String::from(dotenv!("JWT_SECRET_KEY"));
    let blacklist = shareable_data(SimpleBlacklist::default());

    let config = AppConfig {
        user_repo: Arc::new(Box::new(|| {
            shareable_data(InMemoryUserRepo::<SimpleUser>::new())
        })),
        sender: Arc::new(Box::new(move || {
            let transport = shareable_data(InMemoryTransport::default());
            let from = from.clone();
            shareable_data(EmailSender::new(from, transport))
        })),
        hasher: Arc::new(Box::new(move || {
            Arc::new(PasswordHasher::argon2(secret_key.clone()))
        })),
        authenticator: Arc::new(Box::new(move || {
            let alg = Algorithm::HS512;
            let bearer_token_lifetime = Duration::from_secs(60 * 60);
            let refresh_token_lifetime = Duration::from_secs(60 * 60 * 24);
            shareable_data(JwtAuthenticator::new(
                iss.clone(),
                alg,
                secret.clone(),
                bearer_token_lifetime,
                refresh_token_lifetime,
                blacklist.clone(),
            ))
        })),
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
