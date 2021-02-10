//! Top-level service providing API routes and processor functions

use actix_web::web::{get, post, resource, Data, Json, Path};
use actix_web::{HttpRequest, HttpResponse, Responder, Scope};
use actix_web_httpauth::extractors::bearer::BearerAuth;
use lettre_email::EmailBuilder;
use std::time::SystemTime;
use validator::Validate;

use crate::dtos::{
    ConfirmId, LoginUser, LoginUserResponse, RefreshToken, RefreshTokenResponse, ResetPassword,
    ResetPasswordConfirm, TokenStatus, TokenStatusResponse, UpdatePassword,
};
use crate::extractors::JwtUserId;
use crate::models::base::User;
use crate::state::AuthState;
// import needed to know what's on UserRepo, but gets improperly flagged
use crate::errors::{self, AuthApiError};
#[allow(unused_imports)]
use crate::repos::base::UserRepo;

const SUCCESS_MESSAGE: &str = "Success";

async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

async fn register<U>(
    req: HttpRequest,
    registration: Json<U::RegisterDto>,
    data: Data<AuthState<U>>,
) -> Result<HttpResponse, AuthApiError>
where
    U: User,
{
    let registration = registration.into_inner();
    registration
        .validate()
        .map_err(errors::from_validation_errors)?;

    let mut user = U::from(registration);

    let mut builder = EmailBuilder::new()
        .to(user.email())
        .subject("Confirm email address");

    let hash = (data.hasher.hasher)(String::from(user.password())).await?;
    user.set_password(hash);

    let id = format!("{}", user.id());
    let mut user_repo = data.user_repo.write().await;
    user_repo.insert(user).await?;
    let url = req.url_for("register-confirm", &[id]).unwrap();
    builder = builder.body(format!(
        "Please go to {} to confirm your registration.",
        url
    ));

    let mut sender = data.sender.write().await;
    sender.send(builder).await?;

    Ok(HttpResponse::Created().body(SUCCESS_MESSAGE))
}

async fn login<U>(
    login: Json<LoginUser>,
    data: Data<AuthState<U>>,
) -> Result<HttpResponse, AuthApiError>
where
    U: User,
{
    let login = login.into_inner();

    let user_repo = data.user_repo.read().await;
    let key = U::Key::from(login.key);
    let user = user_repo.get_by_key(&key).await?;
    let verified = (data.hasher.verifier)(login.password, String::from(user.password())).await?;
    if verified {
        let mut authenticator = data.authenticator.write().await;
        let now = SystemTime::now();
        let token_pair = authenticator.create_token_pair(user.id(), now).await?;
        let bearer = token_pair.bearer;
        let refresh = token_pair.refresh;
        let user_id = format!("{}", user.id());
        Ok(HttpResponse::Ok().json(LoginUserResponse {
            bearer,
            refresh,
            user_id,
        }))
    } else {
        Err(AuthApiError::Unauthenticated)
    }
}

async fn logout<U: User>(
    auth: BearerAuth,
    data: Data<AuthState<U>>,
) -> Result<HttpResponse, AuthApiError> {
    let mut authenticator = data.authenticator.write().await;
    authenticator.blacklist(auth.token().to_owned()).await?;
    Ok(HttpResponse::Ok().body(SUCCESS_MESSAGE))
}

async fn token_refresh<U: User>(
    token: Json<RefreshToken>,
    data: Data<AuthState<U>>,
) -> Result<HttpResponse, AuthApiError> {
    let token = token.into_inner();
    let mut authenticator = data.authenticator.write().await;
    let pair = authenticator.refresh(token.refresh).await?;
    let bearer = pair.bearer;
    let refresh = pair.refresh;
    Ok(HttpResponse::Ok().json(RefreshTokenResponse { bearer, refresh }))
}

async fn token_status<U: User>(
    token: Json<TokenStatus>,
    data: Data<AuthState<U>>,
) -> Result<HttpResponse, AuthApiError> {
    let token = token.into_inner().token;
    let authenticator = data.authenticator.read().await;
    let data = authenticator.decode(&token)?;
    let jti = data.claims.jti;
    let status = authenticator.status(&jti).await;
    Ok(HttpResponse::Ok().json(TokenStatusResponse { status }))
}

async fn register_confirm<U>(
    info: Path<ConfirmId>,
    data: Data<AuthState<U>>,
) -> Result<HttpResponse, AuthApiError>
where
    U: User,
{
    let mut user_repo = data.user_repo.write().await;
    let info = info.into_inner();
    let id = U::Id::from(info.id);
    user_repo
        .confirm(&id)
        .await
        .map(|_| HttpResponse::Ok().body(SUCCESS_MESSAGE))
}

async fn password_reset_confirm<U>(
    info: Path<ConfirmId>,
    reset: Json<ResetPasswordConfirm>,
    data: Data<AuthState<U>>,
) -> Result<HttpResponse, AuthApiError>
where
    U: User,
{
    let reset = reset.into_inner();
    reset.validate().map_err(errors::from_validation_errors)?;
    let info = info.into_inner();
    let now = SystemTime::now();
    let mut user_repo = data.user_repo.write().await;
    user_repo
        .password_reset_confirm(&info.id, reset.password1, now)
        .await?;
    Ok(HttpResponse::Ok().body(SUCCESS_MESSAGE))
}

async fn password_reset<U>(
    req: HttpRequest,
    reset: Json<ResetPassword>,
    data: Data<AuthState<U>>,
) -> Result<HttpResponse, AuthApiError>
where
    U: User,
{
    let key = U::Key::from(reset.into_inner().key);
    let mut user_repo = data.user_repo.write().await;
    let now = SystemTime::now();
    let user = user_repo.get_by_key(&key).await?;
    let email = user.email().to_owned();
    let reset_id = user_repo.password_reset(&key, now).await?;

    let mut builder = EmailBuilder::new().to(email).subject("Reset password");

    let url = req.url_for("password-reset-confirm", &[reset_id]).unwrap();
    builder = builder.body(format!("Please go to {} to reset your password.", url));

    let mut sender = data.sender.write().await;
    sender.send(builder).await?;
    Ok(HttpResponse::Ok().body(SUCCESS_MESSAGE))
}

async fn update<U: User>(
    update: Json<U::UpdateDto>,
    user: JwtUserId<U>,
    data: Data<AuthState<U>>,
) -> Result<HttpResponse, AuthApiError> {
    let update = update.into_inner();
    update.validate().map_err(errors::from_validation_errors)?;
    let mut user_repo = data.user_repo.write().await;
    let id = user.user_id;
    let user = user_repo.get_by_id(&id).await?;
    let mut user = user.clone();
    user.update(update);
    user_repo.update(user).await?;
    Ok(HttpResponse::Ok().body(SUCCESS_MESSAGE))
}

async fn password_update<U>(
    reset: Json<UpdatePassword>,
    user: JwtUserId<U>,
    data: Data<AuthState<U>>,
) -> Result<HttpResponse, AuthApiError>
where
    U: User,
{
    let reset = reset.into_inner();
    reset.validate().map_err(errors::from_validation_errors)?;
    let mut user_repo = data.user_repo.write().await;
    let id = user.user_id;
    let user = user_repo.get_by_id(&id).await?;
    let verified =
        (data.hasher.verifier)(reset.old_password, String::from(user.password())).await?;
    if verified {
        let hash = (data.hasher.hasher)(reset.new_password1).await?;
        let mut user = user.clone();
        user.set_password(hash);
        user_repo.update(user).await?;
        Ok(HttpResponse::Ok().body(SUCCESS_MESSAGE))
    } else {
        Err(AuthApiError::Unauthenticated)
    }
}

/// Function to configure the routes on a service
pub fn auth_service<U>(scope: Scope) -> Scope
where
    U: User + 'static,
{
    scope
        .route("/", get().to(index))
        .route("/register", post().to(register::<U>))
        .service(
            resource("/register/confirm/{id}")
                .name("register-confirm")
                .route(post().to(register_confirm::<U>)),
        )
        .route("/login", post().to(login::<U>))
        .route("/logout", post().to(logout::<U>))
        .route("/update", post().to(update::<U>))
        .route("/token/refresh", post().to(token_refresh::<U>))
        .route("/token/status", get().to(token_status::<U>))
        .route("/password/reset", post().to(password_reset::<U>))
        .service(
            resource("/password/reset/{id}")
                .name("password-reset-confirm")
                .route(post().to(password_reset_confirm::<U>)),
        )
        .route("/password/update", post().to(password_update::<U>))
}

#[cfg(test)]
mod tests {
    use actix_web::dev::{Body, MessageBody, ServiceResponse};
    use actix_web::http::{header, StatusCode};
    use actix_web::{test, App};
    use regex::Regex;
    use serde::de::DeserializeOwned;

    use crate::jwts::base::JwtStatus;
    use crate::models::base::User;
    use crate::models::simple::SimpleUser;
    use crate::transports::InMemoryTransport;
    use crate::types::{shareable_data, ShareableData};

    use super::*;

    type RegisterDto = <SimpleUser as User>::RegisterDto;
    type UpdateDto = <SimpleUser as User>::UpdateDto;

    fn register_dto(email: String, password1: String, password2: String) -> RegisterDto {
        RegisterDto {
            email,
            password1,
            password2,
        }
    }

    fn get_body(response: &ServiceResponse) -> &str {
        match response.response().body().as_ref() {
            Some(Body::Bytes(bytes)) => std::str::from_utf8(bytes).unwrap(),
            _ => panic!("Response error"),
        }
    }

    async fn read_body_json<B, T>(res: ServiceResponse<B>) -> T
    where
        B: MessageBody + Unpin,
        T: DeserializeOwned,
    {
        let body = test::read_body(res).await;
        serde_json::from_slice(&body)
            .unwrap_or_else(|_| panic!("read_body_json failed during deserialization"))
    }

    fn get_confirmation_url(message: &str) -> &str {
        let re = Regex::new(r"http://\S+").unwrap();
        let m = re.find(&message).unwrap();
        m.as_str()
    }

    async fn register_user(
        email: &str,
        password1: &str,
        password2: &str,
        state: AuthState<SimpleUser>,
    ) -> ServiceResponse {
        let mut app = test::init_service(
            App::new()
                .data(state)
                .route("/register", post().to(register::<SimpleUser>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser>)),
                ),
        )
        .await;
        let dto = register_dto(email.to_owned(), password1.to_owned(), password2.to_owned());
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&dto)
            .to_request();
        test::call_service(&mut app, req).await
    }

    async fn confirm_user(
        email: &str,
        transport: ShareableData<InMemoryTransport>,
        state: AuthState<SimpleUser>,
    ) -> ServiceResponse {
        let mut app = test::init_service(
            App::new().data(state.clone()).service(
                resource("/register/confirm/{id}")
                    .name("register-confirm")
                    .route(post().to(register_confirm::<SimpleUser>)),
            ),
        )
        .await;

        let message;
        {
            let confirmation = transport.write().await.emails.remove(0);
            let tos = confirmation.envelope().to().to_vec();
            assert_eq!(tos.len(), 1);
            let to = format!("{}", tos[0]);
            assert_eq!(&to, email);
            let from = format!("{}", confirmation.envelope().from().unwrap());
            assert_eq!(&from, "admin@example.com");
            message = confirmation.message_to_string().unwrap();
        }

        let url = get_confirmation_url(&message);
        let req = test::TestRequest::post().uri(url).to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        resp
    }

    async fn reset_password_initiate(email: &str, state: AuthState<SimpleUser>) -> ServiceResponse {
        let mut app = test::init_service(
            App::new()
                .data(state)
                .route("/password/reset", post().to(password_reset::<SimpleUser>))
                .service(
                    resource("/password/reset/{id}")
                        .name("password-reset-confirm")
                        .route(post().to(password_reset_confirm::<SimpleUser>)),
                ),
        )
        .await;
        let key = email.to_owned();
        let dto = ResetPassword { key };
        let req = test::TestRequest::post()
            .uri("/password/reset")
            .set_json(&dto)
            .to_request();
        test::call_service(&mut app, req).await
    }

    async fn reset_password_confirm(
        password1: &str,
        password2: &str,
        transport: ShareableData<InMemoryTransport>,
        state: AuthState<SimpleUser>,
    ) -> ServiceResponse {
        let mut app = test::init_service(
            App::new().data(state.clone()).service(
                resource("/password/reset/{id}")
                    .name("password-reset-confirm")
                    .route(post().to(password_reset_confirm::<SimpleUser>)),
            ),
        )
        .await;

        let message = {
            let confirmation = transport.write().await.emails.remove(0);
            confirmation.message_to_string().unwrap()
        };
        let url = get_confirmation_url(&message);

        let password1 = password1.to_owned();
        let password2 = password2.to_owned();
        let dto = ResetPasswordConfirm {
            password1,
            password2,
        };
        let req = test::TestRequest::post()
            .uri(url)
            .set_json(&dto)
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        resp
    }

    async fn login_user(
        email: &str,
        password: &str,
        state: AuthState<SimpleUser>,
    ) -> ServiceResponse {
        let mut app = test::init_service(
            App::new()
                .data(state)
                .route("/login", post().to(login::<SimpleUser>)),
        )
        .await;
        let dto = LoginUser {
            key: email.to_owned(),
            password: password.to_owned(),
        };
        let req = test::TestRequest::post()
            .uri("/login")
            .set_json(&dto)
            .to_request();
        test::call_service(&mut app, req).await
    }

    async fn update_user(
        bearer: &str,
        email: &str,
        state: AuthState<SimpleUser>,
    ) -> ServiceResponse {
        let mut app = test::init_service(
            App::new()
                .app_data(state.extractor.clone())
                .data(state)
                .route("/update", post().to(update::<SimpleUser>)),
        )
        .await;
        let email = email.to_owned();
        let dto = UpdateDto { email };
        let req = test::TestRequest::post()
            .uri("/update")
            .header(header::AUTHORIZATION, format!("Bearer {}", bearer))
            .set_json(&dto)
            .to_request();
        test::call_service(&mut app, req).await
    }

    async fn update_password(
        bearer: &str,
        old_password: &str,
        new_password1: &str,
        new_password2: &str,
        state: AuthState<SimpleUser>,
    ) -> ServiceResponse {
        let mut app = test::init_service(
            App::new()
                .app_data(state.extractor.clone())
                .data(state)
                .route("/password/update", post().to(password_update::<SimpleUser>)),
        )
        .await;
        let dto = UpdatePassword {
            old_password: old_password.to_owned(),
            new_password1: new_password1.to_owned(),
            new_password2: new_password2.to_owned(),
        };
        let req = test::TestRequest::post()
            .uri("/password/update")
            .header(header::AUTHORIZATION, format!("Bearer {}", bearer))
            .set_json(&dto)
            .to_request();
        test::call_service(&mut app, req).await
    }

    async fn logout_user(bearer: &str, state: AuthState<SimpleUser>) -> ServiceResponse {
        let mut app = test::init_service(
            App::new()
                .data(state)
                .route("/logout", post().to(logout::<SimpleUser>)),
        )
        .await;
        let req = test::TestRequest::post()
            .uri("/logout")
            .header(header::AUTHORIZATION, format!("Bearer {}", bearer))
            .to_request();
        test::call_service(&mut app, req).await
    }

    async fn refresh_token(refresh: String, state: AuthState<SimpleUser>) -> ServiceResponse {
        let mut app = test::init_service(
            App::new()
                .data(state)
                .route("/token/refresh", post().to(token_refresh::<SimpleUser>)),
        )
        .await;
        let dto = RefreshToken { refresh };
        let req = test::TestRequest::post()
            .uri("/token/refresh")
            .set_json(&dto)
            .to_request();
        test::call_service(&mut app, req).await
    }

    async fn status_token(token: String, state: AuthState<SimpleUser>) -> ServiceResponse {
        let mut app = test::init_service(
            App::new()
                .data(state)
                .route("/token/status", get().to(token_status::<SimpleUser>)),
        )
        .await;
        let dto = TokenStatus { token };
        let req = test::TestRequest::get()
            .uri("/token/status")
            .set_json(&dto)
            .to_request();
        test::call_service(&mut app, req).await
    }

    #[actix_rt::test]
    async fn get_index() {
        let mut app = test::init_service(App::new().route("/", get().to(index))).await;
        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_rt::test]
    async fn post_register() {
        let state: AuthState<SimpleUser> = Default::default();
        let user_repo = state.user_repo.clone();
        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let resp = register_user(&email, &password, &password, state).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        {
            let user_repo = user_repo.read().await;
            let err = user_repo.get_by_key(&email).await.unwrap_err();
            assert!(matches!(err, AuthApiError::Unconfirmed { .. } ));
        }
    }

    #[actix_rt::test]
    async fn fail_register_password_validation() {
        let state: AuthState<SimpleUser> = Default::default();
        let email = String::from("test@example.com");
        let password1 = String::from("p@ssword1");
        let password2 = String::from("p@ssword2");
        let resp = register_user(&email, &password1, &password2, state).await;
        let body = get_body(&resp);
        assert!(body.contains("password1"));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn fail_register_password_short() {
        let state: AuthState<SimpleUser> = Default::default();
        let email = String::from("test@example.com");
        let password = String::from("p@ss");
        let resp = register_user(&email, &password, &password, state).await;
        let body = get_body(&resp);
        assert!(body.contains("password1"));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn fail_register_invalid_email() {
        let state: AuthState<SimpleUser> = Default::default();
        let email = String::from("test");
        let password = String::from("p@ssword");
        let resp = register_user(&email, &password, &password, state).await;
        let body = get_body(&resp);
        assert!(body.contains("email"));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn fail_register_same_email() {
        let state: AuthState<SimpleUser> = Default::default();
        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let resp = register_user(&email, &password, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = register_user(&email, &password, &password, state).await;
        let body = get_body(&resp);
        assert!(body.contains("User already exists: test@example.com"));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn fail_post_login_unconfirmed() {
        let state: AuthState<SimpleUser> = Default::default();
        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let resp = register_user(&email, &password, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = login_user(&email, &password, state).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn post_login() {
        let state: AuthState<SimpleUser> = Default::default();
        let sender = state.sender.clone();
        let transport = shareable_data(InMemoryTransport::default());
        sender.write().await.transport = transport.clone();

        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let resp = register_user(&email, &password, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = confirm_user(&email, transport.clone(), state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = login_user(&email, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let result: LoginUserResponse = read_body_json(resp).await;
        assert_ne!(result.user_id, String::from(""));
        assert_ne!(result.bearer, String::from(""));
        assert_ne!(result.refresh, String::from(""));
        let resp = status_token(result.bearer.clone(), state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let status: TokenStatusResponse = read_body_json(resp).await;
        assert_eq!(status.status, JwtStatus::Outstanding);
        let resp = logout_user(&result.bearer, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_rt::test]
    async fn fail_post_login_wrong_password() {
        let state: AuthState<SimpleUser> = Default::default();
        let sender = state.sender.clone();
        let transport = shareable_data(InMemoryTransport::default());
        sender.write().await.transport = transport.clone();

        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let resp = register_user(&email, &password, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = confirm_user(&email, transport.clone(), state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = login_user(&email, "notp@ssword", state.clone()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp = logout_user("Bad.token.data", state.clone()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn update_password_header() {
        let state: AuthState<SimpleUser> = Default::default();
        let sender = state.sender.clone();
        let transport = shareable_data(InMemoryTransport::default());
        sender.write().await.transport = transport.clone();

        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let resp = register_user(&email, &password, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = confirm_user(&email, transport.clone(), state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = login_user(&email, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let result: LoginUserResponse = read_body_json(resp).await;
        let new_password = String::from("newp@ass!");
        let resp = update_password(
            &result.bearer,
            &password,
            &new_password,
            &new_password,
            state.clone(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = login_user(&email, &new_password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_rt::test]
    async fn fail_update_password_no_header() {
        let state: AuthState<SimpleUser> = Default::default();
        let sender = state.sender.clone();
        let transport = shareable_data(InMemoryTransport::default());
        sender.write().await.transport = transport.clone();

        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let resp = register_user(&email, &password, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = confirm_user(&email, transport.clone(), state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let new_password = String::from("newp@ass!");
        let resp = update_password(
            "Bearer blah.blah.blah",
            &password,
            &new_password,
            &new_password,
            state.clone(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn fail_update_password_wrong_password2() {
        let state: AuthState<SimpleUser> = Default::default();
        let sender = state.sender.clone();
        let transport = shareable_data(InMemoryTransport::default());
        sender.write().await.transport = transport.clone();

        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let resp = register_user(&email, &password, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = confirm_user(&email, transport.clone(), state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = login_user(&email, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let result: LoginUserResponse = read_body_json(resp).await;
        let resp = update_password(
            &result.bearer,
            &password,
            "newp@ass!",
            "othernewpass!",
            state.clone(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn fail_update_password_wrong_old_password() {
        let state: AuthState<SimpleUser> = Default::default();
        let sender = state.sender.clone();
        let transport = shareable_data(InMemoryTransport::default());
        sender.write().await.transport = transport.clone();

        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let resp = register_user(&email, &password, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = confirm_user(&email, transport.clone(), state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = login_user(&email, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let result: LoginUserResponse = read_body_json(resp).await;
        let new_password = String::from("newp@ass!");
        let resp = update_password(
            &result.bearer,
            "somethingelse",
            &new_password,
            &new_password,
            state.clone(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_rt::test]
    async fn refresh_valid_token() {
        let state: AuthState<SimpleUser> = Default::default();
        let sender = state.sender.clone();
        let transport = shareable_data(InMemoryTransport::default());
        sender.write().await.transport = transport.clone();

        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let resp = register_user(&email, &password, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = confirm_user(&email, transport.clone(), state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = login_user(&email, &password, state.clone()).await;
        let result1: LoginUserResponse = read_body_json(resp).await;
        let resp = status_token(result1.bearer.clone(), state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let status: TokenStatusResponse = read_body_json(resp).await;
        assert_eq!(status.status, JwtStatus::Outstanding);
        let resp = refresh_token(result1.refresh.clone(), state.clone()).await;
        let result2: RefreshTokenResponse = read_body_json(resp).await;
        assert_ne!(result2.bearer, String::from(""));
        assert_ne!(result2.refresh, String::from(""));
        let resp = status_token(result2.bearer, state.clone()).await;
        let status: TokenStatusResponse = read_body_json(resp).await;
        assert_eq!(status.status, JwtStatus::Outstanding);
        let resp = status_token(result1.bearer, state.clone()).await;
        let status: TokenStatusResponse = read_body_json(resp).await;
        assert_eq!(status.status, JwtStatus::Blacklisted);
    }

    #[actix_rt::test]
    async fn reset_user_password() {
        let state: AuthState<SimpleUser> = Default::default();
        let sender = state.sender.clone();
        let transport = shareable_data(InMemoryTransport::default());
        sender.write().await.transport = transport.clone();

        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let resp = register_user(&email, &password, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = confirm_user(&email, transport.clone(), state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = reset_password_initiate(&email, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let password = String::from("newp@ssword");
        let resp =
            reset_password_confirm(&password, &password, transport.clone(), state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = login_user(&email, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_rt::test]
    async fn update_simple_user() {
        let state: AuthState<SimpleUser> = Default::default();
        let sender = state.sender.clone();
        let transport = shareable_data(InMemoryTransport::default());
        sender.write().await.transport = transport.clone();

        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let resp = register_user(&email, &password, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let resp = confirm_user(&email, transport.clone(), state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = login_user(&email, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let result: LoginUserResponse = read_body_json(resp).await;
        let new_email = String::from("newtest@example.com");
        let resp = update_user(&result.bearer, &new_email, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = login_user(&new_email, &password, state.clone()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
