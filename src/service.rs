use actix_web::{
    get,
    post,
    HttpRequest,
    HttpResponse,
    Responder,
    Scope,
};
use actix_web::web::{post, resource, Data, Json, Path};
use lettre_email::EmailBuilder;
use validator::Validate;

use crate::dtos::{
    ConfirmId,
    LoginUser,
    LoginUserResponse,
    ResetPassword,
    ResetPasswordConfirm,
    UpdatePassword
};
use crate::state::AuthState;
use crate::models::base::{User, Status};
use crate::errors::{self, AuthApiError};

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

async fn register<T: User>(req: HttpRequest, registration: Json<T::RegisterDto>, data: Data<AuthState<T>>)
    -> Result<HttpResponse, AuthApiError> {
    let registration = registration.into_inner();
    registration.validate().map_err(errors::from_validation_errors)?;

    let mut user = T::from(registration);

    let mut builder = EmailBuilder::new()
        .to(user.email())
        .subject("Confirm email address");

    let hash = (data.hasher)(String::from(user.password())).await?;
    user.set_password(hash);

    {
        let mut user_repo = data.user_repo.write().unwrap();
        let id = user_repo.insert_unconfirmed(user).await?;
        let id = format!("{}", id);
        let url = req.url_for("register-confirm", &[id]).unwrap();
        builder = builder.body(format!("Please go to {} to confirm your registration.", url));
    }

    {
        let mut sender = data.sender.write().unwrap();
        sender.send(builder).await?;
    }
    Ok(HttpResponse::Created().body("Success."))
}

async fn login<T: User>(login: Json<LoginUser>, data: Data<AuthState<T>>)
    -> Result<HttpResponse, AuthApiError> {
    let login = login.into_inner();

    let user_repo = data.user_repo.read().unwrap();
    let key = T::Key::from(login.email);
    let user_option = user_repo.get(&key).await;
    match user_option {
        None => Err(AuthApiError::NotFound { key: format!("{}", key) }),
        Some(user) => {
            if *user.status() == Status::Confirmed {
                let verified = (data.verifier)(login.password, String::from(user.password())).await?;
                if verified {
                    let jwt = String::from("blah");
                    Ok(HttpResponse::Ok().json(LoginUserResponse { jwt }))
                } else {
                    Err(AuthApiError::Unauthenticated)
                }
            } else {
                Err(AuthApiError::Unconfirmed { key: format!("{}", key) })
            }
        }
    }
}

#[post("/logout")]
async fn logout() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

async fn register_confirm<T: User>(info: Path<ConfirmId>, data: Data<AuthState<T>>)
    -> Result<HttpResponse, AuthApiError> {
    let mut user_repo = data.user_repo.write().unwrap();
    let info = info.into_inner();
    let id = T::Id::from(info.id);
    match user_repo.confirm(&id).await {
        Ok(_) => Ok(HttpResponse::Ok().body("Success")),
        Err(e) => Err(e),
    }
}

async fn password_reset_confirm<T: User>(
    info: Path<ConfirmId>,
    reset: Json<ResetPasswordConfirm>,
    data: Data<AuthState<T>>) -> Result<HttpResponse, AuthApiError> {
    Ok(HttpResponse::Ok().body("Success"))
}

async fn password_reset<T: User>(reset: Json<ResetPassword>, data: Data<AuthState<T>>)
    -> Result<HttpResponse, AuthApiError> {
    Ok(HttpResponse::Ok().body("Success"))
}

async fn password_update<T: User>(reset: Json<UpdatePassword>, data: Data<AuthState<T>>)
    -> Result<HttpResponse, AuthApiError> {
    Ok(HttpResponse::Ok().body("Success"))
}

pub fn auth_service<T: User + 'static>(scope: Scope) -> Scope {
    scope.service(index)
        .route("/register", post().to(register::<T>))
        .service(
            resource("/register/confirm/{id}")
                .name("register-confirm")
                .route(post().to(register_confirm::<T>)))
        .route("/login", post().to(login::<T>))
        .route("/password/reset", post().to(password_reset::<T>))
        .route("/password/reset/{id}", post().to(password_reset_confirm::<T>))
        .route("/password/update", post().to(password_update::<T>))
}

#[cfg(test)]
mod tests {
    use actix_web::{
        test,
        App,
    };
    use actix_web::http::StatusCode;
    use actix_web::dev::Body;
    use actix_web::dev::ServiceResponse;

    use crate::models::base::User;
    use crate::models::simple::SimpleUser;
    use crate::state;

    use super::*;

    type RegisterDto = <SimpleUser as User>::RegisterDto;

    fn register_dto(email: String, password1: String, password2: String) -> RegisterDto {
        RegisterDto { email, password1, password2, }
    }

    fn get_body(response: &ServiceResponse) -> &str {
        match response.response().body().as_ref() {
            Some(Body::Bytes(bytes)) => std::str::from_utf8(bytes).unwrap(),
            _ => panic!("Response error"),
        }
    }

    #[actix_rt::test]
    async fn get_index() {
        let mut app = test::init_service(App::new().service(index)).await;
        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_rt::test]
    async fn post_register() {
        let user_repo = state::inmemory_repo();
        let transport = state::inmemory_transport();
        let sender = state::inmemory_sender(transport);
        let state = state::state::<SimpleUser>(user_repo.clone(), sender.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser>)))
        ).await;
        let email = String::from("test@example.com");
        let password1 = String::from("p@ssword");
        let password2 = String::from("p@ssword");
        let dto = register_dto(email, password1, password2);
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let user_repo = user_repo.read().unwrap();
        let user = user_repo.get(&dto.email).await.unwrap();
        assert_ne!(user.password, dto.password1);
    }

    #[actix_rt::test]
    async fn fail_register_password_validation() {
        let user_repo = state::inmemory_repo();
        let transport = state::inmemory_transport();
        let sender = state::inmemory_sender(transport);
        let state = state::state::<SimpleUser>(user_repo.clone(), sender.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser>)))
        ).await;
        let email = String::from("test@example.com");
        let password1 = String::from("p@ssword1");
        let password2 = String::from("p@ssword2");
        let dto = register_dto(email, password1, password2);
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        let body = get_body(&resp);
        assert!(body.contains("password1"));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn fail_register_password_short() {
        let user_repo = state::inmemory_repo();
        let transport = state::inmemory_transport();
        let sender = state::inmemory_sender(transport);
        let state = state::state::<SimpleUser>(user_repo.clone(), sender.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser>)))
        ).await;
        let email = String::from("test@example.com");
        let password1 = String::from("p@ss");
        let password2 = String::from("p@ss");
        let dto = register_dto(email, password1, password2);
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        let body = get_body(&resp);
        assert!(body.contains("password1"));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn fail_register_invalid_email() {
        let user_repo = state::inmemory_repo();
        let transport = state::inmemory_transport();
        let sender = state::inmemory_sender(transport);
        let state = state::state::<SimpleUser>(user_repo.clone(), sender.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser>)))
        ).await;
        let email = String::from("test");
        let password1 = String::from("p@ssword");
        let password2 = String::from("p@ssword");
        let dto = register_dto(email, password1, password2);
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        let body = get_body(&resp);
        assert!(body.contains("email"));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn fail_register_same_email() {
        let user_repo = state::inmemory_repo();
        let transport = state::inmemory_transport();
        let sender = state::inmemory_sender(transport);
        let state = state::state::<SimpleUser>(user_repo.clone(), sender.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser>)))
        ).await;
        let email = String::from("test@example.com");
        let password1 = String::from("p@ssword");
        let password2 = String::from("p@ssword");
        let dto = register_dto(email, password1, password2);
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        let body = get_body(&resp);
        assert!(body.contains("User already exists: test@example.com"));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn fail_post_login_unconfirmed() {
        let user_repo = state::inmemory_repo();
        let transport = state::inmemory_transport();
        let sender = state::inmemory_sender(transport);
        let state = state::state::<SimpleUser>(user_repo.clone(), sender.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser>)))
                .route("/login", post().to(login::<SimpleUser>))
        ).await;
        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let dto = register_dto(email.clone(), password.clone(), password.clone());
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let dto = LoginUser { email, password };
        let req = test::TestRequest::post().uri("/login").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn post_login() {
        let user_repo = state::inmemory_repo();
        let transport = state::inmemory_transport();
        let sender = state::inmemory_sender(transport.clone());
        let state = state::state::<SimpleUser>(user_repo.clone(), sender.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser>)))
                .route("/login", post().to(login::<SimpleUser>))
        ).await;
        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let dto = register_dto(email.clone(), password.clone(), password.clone());
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        {
            let confirmation = transport.write().unwrap().emails.remove(0);
            let tos = confirmation.envelope().to().to_vec();
            assert_eq!(tos.len(), 1);
            let to = format!("{}", tos[0]);
            assert_eq!(&to, &email);
            let from = format!("{}", confirmation.envelope().from().unwrap());
            assert_eq!(&from, "admin@example.com");
            let message = confirmation.message_to_string().unwrap();
            println!("{}", &message);
        }

        let dto = LoginUser { email, password };
        let req = test::TestRequest::post().uri("/login").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
