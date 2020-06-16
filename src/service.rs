use actix_web::{
    HttpRequest,
    HttpResponse,
    Responder,
    Scope,
};
use actix_web::web::{get, post, resource, Data, Json, Path};
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
use crate::repos::base::UserRepo;
use crate::errors::{self, AuthApiError};

async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

async fn register<U, R>(req: HttpRequest, registration: Json<U::RegisterDto>, data: Data<AuthState<U, R>>)
    -> Result<HttpResponse, AuthApiError>
    where U: User, R: UserRepo<U> {
    let registration = registration.into_inner();
    registration.validate().map_err(errors::from_validation_errors)?;

    let mut user = U::from(registration);

    let mut builder = EmailBuilder::new()
        .to(user.email())
        .subject("Confirm email address");

    let hash = (data.hasher)(String::from(user.password())).await?;
    user.set_password(hash);

    {
        let id = format!("{}", user.id());
        let mut user_repo = data.user_repo.write().unwrap();
        user_repo.insert(user).await?;
        let url = req.url_for("register-confirm", &[id]).unwrap();
        builder = builder.body(format!("Please go to {} to confirm your registration.", url));
    }

    {
        let mut sender = data.sender.write().unwrap();
        sender.send(builder).await?;
    }
    Ok(HttpResponse::Created().body("Success."))
}

async fn login<U, R>(login: Json<LoginUser>, data: Data<AuthState<U, R>>)
    -> Result<HttpResponse, AuthApiError>
    where U: User, R: UserRepo<U> {
    let login = login.into_inner();

    let user_repo = data.user_repo.read().unwrap();
    let key = U::Key::from(login.email);
    let user_option = user_repo.get_by_key(&key).await;
    match user_option {
        None => Err(AuthApiError::NotFound { key: format!("{}", key) }),
        Some(user) => {
            if *user.status() == Status::Confirmed {
                let verified = (data.verifier)(login.password, String::from(user.password())).await?;
                if verified {
                    let access = String::from("blah");
                    let refresh = String::from("blah");
                    let userid = format!("{}", user.id());
                    Ok(HttpResponse::Ok().json(LoginUserResponse { access, refresh, userid }))
                } else {
                    Err(AuthApiError::Unauthenticated)
                }
            } else {
                Err(AuthApiError::Unconfirmed { key: format!("{}", key) })
            }
        }
    }
}

async fn logout<U: User>() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

async fn register_confirm<U, R>(info: Path<ConfirmId>, data: Data<AuthState<U, R>>)
    -> Result<HttpResponse, AuthApiError>
    where U: User, R: UserRepo<U> {
    let mut user_repo = data.user_repo.write().unwrap();
    let info = info.into_inner();
    let id = U::Id::from(info.id);
    match user_repo.confirm(&id).await {
        Ok(_) => Ok(HttpResponse::Ok().body("Success")),
        Err(e) => Err(e),
    }
}

async fn password_reset_confirm<U, R>(
    info: Path<ConfirmId>,
    reset: Json<ResetPasswordConfirm>,
    data: Data<AuthState<U, R>>) -> Result<HttpResponse, AuthApiError>
    where U: User, R: UserRepo<U> {
    Ok(HttpResponse::Ok().body("Success"))
}

async fn password_reset<U, R>(reset: Json<ResetPassword>, data: Data<AuthState<U, R>>)
    -> Result<HttpResponse, AuthApiError>
    where U: User, R: UserRepo<U> {
    Ok(HttpResponse::Ok().body("Success"))
}

async fn password_update<U, R>(reset: Json<UpdatePassword>, data: Data<AuthState<U, R>>)
    -> Result<HttpResponse, AuthApiError>
    where U: User, R: UserRepo<U> {
    Ok(HttpResponse::Ok().body("Success"))
}

pub fn auth_service<U, R>(scope: Scope) -> Scope
    where U: User + 'static, R: UserRepo<U> + 'static, {
    scope.route("/", get().to(index))
        .route("/register", post().to(register::<U, R>))
        .service(
            resource("/register/confirm/{id}")
                .name("register-confirm")
                .route(post().to(register_confirm::<U, R>)))
        .route("/login", post().to(login::<U, R>))
        .route("/logout", post().to(logout::<U>))
        .route("/password/reset", post().to(password_reset::<U, R>))
        .route("/password/reset/{id}", post().to(password_reset_confirm::<U, R>))
        .route("/password/update", post().to(password_update::<U, R>))
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
    use regex::Regex;

    use crate::models::base::User;
    use crate::models::simple::SimpleUser;
    use crate::repos::inmemory::InMemoryUserRepo;
    use crate::state;

    use super::*;

    type RegisterDto = <SimpleUser as User>::RegisterDto;
    type SimpleRepo = InMemoryUserRepo<SimpleUser>;

    fn register_dto(email: String, password1: String, password2: String) -> RegisterDto {
        RegisterDto { email, password1, password2, }
    }

    fn get_body(response: &ServiceResponse) -> &str {
        match response.response().body().as_ref() {
            Some(Body::Bytes(bytes)) => std::str::from_utf8(bytes).unwrap(),
            _ => panic!("Response error"),
        }
    }

    fn get_confirmation_url(message: &String) -> &str {
        let re = Regex::new(r"http://\S+").unwrap();
        let m = re.find(&message).unwrap();
        m.as_str()
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
        let user_repo = state::inmemory_repo();
        let transport = state::stub_transport();
        let sender = state::test_sender(transport);
        let auth = state::test_authenticator();
        let state = state::state::<SimpleUser, SimpleRepo>(user_repo.clone(), sender.clone(), auth.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser, SimpleRepo>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser, SimpleRepo>)))
        ).await;
        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        {
            let dto = register_dto(email.clone(), password.clone(), password.clone());
            let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
            let resp = test::call_service(&mut app, req).await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }
        {
            let user_repo = user_repo.read().unwrap();
            let user = user_repo.get_by_key(&email).await.unwrap();
            assert_ne!(user.password, password);
        }
    }

    #[actix_rt::test]
    async fn fail_register_password_validation() {
        let user_repo = state::inmemory_repo();
        let transport = state::stub_transport();
        let sender = state::test_sender(transport);
        let auth = state::test_authenticator();
        let state = state::state::<SimpleUser, SimpleRepo>(user_repo.clone(), sender.clone(), auth.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser, SimpleRepo>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser, SimpleRepo>)))
        ).await;
        let email = String::from("test@example.com");
        let password1 = String::from("p@ssword1");
        let password2 = String::from("p@ssword2");
        {
            let dto = register_dto(email, password1, password2);
            let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
            let resp = test::call_service(&mut app, req).await;
            let body = get_body(&resp);
            assert!(body.contains("password1"));
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[actix_rt::test]
    async fn fail_register_password_short() {
        let user_repo = state::inmemory_repo();
        let transport = state::stub_transport();
        let sender = state::test_sender(transport);
        let auth = state::test_authenticator();
        let state = state::state::<SimpleUser, SimpleRepo>(user_repo.clone(), sender.clone(), auth.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser, SimpleRepo>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser, SimpleRepo>)))
        ).await;
        let email = String::from("test@example.com");
        let password = String::from("p@ss");
        {
            let dto = register_dto(email, password.clone(), password.clone());
            let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
            let resp = test::call_service(&mut app, req).await;
            let body = get_body(&resp);
            assert!(body.contains("password1"));
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[actix_rt::test]
    async fn fail_register_invalid_email() {
        let user_repo = state::inmemory_repo();
        let transport = state::stub_transport();
        let sender = state::test_sender(transport);
        let auth = state::test_authenticator();
        let state = state::state::<SimpleUser, SimpleRepo>(user_repo.clone(), sender.clone(), auth.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser, SimpleRepo>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser, SimpleRepo>)))
        ).await;
        let email = String::from("test");
        let password = String::from("p@ssword");
        {
            let dto = register_dto(email, password.clone(), password.clone());
            let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
            let resp = test::call_service(&mut app, req).await;
            let body = get_body(&resp);
            assert!(body.contains("email"));
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[actix_rt::test]
    async fn fail_register_same_email() {
        let user_repo = state::inmemory_repo();
        let transport = state::stub_transport();
        let sender = state::test_sender(transport);
        let auth = state::test_authenticator();
        let state = state::state::<SimpleUser, SimpleRepo>(user_repo.clone(), sender.clone(), auth.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser, SimpleRepo>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser, SimpleRepo>)))
        ).await;
        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        let dto = register_dto(email, password.clone(), password.clone());
        {
            let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
            let _resp = test::call_service(&mut app, req).await;
        }
        {
            let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
            let resp = test::call_service(&mut app, req).await;
            let body = get_body(&resp);
            assert!(body.contains("User already exists: test@example.com"));
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[actix_rt::test]
    async fn fail_post_login_unconfirmed() {
        let user_repo = state::inmemory_repo();
        let transport = state::stub_transport();
        let sender = state::test_sender(transport);
        let auth = state::test_authenticator();
        let state = state::state::<SimpleUser, SimpleRepo>(user_repo.clone(), sender.clone(), auth.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser, SimpleRepo>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser, SimpleRepo>)))
                .route("/login", post().to(login::<SimpleUser, SimpleRepo>))
        ).await;
        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        {
            let dto = register_dto(email.clone(), password.clone(), password.clone());
            let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
            let resp = test::call_service(&mut app, req).await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        {
            let dto = LoginUser { email, password };
            let req = test::TestRequest::post().uri("/login").set_json(&dto).to_request();
            let resp = test::call_service(&mut app, req).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[actix_rt::test]
    async fn post_login() {
        let user_repo = state::inmemory_repo();
        let transport = state::inmemory_transport();
        let sender = state::test_sender(transport.clone());
        let auth = state::test_authenticator();
        let state = state::state::<SimpleUser, SimpleRepo>(user_repo.clone(), sender.clone(), auth.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser, SimpleRepo>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser, SimpleRepo>)))
                .route("/login", post().to(login::<SimpleUser, SimpleRepo>))
        ).await;

        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        {
            let dto = register_dto(email.clone(), password.clone(), password.clone());
            let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
            let resp = test::call_service(&mut app, req).await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let message;
        {
            let confirmation = transport.write().unwrap().emails.remove(0);
            let tos = confirmation.envelope().to().to_vec();
            assert_eq!(tos.len(), 1);
            let to = format!("{}", tos[0]);
            assert_eq!(&to, &email);
            let from = format!("{}", confirmation.envelope().from().unwrap());
            assert_eq!(&from, "admin@example.com");
            message = confirmation.message_to_string().unwrap();
            println!("{}", &message);
        }

        let url = get_confirmation_url(&message);
        {
            let req = test::TestRequest::post().uri(url).to_request();
            let resp = test::call_service(&mut app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }

        {
            let dto = LoginUser { email, password };
            let req = test::TestRequest::post().uri("/login").set_json(&dto).to_request();
            let resp = test::call_service(&mut app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[actix_rt::test]
    async fn fail_post_login_wrong_password() {
        let user_repo = state::inmemory_repo();
        let transport = state::inmemory_transport();
        let sender = state::test_sender(transport.clone());
        let auth = state::test_authenticator();
        let state = state::state::<SimpleUser, SimpleRepo>(user_repo.clone(), sender.clone(), auth.clone());
        let mut app = test::init_service(
            App::new().data(state)
                .route("/register", post().to(register::<SimpleUser, SimpleRepo>))
                .service(
                    resource("/register/confirm/{id}")
                        .name("register-confirm")
                        .route(post().to(register_confirm::<SimpleUser, SimpleRepo>)))
                .route("/login", post().to(login::<SimpleUser, SimpleRepo>))
        ).await;

        let email = String::from("test@example.com");
        let password = String::from("p@ssword");
        {
            let dto = register_dto(email.clone(), password.clone(), password.clone());
            let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
            let resp = test::call_service(&mut app, req).await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let message;
        {
            let confirmation = transport.write().unwrap().emails.remove(0);
            let tos = confirmation.envelope().to().to_vec();
            assert_eq!(tos.len(), 1);
            let to = format!("{}", tos[0]);
            assert_eq!(&to, &email);
            let from = format!("{}", confirmation.envelope().from().unwrap());
            assert_eq!(&from, "admin@example.com");
            message = confirmation.message_to_string().unwrap();
            println!("{}", &message);
        }

        let url = get_confirmation_url(&message);
        {
            let req = test::TestRequest::post().uri(url).to_request();
            let resp = test::call_service(&mut app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }

        {
            let password = String::from("notp@assword");
            let dto = LoginUser { email, password };
            let req = test::TestRequest::post().uri("/login").set_json(&dto).to_request();
            let resp = test::call_service(&mut app, req).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
    }
}
