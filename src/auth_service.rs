use actix_web::{
    get,
    post,
    HttpResponse,
    Responder,
    Scope,
};
use actix_web::web::{post, Data, Json};
use validator::Validate;

use crate::dtos::LoginUser;
use crate::app_state::AuthState;
use crate::models::base::User;
use crate::errors::{self, AuthApiError};

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

async fn register<T: User>(registration: Json<T::RegisterDto>, data: Data<AuthState<T>>)
    -> Result<HttpResponse, AuthApiError> {
    let registration = registration.into_inner();
    registration.validate().map_err(errors::into_api_error)?;
    let user = T::from(registration);
    let mut user_repo = data.user_repo.lock().unwrap();
    user_repo.insert(user).await?;
    Ok(HttpResponse::Created().body("Success."))
}

async fn login<T: User>(login: Json<LoginUser>, data: Data<AuthState<T>>) -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

#[post("/logout")]
async fn logout() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

#[post("/email/confirm")]
async fn email_confirm() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

#[post("/password/reset")]
async fn password_reset() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

pub fn make_auth_service<T: User + 'static>(scope: Scope) -> Scope {
    scope.service(index)
        .route("/register", post().to(register::<T>))
        .route("/login", post().to(login::<T>))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use actix_web::{
        test,
        App,
    };
    use actix_web::http::StatusCode;
    use actix_web::dev::Body;
    use actix_web::dev::ServiceResponse;

    use crate::repos::base::UserRepo;
    use crate::repos::inmemory::InMemoryUserRepo;
    use crate::models::base::User;
    use crate::models::simple::SimpleUser;
    use super::*;
    type RegisterDto = <SimpleUser as User>::RegisterDto;

    fn make_register_dto(email: String, password1: String, password2: String) -> RegisterDto {
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
        let user_repo: Mutex<Box<dyn UserRepo<SimpleUser>>> = Mutex::new(Box::new(InMemoryUserRepo::<SimpleUser>::new()));
        let mut app = test::init_service(
            App::new().data(AuthState { user_repo })
                .route("/register", post().to(register::<SimpleUser>))
        ).await;
        let email = String::from("test@example.com");
        let password1 = String::from("p@ssword");
        let password2 = String::from("p@ssword");
        let dto = make_register_dto(email, password1, password2);
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[actix_rt::test]
    async fn fail_register_password_validation() {
        let user_repo: Mutex<Box<dyn UserRepo<SimpleUser>>> = Mutex::new(Box::new(InMemoryUserRepo::<SimpleUser>::new()));
        let mut app = test::init_service(
            App::new().data(AuthState { user_repo })
                .route("/register", post().to(register::<SimpleUser>))
        ).await;
        let email = String::from("test@example.com");
        let password1 = String::from("p@ssword1");
        let password2 = String::from("p@ssword2");
        let dto = make_register_dto(email, password1, password2);
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        let body = get_body(&resp);
        assert!(body.contains("password1"));
        assert!(body.contains("password2"));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn fail_register_password_short() {
        let user_repo: Mutex<Box<dyn UserRepo<SimpleUser>>> = Mutex::new(Box::new(InMemoryUserRepo::<SimpleUser>::new()));
        let mut app = test::init_service(
            App::new().data(AuthState { user_repo })
                .route("/register", post().to(register::<SimpleUser>))
        ).await;
        let email = String::from("test@example.com");
        let password1 = String::from("p@ss");
        let password2 = String::from("p@ss");
        let dto = make_register_dto(email, password1, password2);
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        let body = get_body(&resp);
        assert!(body.contains("password1"));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn fail_register_invalid_email() {
        let user_repo: Mutex<Box<dyn UserRepo<SimpleUser>>> = Mutex::new(Box::new(InMemoryUserRepo::<SimpleUser>::new()));
        let mut app = test::init_service(
            App::new().data(AuthState { user_repo })
                .route("/register", post().to(register::<SimpleUser>))
        ).await;
        let email = String::from("test");
        let password1 = String::from("p@ssword");
        let password2 = String::from("p@ssword");
        let dto = make_register_dto(email, password1, password2);
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        let body = get_body(&resp);
        assert!(body.contains("email"));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[actix_rt::test]
    async fn fail_register_same_email() {
        let user_repo: Mutex<Box<dyn UserRepo<SimpleUser>>> = Mutex::new(Box::new(InMemoryUserRepo::<SimpleUser>::new()));
        let mut app = test::init_service(
            App::new().data(AuthState { user_repo })
                .route("/register", post().to(register::<SimpleUser>))
        ).await;
        let email = String::from("test@example.com");
        let password1 = String::from("p@ssword");
        let password2 = String::from("p@ssword");
        let dto = make_register_dto(email, password1, password2);
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        let req = test::TestRequest::post().uri("/register").set_json(&dto).to_request();
        let resp = test::call_service(&mut app, req).await;
        let body = get_body(&resp);
        assert!(body.contains("User already exists: test@example.com"));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
