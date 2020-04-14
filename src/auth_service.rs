use actix_web::{
    get,
    post,
    HttpResponse,
    Responder,
    Scope,
};
use actix_web::web::{Data, Json};

use crate::dtos::RegisterUser;
use crate::app_state::AppState;

#[get("/")]
async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

#[post("/register")]
async fn register<'a, T>(user: Json<RegisterUser>, data: Data<AppState<'a, T>>) -> impl Responder {
    HttpResponse::Ok().body("Hello, world!")
}

#[post("/login")]
async fn login() -> impl Responder {
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

pub fn make_auth_service<'a, T>(scope: Scope) -> Scope {
    scope.service(index)
        .service(register::<'a, T>)
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{
        test,
        App,
    };
    use actix_web::http::StatusCode;

    #[actix_rt::test]
    async fn index_ok() {
        let mut app = test::init_service(App::new().service(index)).await;
        let req = test::TestRequest::get().uri("/").to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
