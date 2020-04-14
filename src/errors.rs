use actix_web::HttpResponse;
use actix_web::error::ResponseError;
use actix_web::http::{header, StatusCode};
use failure::Fail;

#[derive(Fail, Debug)]
pub enum AuthApiError {
    #[fail(display = "An internal error occurred.  Please try again later.")]
    InternalError,
    #[fail(display = "Validation error on field: {}", field)]
    ValidationError { field: String },
    #[fail(display = "User not found for key: {}", key)]
    NotFound { key: String },
    #[fail(display = "User already exists: {}", key)]
    AlreadyExists { key: String },
    #[fail(display = "Authentication credentials not provided or invalid")]
    Unauthenticated,
    #[fail(display = "User not authorized for operation")]
    Unauthorized,
}

impl ResponseError for AuthApiError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .set_header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            AuthApiError::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            AuthApiError::ValidationError { .. } => StatusCode::BAD_REQUEST,
            AuthApiError::NotFound { .. } => StatusCode::BAD_REQUEST,
            AuthApiError::AlreadyExists { .. } => StatusCode::BAD_REQUEST,
            AuthApiError::Unauthenticated => StatusCode::UNAUTHORIZED,
            AuthApiError::Unauthorized => StatusCode::FORBIDDEN,
        }
    }
}
