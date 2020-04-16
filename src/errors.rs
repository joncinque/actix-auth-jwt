use actix_web::HttpResponse;
use actix_web::error::ResponseError;
use actix_web::http::{header, StatusCode};
use failure::Fail;
use validator::{ValidationError, ValidationErrors};

#[derive(Fail, Debug)]
pub enum AuthApiError {
    #[fail(display = "An internal error occurred.  Please try again later.")]
    InternalError,
    #[fail(display = "Validation errors on field(s): {}\n{}", fields, errors)]
    ValidationErrors { fields: String, errors: String },
    #[fail(display = "User not found for key: {}", key)]
    NotFound { key: String },
    #[fail(display = "User already exists: {}", key)]
    AlreadyExists { key: String },
    #[fail(display = "Authentication credentials not provided or invalid")]
    Unauthenticated,
    #[fail(display = "User not authorized for operation")]
    Unauthorized,
}

fn into_str(error: &Vec<ValidationError>) -> String {
    error.iter().map(|e| format!("{}", e)).collect::<Vec<String>>().join("\n")
}

pub fn into_api_error(errors: ValidationErrors) -> AuthApiError {
    let field_errors = errors.field_errors();
    AuthApiError::ValidationErrors {
        fields: field_errors.keys().map(|f| f.to_string()).collect::<Vec<String>>().join(", "),
        errors: field_errors.values().map(|e| format!("{}", into_str(e))).collect::<Vec<String>>().join("\n"),
    }
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
            AuthApiError::ValidationErrors { .. } => StatusCode::BAD_REQUEST,
            AuthApiError::NotFound { .. } => StatusCode::BAD_REQUEST,
            AuthApiError::AlreadyExists { .. } => StatusCode::BAD_REQUEST,
            AuthApiError::Unauthenticated => StatusCode::UNAUTHORIZED,
            AuthApiError::Unauthorized => StatusCode::FORBIDDEN,
        }
    }
}
