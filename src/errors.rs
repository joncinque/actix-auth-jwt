use actix_web::HttpResponse;
use actix_web::error::ResponseError;
use actix_web::http::{header, StatusCode};
use argon2::Error as Argon2Error;
use failure::Fail;
use lettre_email::error::Error as LettreError;
use rand::Error as RandError;
use validator::{ValidationError, ValidationErrors};
use mongodb::error::{ErrorKind, Error as MongoError};
use regex::Regex;

/// Domain-specific errors with any extra information required
#[derive(Fail, Debug, PartialEq)]
pub enum AuthApiError {
    #[fail(display = "An internal error occurred.  Please try again later.")]
    InternalError,
    #[fail(display = "Validation errors on field(s): {}\n{}", fields, errors)]
    ValidationErrors { fields: String, errors: String },
    #[fail(display = "User not found for key: {}", key)]
    NotFound { key: String },
    #[fail(display = "User already exists: {}", key)]
    AlreadyExists { key: String },
    #[fail(display = "One-time resource already used")]
    AlreadyUsed,
    #[fail(display = "Temporary authentication token expired")]
    TokenExpired,
    #[fail(display = "User awaiting confirmation: {}", key)]
    Unconfirmed { key: String },
    #[fail(display = "Authentication credentials not provided or invalid")]
    Unauthenticated,
    #[fail(display = "User not authorized for operation")]
    Unauthorized,
    #[fail(display = "Error with JWT")]
    JwtError,
    #[fail(display = "Configuration error on component: {}", key)]
    ConfigurationError { key: String },
}

fn into_str(error: &Vec<ValidationError>) -> String {
    error.iter().map(|e| format!("{}", e)).collect::<Vec<String>>().join("\n")
}

/// TODO change this to a From impl
pub fn from_validation_errors(errors: ValidationErrors) -> AuthApiError {
    let field_errors = errors.field_errors();
    AuthApiError::ValidationErrors {
        fields: field_errors.keys().map(|f| f.to_string()).collect::<Vec<String>>().join(", "),
        errors: field_errors.values().map(|e| format!("{}", into_str(e))).collect::<Vec<String>>().join("\n"),
    }
}

/// TODO change this to a From impl
pub fn from_argon_error(_error: Argon2Error) -> AuthApiError {
    AuthApiError::InternalError
}

/// TODO change this to a From impl
pub fn from_rand_error(_error: RandError) -> AuthApiError {
    AuthApiError::InternalError
}

/// TODO change this to a From impl
pub fn from_empty(_error: ()) -> AuthApiError {
    AuthApiError::InternalError
}

/// TODO change this to a From impl
pub fn from_lettre(_error: LettreError) -> AuthApiError {
    AuthApiError::InternalError
}

impl From<jsonwebtoken::errors::Error> for AuthApiError {
    fn from(_err: jsonwebtoken::errors::Error) -> AuthApiError {
        AuthApiError::JwtError
    }
}

const DUPLICATE_WRITE_ERROR: i32 = 11000;

impl From<MongoError> for AuthApiError {
    fn from(error: MongoError) -> AuthApiError {
        match error.kind.as_ref() {
            ErrorKind::WriteError(f) => {
                match f {
                    mongodb::error::WriteFailure::WriteError(we) => {
                        match we.code {
                            DUPLICATE_WRITE_ERROR => {
                                let re = Regex::new("dup key.*\"(.*)\"").unwrap();
                                println!("{}", &we.message);
                                match re.captures(&we.message) {
                                    None => AuthApiError::InternalError,
                                    Some(caps) => {
                                        let key = caps.get(1).map_or("", |m| m.as_str()).to_owned();
                                        AuthApiError::AlreadyExists { key }
                                    }
                                }
                            },
                            _ => AuthApiError::InternalError,
                        }
                    }
                    _ => AuthApiError::InternalError,
                }
            },
            _ => AuthApiError::InternalError,
        }
    }
}

impl From<bson::ser::Error> for AuthApiError {
    fn from(_err: bson::ser::Error) -> AuthApiError {
        AuthApiError::InternalError
    }
}

impl From<bson::de::Error> for AuthApiError {
    fn from(_err: bson::de::Error) -> AuthApiError {
        AuthApiError::InternalError
    }
}

/// Maps domain errors into something usable by REST APIs
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
            AuthApiError::AlreadyUsed { .. } => StatusCode::BAD_REQUEST,
            AuthApiError::TokenExpired { .. } => StatusCode::UNAUTHORIZED,
            AuthApiError::Unconfirmed { .. } => StatusCode::BAD_REQUEST,
            AuthApiError::Unauthenticated => StatusCode::UNAUTHORIZED,
            AuthApiError::Unauthorized => StatusCode::FORBIDDEN,
            AuthApiError::JwtError => StatusCode::UNAUTHORIZED,
            AuthApiError::ConfigurationError { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
