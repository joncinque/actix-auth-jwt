//! Contains all data-transfer objects to be used by API routes

use {
    crate::jwts::base::JwtStatus,
    serde::{Deserialize, Serialize},
    validator::Validate,
};

#[derive(Serialize, Deserialize)]
pub struct LoginUser {
    pub key: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginUserResponse {
    pub bearer: String,
    pub refresh: String,
    pub user_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshToken {
    pub refresh: String,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshTokenResponse {
    pub bearer: String,
    pub refresh: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenStatus {
    pub token: String,
}

#[derive(Serialize, Deserialize)]
pub struct TokenStatusResponse {
    pub status: JwtStatus,
}

#[derive(Validate, Serialize, Deserialize)]
pub struct UpdatePassword {
    pub old_password: String,
    #[validate(must_match = "new_password2", length(min = 8, max = 100))]
    pub new_password1: String,
    pub new_password2: String,
}

#[derive(Serialize, Deserialize)]
pub struct ResetPassword {
    pub key: String,
}

#[derive(Validate, Serialize, Deserialize)]
pub struct ResetPasswordConfirm {
    #[validate(must_match = "password2", length(min = 8, max = 100))]
    pub password1: String,
    pub password2: String,
}

#[derive(Serialize, Deserialize)]
pub struct ConfirmId {
    pub id: String,
}
