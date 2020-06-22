//! Contains all data-transfer objects to be used by API routes

use serde::{Deserialize, Serialize};
use validator::Validate;
use validator_derive::Validate;

#[derive(Serialize, Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginUserResponse {
    pub bearer: String,
    pub refresh: String,
    pub user_id: String,
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
    pub email: String,
}

#[derive(Serialize, Deserialize)]
pub struct ResetPasswordConfirm {
    pub password1: String,
    pub password2: String,
}

#[derive(Serialize, Deserialize)]
pub struct ConfirmId {
    pub id: String,
}
