use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct RegisterUser {
    email: String,
    password1: String,
    password2: String,
}

#[derive(Deserialize)]
pub struct LoginUser {
    email: String,
    password: String,
}
