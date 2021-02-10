//! Simple reference implementation for how you might want to create your
//! own user, including Validators for the DTOs.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;
use validator_derive::Validate;

use crate::models::base::{Status, User};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimpleUser {
    pub id: String,
    pub email: String,
    pub password: String,
    pub status: Status,
}

#[derive(Validate, Deserialize, Serialize)]
pub struct RegisterSimpleUser {
    #[validate(email, length(max = 100))]
    pub email: String,
    #[validate(must_match = "password2", length(min = 8, max = 100))]
    pub password1: String,
    pub password2: String,
}

#[derive(Validate, Deserialize, Serialize)]
pub struct UpdateSimpleUser {
    #[validate(email, length(max = 100))]
    pub email: String,
}

impl SimpleUser {
    pub fn new(email: String, password: String) -> SimpleUser {
        let id = Uuid::new_v4().to_string();
        let status = Status::Unconfirmed;
        SimpleUser {
            id,
            email,
            password,
            status,
        }
    }
}

impl User for SimpleUser {
    type Key = String;
    type Id = String;

    fn key(&self) -> &Self::Key {
        &self.email
    }
    fn id(&self) -> &Self::Id {
        &self.id
    }
    fn email(&self) -> &str {
        &self.email
    }
    fn status(&self) -> &Status {
        &self.status
    }
    fn password(&self) -> &str {
        self.password.as_str()
    }

    fn key_field() -> &'static str {
        "email"
    }

    fn id_field() -> &'static str {
        "id"
    }

    fn password_field() -> &'static str {
        "password"
    }

    fn status_field() -> &'static str {
        "status"
    }

    fn set_status(&mut self, status: Status) {
        self.status = status;
    }

    fn set_password(&mut self, password: String) {
        self.password = password;
    }

    fn generate_id() -> Self::Id {
        Uuid::new_v4().to_string()
    }

    type RegisterDto = RegisterSimpleUser;

    fn from(registration: Self::RegisterDto) -> Self {
        SimpleUser::new(registration.email, registration.password1)
    }

    type UpdateDto = UpdateSimpleUser;
    fn update(&mut self, update: Self::UpdateDto) {
        self.email = update.email;
    }
}
