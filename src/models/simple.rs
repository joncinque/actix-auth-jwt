use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;
use validator_derive::Validate;

use crate::models::base::{User, Status};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimpleUser {
    pub userid: String,
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

#[derive(Validate, Deserialize, Serialize)]
pub struct UpdateSimpleUserPassword {
    #[validate(email, length(max = 100))]
    pub email: String,
    pub old_password: String,
    #[validate(must_match = "new_password2", length(min = 8, max = 100))]
    pub new_password1: String,
    pub new_password2: String,
}

impl SimpleUser {
    pub fn new(email: String, password: String) -> SimpleUser {
        let userid = Uuid::new_v4().to_string();
        let status = Status::Unconfirmed;
        SimpleUser {
            userid,
            email,
            password,
            status,
        }
    }
}

impl User for SimpleUser {
    type Key = String;
    type Id = String;

    fn key(&self) -> &Self::Key { &self.email }
    fn id(&self) -> &Self::Id { &self.userid }
    fn email(&self) -> &str { &self.email }
    fn status(&self) -> &Status { &self.status }
    fn password(&self) -> &str { self.password.as_str() }

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
    }

    type UpdatePasswordDto = UpdateSimpleUserPassword;
    fn update_password(&mut self, update_password: Self::UpdatePasswordDto) {
    }
}
