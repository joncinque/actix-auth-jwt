use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;
use validator_derive::Validate;

use crate::models::base::User;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimpleUser {
    pub userid: String,
    pub email: String,
    pub password: String,
}

#[derive(Validate, Deserialize, Serialize)]
pub struct RegisterSimpleUser {
    #[validate(email, length(max = 100))]
    pub email: String,
    #[validate(must_match = "password2", length(min = 8, max = 100))]
    pub password1: String,
    #[validate(must_match = "password1")]
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
    #[validate(must_match = "new_password1")]
    pub new_password2: String,
}

impl SimpleUser {
    pub fn new(email: String, password: String) -> SimpleUser {
        let userid = Uuid::new_v4().to_string();
        SimpleUser {
            userid,
            email,
            password,
        }
    }
}

impl User for SimpleUser {
    fn get_key(&self) -> &str { self.email.as_str() }
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
