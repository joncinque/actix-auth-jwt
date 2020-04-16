use std::sync::Mutex;
use crate::models::base::User;
use crate::repos::base::UserRepo;

pub struct AuthState<T: User> {
    pub user_repo: Mutex<Box<dyn UserRepo<T>>>,
}
