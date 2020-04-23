use crate::repos::base::UserRepo;
use crate::models::base::User;
use crate::emails::EmailConfig;

pub struct AppConfig<T, U>
    where
        T: User,
        U: UserRepo<T> {
    pub user_repo: U::Config,
    pub sender: EmailConfig,
}

impl<T, U> Clone for AppConfig<T, U>
    where T: User, U: UserRepo<T> {
        fn clone(&self) -> AppConfig<T, U> {
            AppConfig {
                user_repo: self.user_repo.clone(),
                sender: self.sender.clone(),
            }
        }
}
