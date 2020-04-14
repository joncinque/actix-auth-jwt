use crate::db::UserRepo;

pub struct AppState<'a, T> {
    pub user_repo: Box<dyn UserRepo<'a, T>>,
}
