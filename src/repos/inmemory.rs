use async_trait::async_trait;
use std::collections::hash_map::{HashMap, Entry};

use crate::errors::AuthApiError;
use crate::repos::base::UserRepo;
use crate::models::base::{User, Status};

pub struct InMemoryUserRepo<U>
    where U: User {
    users_by_id: HashMap<U::Id, U>,
    users_by_key: HashMap<U::Key, U::Id>,
    password_resets: HashMap<U::Id, U::Id>,
}

impl<U> InMemoryUserRepo<U>
    where U: User {
    pub fn new() -> Self {
        let users_by_key = HashMap::new();
        let users_by_id = HashMap::new();
        let password_resets = HashMap::new();
        InMemoryUserRepo {
            users_by_key,
            users_by_id,
            password_resets,
        }
    }
}

#[async_trait]
impl<U> UserRepo<U> for InMemoryUserRepo<U>
    where U: User {

    type Config = ();

    fn from(_config: &Self::Config) -> Self {
        Self::new()
    }

    async fn get_by_key<'a>(&'a self, key: &U::Key) -> Option<&'a U> {
        match self.users_by_key.get(key) {
            None => None,
            Some(id) => self.get_by_id(id).await,
        }
    }

    async fn get_by_id<'a>(&'a self, id: &U::Id) -> Option<&'a U> {
        self.users_by_id.get(id)
    }

    async fn insert(&mut self, user: U) -> Result<(), AuthApiError> {
        let key = user.key().clone();
        match self.users_by_key.entry(key) {
            Entry::Occupied(e) => Err(
                AuthApiError::AlreadyExists { key: format!("{}", e.key()) }
            ),
            Entry::Vacant(e) => {
                let id = user.id().clone();
                match self.users_by_id.entry(id) {
                    Entry::Occupied(f) => Err(
                        AuthApiError::AlreadyExists { key: format!("{}", f.key()) }
                    ),
                    Entry::Vacant(f) => {
                        e.insert(user.id().clone());
                        f.insert(user);
                        Ok(())
                    }
                }
            }
        }
    }

    async fn confirm(&mut self, id: &U::Id) -> Result<(), AuthApiError> {
        let id = id.clone();
        match self.users_by_id.entry(id) {
            Entry::Occupied(mut e) => {
                let user = e.get_mut();
                if *user.status() == Status::Unconfirmed {
                    Ok(user.set_status(Status::Confirmed))
                } else {
                    Err(AuthApiError::AlreadyUsed)
                }
            },
            Entry::Vacant(e) => {
                let key = format!("{}", e.into_key());
                Err(AuthApiError::NotFound { key })
            },
        }
    }

    async fn remove(&mut self, id: &U::Id) -> Result<U, AuthApiError> {
        match self.users_by_id.remove(&id) {
            Some(v) => {
                self.users_by_key.remove(v.key());
                Ok(v)
            },
            None => {
                Err(AuthApiError::NotFound { key: format!("{}", id) })
            }
        }
    }

    async fn update(&mut self, user: U) -> Result<(), AuthApiError> {
        let id = user.id().clone();
        match self.users_by_id.entry(id) {
            Entry::Occupied(mut e) => {
                e.insert(user);
                Ok(())
            },
            Entry::Vacant(e) => Err(AuthApiError::NotFound { key: format!("{}", e.key()) }),
        }
    }

    async fn password_reset(&mut self, key: &U::Key) -> Result<U::Id, AuthApiError> {
        let reset_id = U::generate_id();
        Ok(reset_id)
    }

    async fn password_reset_confirm(&mut self, id: &U::Id, password: &str) -> Result<(), AuthApiError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::simple::SimpleUser;

    #[actix_rt::test]
    async fn create_user() {
        let mut repo = InMemoryUserRepo::new();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let user = SimpleUser::new(email.clone(), password.clone());
        let id = user.id().clone();
        repo.insert(user).await.unwrap();
        let user = repo.get_by_key(&email).await.unwrap();
        assert_eq!(email, user.email);
        assert_eq!(password, user.password);
        assert_eq!(id, *user.id());
        let user = repo.get_by_id(&id).await.unwrap();
        assert_eq!(email, user.email);
        assert_eq!(password, user.password);
        assert_eq!(id, *user.id());
    }

    #[actix_rt::test]
    async fn fail_double_create_user() {
        let mut repo = InMemoryUserRepo::new();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let user1 = SimpleUser::new(email.clone(), password.clone());
        repo.insert(user1).await.unwrap();
        let user2 = SimpleUser::new(email.clone(), password.clone());
        let err = repo.insert(user2).await.unwrap_err();
        if let AuthApiError::AlreadyExists { key } = err {
            assert_eq!(key, email);
        } else {
            panic!("Wrong error type");
        }
    }

    #[actix_rt::test]
    async fn get_user() {
        let mut repo = InMemoryUserRepo::new();
        let email: <SimpleUser as User>::Key = String::from("user@example.com");
        let password = String::from("p@ssword");
        let user = SimpleUser::new(email.clone(), password.clone());
        let id = user.id().clone();
        repo.insert(user).await.unwrap();
        let user = repo.get_by_key(&email).await.unwrap();
        assert_eq!(email, user.email);
        assert_eq!(password, user.password);
        let user = repo.get_by_id(&id).await.unwrap();
        assert_eq!(email, user.email);
        assert_eq!(password, user.password);
    }

    #[actix_rt::test]
    async fn fail_get_user() {
        let repo = InMemoryUserRepo::<SimpleUser>::new();
        let email = String::from("user@example.com");
        let user = repo.get_by_key(&email).await;
        assert!(user.is_none());
        let id = String::from("unknown_id");
        let user = repo.get_by_id(&id).await;
        assert!(user.is_none());
    }

    #[actix_rt::test]
    async fn fail_remove_user() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::new();
        let id: <SimpleUser as User>::Id = String::from("some-unknown-id");
        let err = repo.remove(&id).await.unwrap_err();
        if let AuthApiError::NotFound { key } = err {
            assert_eq!(key, id);
        } else {
            panic!("Wrong error type");
        }
    }

    #[actix_rt::test]
    async fn remove_user() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::new();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let user = SimpleUser::new(email.clone(), password.clone());
        repo.insert(user).await.unwrap();
        let user = repo.get_by_key(&email).await.unwrap();
        let id = user.id().clone();
        let user = repo.remove(&id).await.unwrap();
        assert_eq!(email, user.email);
        assert_eq!(password, user.password);
        assert_eq!(id, *user.id());
    }

    #[actix_rt::test]
    async fn fail_update_user() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::new();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let user = SimpleUser::new(email.clone(), password.clone());
        let id = user.id().clone();
        let err = repo.update(user).await.unwrap_err();
        if let AuthApiError::NotFound { key } = err {
            assert_eq!(key, id);
        } else {
            panic!("Wrong error type");
        }
    }

    #[actix_rt::test]
    async fn update_user() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::new();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let user = SimpleUser::new(email.clone(), password.clone());
        let userid = user.userid.clone();
        repo.insert(user).await.unwrap();
        let mut user = repo.get_by_key(&email).await.unwrap().clone();
        let password2 = String::from("p@ssword2");
        user.password = password2.clone();
        repo.update(user).await.unwrap();
        let user = repo.get_by_key(&email).await.unwrap().clone();
        assert_eq!(password2, user.password);
        assert_eq!(userid, user.userid);
        assert_eq!(email, user.email);
    }

    #[actix_rt::test]
    async fn confirm_user() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::new();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let id;
        {
            let user = SimpleUser::new(email.clone(), password.clone());
            id = user.id().clone();
            repo.insert(user).await.unwrap();
        }
        {
            let user = repo.get_by_key(&email).await.unwrap();
            assert_eq!(Status::Unconfirmed, *user.status());
        }
        repo.confirm(&id).await.unwrap();
        let user = repo.get_by_key(&email).await.unwrap();
        assert_eq!(Status::Confirmed, *user.status());
        assert_eq!(id, user.userid);
        assert_eq!(email, user.email);
        assert_eq!(password, user.password);
    }

    #[actix_rt::test]
    async fn fail_insert_user_exists_unconfirmed() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::new();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        {
            let user = SimpleUser::new(email.clone(), password.clone());
            repo.insert(user).await.unwrap();
        }
        {
            let user = SimpleUser::new(email.clone(), password.clone());
            let err = repo.insert(user).await.unwrap_err();
            if let AuthApiError::AlreadyExists { key } = err {
                assert_eq!(key, email);
            } else {
                panic!("Wrong error type");
            }
        }
    }

    #[actix_rt::test]
    async fn fail_insert_user_exists_confirmed() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::new();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        {
            let user = SimpleUser::new(email.clone(), password.clone());
            let id = user.id().clone();
            repo.insert(user).await.unwrap();
            repo.confirm(&id).await.unwrap();
        }
        {
            let user = SimpleUser::new(email.clone(), password.clone());
            let err = repo.insert(user).await.unwrap_err();
            if let AuthApiError::AlreadyExists { key } = err {
                assert_eq!(key, email);
            } else {
                panic!("Wrong error type");
            }
        }
    }

    #[actix_rt::test]
    async fn password_reset() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::new();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        {
            let user = SimpleUser::new(email.clone(), password.clone());
            let id = user.id().clone();
            repo.insert(user).await.unwrap();
            repo.confirm(&id).await.unwrap();
        }
    }
}
