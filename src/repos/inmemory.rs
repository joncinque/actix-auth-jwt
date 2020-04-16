use async_trait::async_trait;
use std::collections::hash_map::{HashMap, Entry};

use crate::errors::AuthApiError;
use crate::repos::base::UserRepo;
use crate::models::base::User;

pub struct InMemoryUserRepo<T> {
    users: HashMap<String, T>,
}

impl<T> InMemoryUserRepo<T> {
    pub fn new() -> InMemoryUserRepo<T> {
        let users = HashMap::new();
        InMemoryUserRepo {
            users
        }
    }
}

#[async_trait]
impl<T> UserRepo<T> for InMemoryUserRepo<T>
    where T: User {
    async fn get<'a>(&'a self, key: &str) -> Option<&'a T> {
        self.users.get(key)
    }

    async fn insert(&mut self, user: T) -> Result<(), AuthApiError> {
        let key = String::from(user.get_key());
        match self.users.entry(key) {
            Entry::Occupied(e) => Err(
                AuthApiError::AlreadyExists { key: String::from(e.key()) }
            ),
            Entry::Vacant(e) => {
                e.insert(user);
                Ok(())
            }
        }
    }

    async fn remove(&mut self, key: &str) -> Result<T, AuthApiError> {
        let key = String::from(key);
        match self.users.remove(&key) {
            Some(v) => Ok(v),
            None => Err(AuthApiError::NotFound { key: key })
        }
    }

    async fn update(&mut self, user: T) -> Result<(), AuthApiError> {
        let key = String::from(user.get_key());
        match self.users.entry(key) {
            Entry::Occupied(mut e) => {
                e.insert(user);
                Ok(())
            },
            Entry::Vacant(e) => Err(AuthApiError::NotFound { key: String::from(e.key()) }),
        }
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
        let userid = user.userid.clone();
        repo.insert(user).await.unwrap();
        let user = repo.get(&email).await.unwrap();
        assert_eq!(email, user.email);
        assert_eq!(password, user.password);
        assert_eq!(userid, user.userid);
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
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let user = SimpleUser::new(email.clone(), password.clone());
        repo.insert(user).await.unwrap();
        let user = repo.get(email.as_str()).await.unwrap();
        assert_eq!(email, user.email);
        assert_eq!(password, user.password);
    }

    #[actix_rt::test]
    async fn fail_get_user() {
        let repo = InMemoryUserRepo::<SimpleUser>::new();
        let email = String::from("user@example.com");
        let user = repo.get(&email).await;
        assert!(user.is_none());
    }

    #[actix_rt::test]
    async fn fail_remove_user() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::new();
        let email = String::from("user@example.com");
        let err = repo.remove(email.as_str()).await.unwrap_err();
        if let AuthApiError::NotFound { key } = err {
            assert_eq!(key, email);
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
        let user = repo.get(&email).await.unwrap();
        let userid = user.userid.to_string();
        let user = repo.remove(&email).await.unwrap();
        assert_eq!(email, user.email);
        assert_eq!(password, user.password);
        assert_eq!(userid, user.userid);
    }

    #[actix_rt::test]
    async fn fail_update_user() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::new();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let user = SimpleUser::new(email.clone(), password.clone());
        let err = repo.update(user).await.unwrap_err();
        if let AuthApiError::NotFound { key } = err {
            assert_eq!(key, email);
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
        let mut user = repo.get(&email).await.unwrap().clone();
        let password2 = String::from("p@ssword2");
        user.password = password2.clone();
        repo.update(user).await.unwrap();
        let user = repo.get(&email).await.unwrap().clone();
        assert_eq!(password2, user.password);
        assert_eq!(userid, user.userid);
        assert_eq!(email, user.email);
    }
}

