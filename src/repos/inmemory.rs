use async_trait::async_trait;
use std::collections::hash_map::{HashMap, Entry};

use crate::errors::AuthApiError;
use crate::repos::base::UserRepo;
use crate::models::base::{User, Status};

pub struct InMemoryUserRepo<T>
    where T: User {
    users: HashMap<T::Key, T>,
    unconfirmed_users: HashMap<T::Id, T::Key>,
    password_resets: HashMap<T::Id, T::Key>,
}

impl<T> InMemoryUserRepo<T>
    where T: User {
    pub fn empty() -> Self {
        let users = HashMap::new();
        let unconfirmed_users = HashMap::new();
        let password_resets = HashMap::new();
        InMemoryUserRepo {
            users,
            unconfirmed_users,
            password_resets,
        }
    }
}

#[async_trait]
impl<T> UserRepo<T> for InMemoryUserRepo<T>
    where T: User {

    type Config = ();

    fn new(_config: &Self::Config) -> Self {
        Self::empty()
    }

    async fn get<'a>(&'a self, key: &T::Key) -> Option<&'a T> {
        self.users.get(key)
    }

    async fn insert(&mut self, user: T) -> Result<(), AuthApiError> {
        let key = user.key().clone();
        match self.users.entry(key) {
            Entry::Occupied(e) => Err(
                AuthApiError::AlreadyExists { key: format!("{}", e.key()) }
            ),
            Entry::Vacant(e) => {
                e.insert(user);
                Ok(())
            }
        }
    }

    async fn insert_unconfirmed(&mut self, user: T) -> Result<T::Id, AuthApiError> {
        let key = user.key().clone();
        let id = user.id().clone();
        let status = user.status().clone();
        {
            if let Err(err) = self.insert(user).await {
                return Err(err)
            }
        }
        if status == Status::Unconfirmed {
            match self.unconfirmed_users.entry(id) {
                Entry::Occupied(e) => Err(
                    AuthApiError::AlreadyExists { key: format!("{}", e.key()) }
                ),
                Entry::Vacant(e) => {
                    let id = e.key().clone();
                    e.insert(key);
                    Ok(id)
                }
            }
        } else {
            match self.users.get(&key) {
                Some(e) => Ok(e.id().clone()),
                None => Err(AuthApiError::NotFound { key: format!("{}", key) }),
            }
        }
    }

    async fn confirm(&mut self, id: &T::Id) -> Result<(), AuthApiError> {
        let id = id.clone();
        match self.unconfirmed_users.entry(id) {
            Entry::Occupied(e) => {
                let (_, key) = e.remove_entry();
                match self.users.entry(key) {
                    Entry::Occupied(mut e) => {
                        Ok(e.get_mut().set_status(Status::Confirmed))
                    },
                    Entry::Vacant(e) => {
                        let key = format!("{}", e.into_key());
                        Err(AuthApiError::NotFound { key })
                    }
                }
            },
            Entry::Vacant(e) => {
                let key = format!("{}", e.into_key());
                Err(AuthApiError::NotFound { key })
            },
        }
    }

    async fn remove(&mut self, key: &T::Key) -> Result<T, AuthApiError> {
        let key = key.clone();
        match self.users.remove(&key) {
            Some(v) => Ok(v),
            None => Err(AuthApiError::NotFound { key: format!("{}", key) })
        }
    }

    async fn update(&mut self, user: T) -> Result<(), AuthApiError> {
        let key = user.key().clone();
        match self.users.entry(key) {
            Entry::Occupied(mut e) => {
                e.insert(user);
                Ok(())
            },
            Entry::Vacant(e) => Err(AuthApiError::NotFound { key: format!("{}", e.key()) }),
        }
    }

    async fn password_reset(&mut self, key: &T::Key) -> Result<T::Id, AuthApiError> {
        let reset_id = T::generate_id();
        Ok(reset_id)
    }

    async fn password_reset_confirm(&mut self, id: &T::Id, password: &str) -> Result<(), AuthApiError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::simple::SimpleUser;

    #[actix_rt::test]
    async fn create_user() {
        let mut repo = InMemoryUserRepo::empty();
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
        let mut repo = InMemoryUserRepo::empty();
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
        let mut repo = InMemoryUserRepo::empty();
        let email: <SimpleUser as User>::Key = String::from("user@example.com");
        let password = String::from("p@ssword");
        let user = SimpleUser::new(email.clone(), password.clone());
        repo.insert(user).await.unwrap();
        let user = repo.get(&email).await.unwrap();
        assert_eq!(email, user.email);
        assert_eq!(password, user.password);
    }

    #[actix_rt::test]
    async fn fail_get_user() {
        let repo = InMemoryUserRepo::<SimpleUser>::empty();
        let email = String::from("user@example.com");
        let user = repo.get(&email).await;
        assert!(user.is_none());
    }

    #[actix_rt::test]
    async fn fail_remove_user() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::empty();
        let email: <SimpleUser as User>::Key = String::from("user@example.com");
        let err = repo.remove(&email).await.unwrap_err();
        if let AuthApiError::NotFound { key } = err {
            assert_eq!(key, email);
        } else {
            panic!("Wrong error type");
        }
    }

    #[actix_rt::test]
    async fn remove_user() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::empty();
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
        let mut repo = InMemoryUserRepo::<SimpleUser>::empty();
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
        let mut repo = InMemoryUserRepo::<SimpleUser>::empty();
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

    #[actix_rt::test]
    async fn confirm_user() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::empty();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let key;
        {
            let user = SimpleUser::new(email.clone(), password.clone());
            key = String::from(repo.insert_unconfirmed(user).await.unwrap());
            assert_ne!(String::new(), key);
        }
        {
            let user = repo.get(&email).await.unwrap();
            assert_eq!(Status::Unconfirmed, *user.status());
        }
        repo.confirm(&key).await.unwrap();
        let user = repo.get(&email).await.unwrap();
        assert_eq!(Status::Confirmed, *user.status());
        assert_eq!(key, user.userid);
        assert_eq!(email, user.email);
        assert_eq!(password, user.password);
    }

    #[actix_rt::test]
    async fn fail_insert_user_exists_unconfirmed() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::empty();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        {
            let user = SimpleUser::new(email.clone(), password.clone());
            let key = String::from(repo.insert_unconfirmed(user).await.unwrap());
            assert_ne!(String::new(), key);
        }
        {
            let user = SimpleUser::new(email.clone(), password.clone());
            let err = repo.insert_unconfirmed(user).await.unwrap_err();
            if let AuthApiError::AlreadyExists { key } = err {
                assert_eq!(key, email);
            } else {
                panic!("Wrong error type");
            }
        }
    }

    #[actix_rt::test]
    async fn fail_insert_user_exists_confirmed() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::empty();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        {
            let user = SimpleUser::new(email.clone(), password.clone());
            let key = String::from(repo.insert_unconfirmed(user).await.unwrap());
            assert_ne!(String::new(), key);
            repo.confirm(&key).await.unwrap();
        }
        {
            let user = SimpleUser::new(email.clone(), password.clone());
            let err = repo.insert_unconfirmed(user).await.unwrap_err();
            if let AuthApiError::AlreadyExists { key } = err {
                assert_eq!(key, email);
            } else {
                panic!("Wrong error type");
            }
        }
    }

    #[actix_rt::test]
    async fn password_reset() {
        let mut repo = InMemoryUserRepo::<SimpleUser>::empty();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        {
            let user = SimpleUser::new(email.clone(), password.clone());
            let key = String::from(repo.insert_unconfirmed(user).await.unwrap());
            assert_ne!(String::new(), key);
            repo.confirm(&key).await.unwrap();
        }
    }
}
