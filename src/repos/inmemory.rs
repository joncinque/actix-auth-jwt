//! Sample in-memory implementation of UserRepo

use async_trait::async_trait;
use uuid::Uuid;
use std::collections::hash_map::{HashMap, Entry};
use std::time::{Duration, SystemTime};

use crate::errors::AuthApiError;
use crate::repos::base::UserRepo;
use crate::models::base::{User, Status};

pub struct InMemoryUserRepo<U>
    where U: User {
    users_by_id: HashMap<U::Id, U>,
    users_by_key: HashMap<U::Key, U::Id>,
    password_resets: HashMap<String, (SystemTime, U::Id)>,
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

impl<U> Default for InMemoryUserRepo<U>
where U: User {
    fn default() -> Self {
        InMemoryUserRepo::new()
    }
}

#[async_trait]
impl<U> UserRepo<U> for InMemoryUserRepo<U>
    where U: User {

    async fn get_by_key<'a>(&'a self, key: &U::Key) -> Result<&'a U, AuthApiError> {
        let user_id = self.users_by_key.get(key).ok_or(AuthApiError::NotFound { key: format!("{}", key) })?;
        self.get_by_id(user_id).await
    }

    async fn get_by_id<'a>(&'a self, id: &U::Id) -> Result<&'a U, AuthApiError> {
        let user = self.users_by_id.get(id).ok_or(AuthApiError::NotFound { key: format!("{}", id) })?;
        match *user.status() {
            Status::Confirmed => Ok(user),
            Status::Unconfirmed => Err(AuthApiError::Unconfirmed { key: format!("{}", id) }),
            Status::Suspended => Err(AuthApiError::Unauthorized),
            Status::Deleted => Err(AuthApiError::NotFound { key: format!("{}", id) }),
        }
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
                let old_user = e.get();
                if old_user.key() != user.key() {
                    if let Some(id) = self.users_by_key.remove(old_user.key()) {
                        self.users_by_key.insert(user.key().clone(), id);
                    }
                }
                e.insert(user);
                Ok(())
            },
            Entry::Vacant(e) => Err(AuthApiError::NotFound { key: format!("{}", e.key()) }),
        }
    }

    async fn password_reset(&mut self, key: &U::Key, time: SystemTime) -> Result<String, AuthApiError> {
        let user_id = self.get_by_key(key).await.map(|user| user.id().clone())?;
        let reset_id = Uuid::new_v4().to_string();
        self.password_resets.insert(reset_id.clone(), (time, user_id));
        Ok(reset_id)
    }

    async fn password_reset_confirm(&mut self, reset_id: &str, password: String, time: SystemTime) -> Result<(), AuthApiError> {
        let time_id_tuple = self.password_resets.remove(reset_id)
            .ok_or(AuthApiError::NotFound { key: reset_id.to_owned() })?;
        let reset_time = time_id_tuple.0;
        let user_id = time_id_tuple.1;
        if (reset_time + Duration::from_secs(10 * 60)) < time {
            Err(AuthApiError::TokenExpired)
        } else {
            let user = self.get_by_id(&user_id).await?;
            let mut user = user.clone();
            user.set_password(password);
            self.update(user).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::simple::SimpleUser;

    async fn create_user(email: &str, password: &str, repo: &mut InMemoryUserRepo<SimpleUser>) -> <SimpleUser as User>::Id {
        let user = SimpleUser::new(email.to_owned(), password.to_owned());
        let id = user.id().clone();
        repo.insert(user).await.unwrap();
        repo.confirm(&id).await.unwrap();
        id
    }

    #[actix_rt::test]
    async fn get_created_user() {
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let id = create_user(&email, &password, &mut repo).await;
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
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
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
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
        let email: <SimpleUser as User>::Key = String::from("user@example.com");
        let password = String::from("p@ssword");
        let id = create_user(&email, &password, &mut repo).await;
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
        let err = repo.get_by_key(&email).await.unwrap_err();
        assert!(matches!(err, AuthApiError::NotFound { .. }));
        let id = String::from("unknown_id");
        let err = repo.get_by_id(&id).await.unwrap_err();
        assert!(matches!(err, AuthApiError::NotFound { .. }));
    }

    #[actix_rt::test]
    async fn fail_remove_user() {
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
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
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let id = create_user(&email, &password, &mut repo).await;
        let user = repo.remove(&id).await.unwrap();
        assert_eq!(email, user.email);
        assert_eq!(password, user.password);
        assert_eq!(id, *user.id());
    }

    #[actix_rt::test]
    async fn fail_update_user() {
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
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
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let id = create_user(&email, &password, &mut repo).await;
        let mut user = repo.get_by_key(&email).await.unwrap().clone();
        let password2 = String::from("p@ssword2");
        user.password = password2.clone();
        repo.update(user).await.unwrap();
        let user = repo.get_by_key(&email).await.unwrap().clone();
        assert_eq!(password2, user.password);
        assert_eq!(id, user.userid);
        assert_eq!(email, user.email);
    }

    #[actix_rt::test]
    async fn confirm_user() {
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let id;
        {
            let user = SimpleUser::new(email.clone(), password.clone());
            id = user.id().clone();
            repo.insert(user).await.unwrap();
        }
        {
            let err = repo.get_by_key(&email).await.unwrap_err();
            assert!(matches!(err, AuthApiError::Unconfirmed { .. }));
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
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
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
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        create_user(&email, &password, &mut repo).await;
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
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        create_user(&email, &password, &mut repo).await;

        let now = SystemTime::now();
        let reset_id = repo.password_reset(&email, now).await.unwrap();
        let new_password = String::from("newp@ssword");
        repo.password_reset_confirm(&reset_id, new_password.clone(), now).await.unwrap();

        let user = repo.get_by_key(&email).await.unwrap();
        assert_eq!(user.password, new_password);
    }

    #[actix_rt::test]
    async fn fail_password_reset_no_id() {
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
        let now = SystemTime::now();
        let email = String::from("user@example.com");
        let err = repo.password_reset(&email, now).await.unwrap_err();
        if let AuthApiError::NotFound { key } = err {
            assert_eq!(key, email);
        } else {
            panic!("Wrong error type");
        }
    }

    #[actix_rt::test]
    async fn fail_password_reset_no_user() {
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
        let now = SystemTime::now();
        let email = String::from("user@example.com");
        let err = repo.password_reset(&email, now).await.unwrap_err();
        if let AuthApiError::NotFound { key } = err {
            assert_eq!(key, email);
        } else {
            panic!("Wrong error type");
        }
    }

    #[actix_rt::test]
    async fn fail_password_reset_confirm_no_id() {
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
        let now = SystemTime::now();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let err = repo.password_reset_confirm(&email, password, now).await.unwrap_err();
        if let AuthApiError::NotFound { key } = err {
            assert_eq!(key, email);
        } else {
            panic!("Wrong error type");
        }
    }

    #[actix_rt::test]
    async fn fail_password_reset_confirm_too_late() {
        let mut repo: InMemoryUserRepo<SimpleUser> = Default::default();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        create_user(&email, &password, &mut repo).await;

        let now = SystemTime::now();
        let reset_id = repo.password_reset(&email, now).await.unwrap();
        let new_password = String::from("newp@ssword");
        let too_late = now + Duration::from_secs(60 * 60);
        let err = repo.password_reset_confirm(&reset_id, new_password, too_late).await.unwrap_err();
        if let AuthApiError::TokenExpired = err {
        } else {
            println!("{}", err);
            panic!("Wrong error type");
        }
    }
}
