//! Sample in-memory implementation of UserRepo

use {
    crate::{
        errors::AuthApiError,
        models::base::{Status, User},
        repos::base::UserRepo,
    },
    async_trait::async_trait,
    std::{
        collections::hash_map::{Entry, HashMap},
        time::{Duration, SystemTime},
    },
    uuid::Uuid,
};

pub struct InMemoryUserRepo<U: User> {
    users_by_id: HashMap<U::Id, U>,
    users_by_key: HashMap<U::Key, U::Id>,
    password_resets: HashMap<String, (SystemTime, U::Id)>,
}

impl<U: User> InMemoryUserRepo<U> {
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

impl<U: User> Default for InMemoryUserRepo<U> {
    fn default() -> Self {
        InMemoryUserRepo::new()
    }
}

#[async_trait]
impl<U: User> UserRepo<U> for InMemoryUserRepo<U> {
    async fn start(&mut self) -> Result<(), AuthApiError> {
        Ok(())
    }

    async fn get_by_key(&self, key: &U::Key) -> Result<U, AuthApiError> {
        let user_id = self.users_by_key.get(key).ok_or(AuthApiError::NotFound {
            key: format!("{}", key),
        })?;
        self.get_by_id(user_id).await
    }

    async fn get_by_id(&self, id: &U::Id) -> Result<U, AuthApiError> {
        let user = self.users_by_id.get(id).ok_or(AuthApiError::NotFound {
            key: format!("{}", id),
        })?;
        match *user.status() {
            Status::Confirmed => Ok(user.clone()),
            Status::Unconfirmed => Err(AuthApiError::Unconfirmed {
                key: format!("{}", id),
            }),
            Status::Suspended => Err(AuthApiError::Unauthorized),
            Status::Deleted => Err(AuthApiError::NotFound {
                key: format!("{}", id),
            }),
        }
    }

    async fn insert(&mut self, user: U) -> Result<(), AuthApiError> {
        let key = user.key().clone();
        match self.users_by_key.entry(key) {
            Entry::Occupied(e) => Err(AuthApiError::AlreadyExists {
                key: format!("{}", e.key()),
            }),
            Entry::Vacant(e) => {
                let id = user.id().clone();
                match self.users_by_id.entry(id) {
                    Entry::Occupied(f) => Err(AuthApiError::AlreadyExists {
                        key: format!("{}", f.key()),
                    }),
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
                    user.set_status(Status::Confirmed);
                    Ok(())
                } else {
                    Err(AuthApiError::AlreadyUsed)
                }
            }
            Entry::Vacant(e) => {
                let key = format!("{}", e.into_key());
                Err(AuthApiError::NotFound { key })
            }
        }
    }

    async fn remove(&mut self, id: &U::Id) -> Result<(), AuthApiError> {
        match self.users_by_id.remove(id) {
            Some(v) => {
                self.users_by_key.remove(v.key());
                Ok(())
            }
            None => Err(AuthApiError::NotFound {
                key: format!("{}", id),
            }),
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
            }
            Entry::Vacant(e) => Err(AuthApiError::NotFound {
                key: format!("{}", e.key()),
            }),
        }
    }

    async fn password_reset(
        &mut self,
        key: &U::Key,
        time: SystemTime,
    ) -> Result<String, AuthApiError> {
        let user_id = self.get_by_key(key).await.map(|user| user.id().clone())?;
        let reset_id = Uuid::new_v4().to_string();
        self.password_resets
            .insert(reset_id.clone(), (time, user_id));
        Ok(reset_id)
    }

    async fn password_reset_confirm(
        &mut self,
        reset_id: &str,
        password: String,
        time: SystemTime,
    ) -> Result<(), AuthApiError> {
        let time_id_tuple =
            self.password_resets
                .remove(reset_id)
                .ok_or(AuthApiError::NotFound {
                    key: reset_id.to_owned(),
                })?;
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
    use crate::repos::base;

    #[actix_rt::test]
    async fn get_created_user() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::get_created_user(repo).await;
    }

    #[actix_rt::test]
    async fn fail_double_create_user() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::fail_double_create_user(repo).await;
    }

    #[actix_rt::test]
    async fn get_user() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::get_user(repo).await;
    }

    #[actix_rt::test]
    async fn fail_get_user() {
        let repo = InMemoryUserRepo::<SimpleUser>::new();
        base::tests::fail_get_user(repo).await;
    }

    #[actix_rt::test]
    async fn fail_remove_user() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::fail_remove_user(repo).await;
    }

    #[actix_rt::test]
    async fn remove_user() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::remove_user(repo).await;
    }

    #[actix_rt::test]
    async fn fail_update_user() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::fail_update_user(repo).await;
    }

    #[actix_rt::test]
    async fn update_user() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::update_user(repo).await;
    }

    #[actix_rt::test]
    async fn confirm_user() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::confirm_user(repo).await;
    }

    #[actix_rt::test]
    async fn fail_insert_user_exists_unconfirmed() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::fail_insert_user_exists_unconfirmed(repo).await;
    }

    #[actix_rt::test]
    async fn fail_insert_user_exists_confirmed() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::fail_insert_user_exists_confirmed(repo).await;
    }

    #[actix_rt::test]
    async fn password_reset() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::password_reset(repo).await;
    }

    #[actix_rt::test]
    async fn fail_password_reset_no_id() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::fail_password_reset_no_id(repo).await;
    }

    #[actix_rt::test]
    async fn fail_password_reset_no_user() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::fail_password_reset_no_user(repo).await;
    }

    #[actix_rt::test]
    async fn fail_password_reset_confirm_no_id() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::fail_password_reset_confirm_no_id(repo).await;
    }

    #[actix_rt::test]
    async fn fail_password_reset_confirm_too_late() {
        let repo: InMemoryUserRepo<SimpleUser> = Default::default();
        base::tests::fail_password_reset_confirm_too_late(repo).await;
    }
}
