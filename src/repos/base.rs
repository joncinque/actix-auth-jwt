//! General trait for the user repo, which could be contained in memory, in a
//! database, a flat file, whichever you prefer!
use async_trait::async_trait;
use std::time::SystemTime;

use crate::errors::AuthApiError;
use crate::models::base::User;

/// UserRepo contains all of the requirements for managing a user
#[async_trait]
pub trait UserRepo<U> where U: User {
    /// Initiate any connections to make the repo usable.  Assume that this is
    /// called before anything happens in the system.
    async fn start(&mut self) -> Result<(), AuthApiError>;
    /// Get a User based in the human-provided key, most useful on login
    async fn get_by_key(&self, key: &U::Key) -> Result<U, AuthApiError>;
    /// Get a User based on the machine-generated id, useful everywhere a User
    /// needs to be fetched from a JWT
    async fn get_by_id(&self, id: &U::Id) -> Result<U, AuthApiError>;

    /// Add a new User, returning Err if the key or id already exists
    async fn insert(&mut self, user: U) -> Result<(), AuthApiError>;
    /// Remove an existing User based on Id
    async fn remove(&mut self, id: &U::Id) -> Result<(), AuthApiError>;
    /// Update an existing User based on Id
    async fn update(&mut self, user: U) -> Result<(), AuthApiError>;
    /// Confirm the registration of a User, usually coming from an emailed link
    async fn confirm(&mut self, id: &U::Id) -> Result<(), AuthApiError>;

    /// Reset user password without being logged in, used for forgotten passwords.
    /// The time parameter is used to expire a reset requests later.
    async fn password_reset(&mut self, key: &U::Key, time: SystemTime) -> Result<String, AuthApiError>;
    /// Confirm the reset of the password, along with the new password.  If the
    /// provided time is more than 10 minutes after the initial request, the
    /// reset will fail.
    /// TODO allow for tweaking the 10 minute reset
    async fn password_reset_confirm(&mut self, id: &str, password: String, time: SystemTime) -> Result<(), AuthApiError>;
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use std::time::Duration;

    use crate::models::base::Status;
    use crate::models::simple::SimpleUser;

    async fn create_user<T: UserRepo<SimpleUser>>(email: &str, password: &str, repo: &mut T) -> <SimpleUser as User>::Id {
        let user = SimpleUser::new(email.to_owned(), password.to_owned());
        let id = user.id().clone();
        repo.insert(user).await.unwrap();
        repo.confirm(&id).await.unwrap();
        id
    }

    pub async fn get_created_user<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let id = create_user(&email, &password, &mut repo).await;
        let user = repo.get_by_key(&email).await.unwrap();
        assert_eq!(email, user.email());
        assert_eq!(password, user.password());
        assert_eq!(id, *user.id());
        let user = repo.get_by_id(&id).await.unwrap();
        assert_eq!(email, user.email());
        assert_eq!(password, user.password());
        assert_eq!(id, *user.id());
    }

    pub async fn fail_double_create_user<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
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


    pub async fn get_user<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
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

    pub async fn fail_get_user<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
        let email = String::from("user@example.com");
        let err = repo.get_by_key(&email).await.unwrap_err();
        assert!(matches!(err, AuthApiError::NotFound { .. }));
        let id = String::from("unknown_id");
        let err = repo.get_by_id(&id).await.unwrap_err();
        assert!(matches!(err, AuthApiError::NotFound { .. }));
    }

    pub async fn fail_remove_user<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
        let id: <SimpleUser as User>::Id = String::from("some-unknown-id");
        let err = repo.remove(&id).await.unwrap_err();
        if let AuthApiError::NotFound { key } = err {
            assert_eq!(key, id);
        } else {
            panic!("Wrong error type");
        }
    }

    pub async fn remove_user<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let id = create_user(&email, &password, &mut repo).await;
        repo.remove(&id).await.unwrap();
        let err = repo.get_by_key(&email).await.unwrap_err();
        assert!(matches!(err, AuthApiError::NotFound { .. }));
    }

    pub async fn fail_update_user<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
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

    pub async fn update_user<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
        let email = String::from("user@example.com");
        let password = String::from("p@ssword");
        let id = create_user(&email, &password, &mut repo).await;
        let mut user = repo.get_by_key(&email).await.unwrap().clone();
        let password2 = String::from("p@ssword2");
        user.password = password2.clone();
        repo.update(user).await.unwrap();
        let user = repo.get_by_key(&email).await.unwrap().clone();
        assert_eq!(password2, user.password);
        assert_eq!(id, user.id);
        assert_eq!(email, user.email);
    }

    pub async fn confirm_user<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
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
        assert_eq!(id, user.id);
        assert_eq!(email, user.email);
        assert_eq!(password, user.password);
    }

    pub async fn fail_insert_user_exists_unconfirmed<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
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

    pub async fn fail_insert_user_exists_confirmed<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
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

    pub async fn password_reset<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
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

    pub async fn fail_password_reset_no_id<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
        let now = SystemTime::now();
        let email = String::from("user@example.com");
        let err = repo.password_reset(&email, now).await.unwrap_err();
        if let AuthApiError::NotFound { key } = err {
            assert_eq!(key, email);
        } else {
            panic!("Wrong error type");
        }
    }

    pub async fn fail_password_reset_no_user<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
        let now = SystemTime::now();
        let email = String::from("user@example.com");
        let err = repo.password_reset(&email, now).await.unwrap_err();
        if let AuthApiError::NotFound { key } = err {
            assert_eq!(key, email);
        } else {
            panic!("Wrong error type");
        }
    }

    pub async fn fail_password_reset_confirm_no_id<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
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

    pub async fn fail_password_reset_confirm_too_late<T: UserRepo<SimpleUser>>(mut repo: T) {
        repo.start().await.unwrap();
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
