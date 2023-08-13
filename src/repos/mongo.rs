//! MongoDB implementation of UserRepo, for actual production use

use {
    crate::{
        errors::AuthApiError,
        models::base::{Status, User},
        repos::base::UserRepo,
    },
    async_trait::async_trait,
    bson::{doc, Bson, Document},
    mongodb::{Client, Collection, Database},
    std::{
        time::SystemTime,
    },
};

pub struct MongoRepo<U: User> {
    client: Option<Client>,
    db: Option<Database>,
    coll: Option<Collection<U>>,
    uri: String,
    db_name: String,
    coll_name: String,
}

impl<U: User> MongoRepo<U> {
    pub fn new(uri: String, db_name: String, coll_name: String) -> MongoRepo<U> {
        let client = None;
        let db = None;
        let coll = None;
        Self {
            client,
            db,
            coll,
            uri,
            db_name,
            coll_name,
        }
    }

    fn get_user_collection(&self) -> Result<&Collection<U>, AuthApiError> {
        self.coll.as_ref().ok_or(AuthApiError::InternalError)
    }

    fn get_user_document(&self, user: &U) -> Result<Document, AuthApiError> {
        let serialized = bson::to_bson(user).map_err(|e| AuthApiError::from(e))?;

        match serialized {
            Bson::Document(v) => Ok(v),
            _ => Err(AuthApiError::ConfigurationError {
                key: "User not serializable".to_owned(),
            }),
        }
    }

    fn check_user_status(&self, user: U) -> Result<U, AuthApiError> {
        match *user.status() {
            Status::Confirmed => Ok(user),
            Status::Unconfirmed => Err(AuthApiError::Unconfirmed {
                key: format!("{}", user.key()),
            }),
            Status::Suspended => Err(AuthApiError::Unauthorized),
            Status::Deleted => Err(AuthApiError::NotFound {
                key: format!("{}", user.key()),
            }),
        }
    }

    /// Testing function to drop collection between test runs
    pub async fn drop(&self) -> Result<(), AuthApiError> {
        self.get_user_collection()
            .unwrap()
            .drop(None)
            .await
            .map_err(|e| AuthApiError::from(e))
    }
}

impl<U: User> Default for MongoRepo<U> {
    fn default() -> MongoRepo<U> {
        let uri = String::from("mongodb://localhost");
        let db_name = String::from("auth_jwt_test");
        let coll_name = String::from("users");
        Self::new(uri, db_name, coll_name)
    }
}

#[async_trait]
impl<U: User> UserRepo<U> for MongoRepo<U> {
    async fn start(&mut self) -> Result<(), AuthApiError> {
        let client = Client::with_uri_str(&self.uri)
            .await
            .map_err(|e| AuthApiError::from(e))?;
        let db = client.database(&self.db_name);
        let indexes = doc! {
            "createIndexes": self.coll_name.clone(),
            "indexes": [
                {
                    "key": { U::key_field(): 1, },
                    "name": U::key_field(),
                    "unique": true,
                },
                {
                    "key": { U::id_field(): 1, },
                    "name": U::id_field(),
                    "unique": true,
                },
            ],
        };
        db.run_command(indexes, None).await?;
        self.coll = Some(db.collection(&self.coll_name));
        self.client = Some(client);
        self.db = Some(db);
        Ok(())
    }

    async fn get_by_key(&self, key: &U::Key) -> Result<U, AuthApiError> {
        let coll = self.get_user_collection()?;
        let key = format!("{}", key);
        let user = coll
            .find_one(doc! { U::key_field(): key.clone() }, None)
            .await?
            .ok_or(AuthApiError::NotFound { key })?;
        self.check_user_status(user)
    }

    async fn get_by_id(&self, id: &U::Id) -> Result<U, AuthApiError> {
        let coll = self.get_user_collection()?;
        let key = format!("{}", id);
        let user = coll
            .find_one(doc! { U::id_field(): key.clone() }, None)
            .await?
            .ok_or(AuthApiError::NotFound { key })?;
        self.check_user_status(user)
    }

    async fn insert(&mut self, user: U) -> Result<(), AuthApiError> {
        let coll = self.get_user_collection()?;
        coll.insert_one(user, None)
            .await
            .map(|_r| ())
            .map_err(|e| AuthApiError::from(e))
    }

    async fn confirm(&mut self, id: &U::Id) -> Result<(), AuthApiError> {
        let coll = self.get_user_collection()?;
        let query = doc! {
            U::id_field(): format!("{}", id)
        };
        let confirmed = bson::to_bson(&Status::Confirmed).unwrap();
        let update = doc! {
            "$set": { U::status_field(): confirmed, }
        };
        let result = coll
            .update_one(query, update, None)
            .await
            .map_err(|e| AuthApiError::from(e))?;
        match result.modified_count {
            1 => Ok(()),
            0 => Err(AuthApiError::NotFound {
                key: format!("{}", id),
            }),
            _ => Err(AuthApiError::InternalError),
        }
    }

    async fn remove(&mut self, id: &U::Id) -> Result<(), AuthApiError> {
        let coll = self.get_user_collection()?;
        let doc = doc! {
            U::id_field(): format!("{}", id)
        };
        let result = coll
            .delete_one(doc, None)
            .await
            .map_err(|e| AuthApiError::from(e))?;
        match result.deleted_count {
            1 => Ok(()),
            0 => Err(AuthApiError::NotFound {
                key: format!("{}", id),
            }),
            _ => Err(AuthApiError::InternalError),
        }
    }

    async fn update(&mut self, user: U) -> Result<(), AuthApiError> {
        let coll = self.get_user_collection()?;
        let query = doc! {
            U::id_field(): format!("{}", user.id())
        };
        let update = self.get_user_document(&user)?;
        let result = coll
            .update_one(query, update, None)
            .await
            .map_err(|e| AuthApiError::from(e))?;
        match result.modified_count {
            1 => Ok(()),
            0 => Err(AuthApiError::NotFound {
                key: format!("{}", user.id()),
            }),
            _ => Err(AuthApiError::InternalError),
        }
    }

    async fn password_reset(
        &mut self,
        key: &U::Key,
        time: SystemTime,
    ) -> Result<String, AuthApiError> {
        Err(AuthApiError::InternalError)
    }

    async fn password_reset_confirm(
        &mut self,
        reset_id: &str,
        password: String,
        time: SystemTime,
    ) -> Result<(), AuthApiError> {
        Err(AuthApiError::InternalError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::simple::SimpleUser;
    use crate::repos::base;

    #[actix_rt::test]
    async fn get_created_user() {
        let uri = String::from("mongodb://localhost");
        let db_name = String::from("auth_jwt_test");
        let coll_name = String::from("create_user_test");
        let mut repo = MongoRepo::<SimpleUser>::new(uri, db_name, coll_name);
        repo.start().await.unwrap();
        repo.drop().await.unwrap();
        base::tests::get_created_user(repo).await;
    }

    #[actix_rt::test]
    async fn fail_double_create_user() {
        let uri = String::from("mongodb://localhost");
        let db_name = String::from("auth_jwt_test");
        let coll_name = String::from("fail_double_create_user_test");
        let mut repo = MongoRepo::<SimpleUser>::new(uri, db_name, coll_name);
        repo.start().await.unwrap();
        repo.drop().await.unwrap();
        base::tests::fail_double_create_user(repo).await;
    }

    #[actix_rt::test]
    async fn get_user() {
        let uri = String::from("mongodb://localhost");
        let db_name = String::from("auth_jwt_test");
        let coll_name = String::from("get_user_test");
        let mut repo = MongoRepo::<SimpleUser>::new(uri, db_name, coll_name);
        repo.start().await.unwrap();
        repo.drop().await.unwrap();
        base::tests::get_user(repo).await;
    }

    #[actix_rt::test]
    async fn fail_get_user() {
        let uri = String::from("mongodb://localhost");
        let db_name = String::from("auth_jwt_test");
        let coll_name = String::from("fail_get_user_test");
        let mut repo = MongoRepo::<SimpleUser>::new(uri, db_name, coll_name);
        repo.start().await.unwrap();
        repo.drop().await.unwrap();
        base::tests::fail_get_user(repo).await;
    }

    #[actix_rt::test]
    async fn fail_remove_user() {
        let uri = String::from("mongodb://localhost");
        let db_name = String::from("auth_jwt_test");
        let coll_name = String::from("fail_remove_user_test");
        let mut repo = MongoRepo::<SimpleUser>::new(uri, db_name, coll_name);
        repo.start().await.unwrap();
        repo.drop().await.unwrap();
        base::tests::fail_remove_user(repo).await;
    }

    #[actix_rt::test]
    async fn remove_user() {
        let uri = String::from("mongodb://localhost");
        let db_name = String::from("auth_jwt_test");
        let coll_name = String::from("remove_user_test");
        let mut repo = MongoRepo::<SimpleUser>::new(uri, db_name, coll_name);
        repo.start().await.unwrap();
        repo.drop().await.unwrap();
        base::tests::remove_user(repo).await;
    }

    #[actix_rt::test]
    async fn fail_update_user() {
        let uri = String::from("mongodb://localhost");
        let db_name = String::from("auth_jwt_test");
        let coll_name = String::from("fail_update_user_test");
        let mut repo = MongoRepo::<SimpleUser>::new(uri, db_name, coll_name);
        repo.start().await.unwrap();
        repo.drop().await.unwrap();
        base::tests::fail_update_user(repo).await;
    }

    #[actix_rt::test]
    async fn update_user() {
        let uri = String::from("mongodb://localhost");
        let db_name = String::from("auth_jwt_test");
        let coll_name = String::from("update_user_test");
        let mut repo = MongoRepo::<SimpleUser>::new(uri, db_name, coll_name);
        repo.start().await.unwrap();
        repo.drop().await.unwrap();
        base::tests::update_user(repo).await;
    }

    #[actix_rt::test]
    async fn confirm_user() {
        let uri = String::from("mongodb://localhost");
        let db_name = String::from("auth_jwt_test");
        let coll_name = String::from("confirm_user_test");
        let mut repo = MongoRepo::<SimpleUser>::new(uri, db_name, coll_name);
        repo.start().await.unwrap();
        repo.drop().await.unwrap();
        base::tests::confirm_user(repo).await;
    }

    #[actix_rt::test]
    async fn fail_insert_user_exists_unconfirmed() {
        let uri = String::from("mongodb://localhost");
        let db_name = String::from("auth_jwt_test");
        let coll_name = String::from("fail_insert_user_exists_unconfirmed_test");
        let mut repo = MongoRepo::<SimpleUser>::new(uri, db_name, coll_name);
        repo.start().await.unwrap();
        repo.drop().await.unwrap();
        base::tests::fail_insert_user_exists_unconfirmed(repo).await;
    }

    #[actix_rt::test]
    async fn fail_insert_user_exists_confirmed() {
        let uri = String::from("mongodb://localhost");
        let db_name = String::from("auth_jwt_test");
        let coll_name = String::from("fail_insert_user_exists_confirmed_test");
        let mut repo = MongoRepo::<SimpleUser>::new(uri, db_name, coll_name);
        repo.start().await.unwrap();
        repo.drop().await.unwrap();
        base::tests::fail_insert_user_exists_confirmed(repo).await;
    }
}
