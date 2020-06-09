use async_trait::async_trait;
use std::collections::hash_map::{HashMap, Entry};

use crate::errors::AuthApiError;
use crate::jwts::base::{Claims, Jti, JwtBlacklist, TokenStatus};
use crate::models::base::User;


pub struct InMemoryJwtBlacklist<U> where U: User {
    outstanding: HashMap<Jti, Claims<U>>,
    blacklist: HashMap<Jti, Claims<U>>,
}

impl<U> InMemoryJwtBlacklist<U> where U: User {
    pub fn new() -> Self {
        let outstanding = HashMap::new();
        let blacklist = HashMap::new();
        InMemoryJwtBlacklist {
            outstanding,
            blacklist,
        }
    }
}

#[async_trait]
impl<U> JwtBlacklist<U> for InMemoryJwtBlacklist<U> where U: User {
    type Config = ();

    fn from(_config: &Self::Config) -> Self {
        InMemoryJwtBlacklist::new()
    }

    async fn status(&self, jti: &Jti) -> TokenStatus {
        if self.outstanding.contains_key(jti) {
            TokenStatus::Outstanding
        } else if self.blacklist.contains_key(jti) {
            TokenStatus::Blacklisted
        } else {
            TokenStatus::NotFound
        }
    }

    async fn blacklist(&mut self, token: Claims<U>) -> Result<(), AuthApiError> {
        match self.outstanding.remove(&token.jti) {
            None => {
                Err(AuthApiError::NotFound { key: token.jti })
            },
            Some(v) => {
                self.blacklist.insert(token.jti.clone(), token);
                Ok(())
            },
        }
    }

    async fn insert_outstanding(&mut self, token: Claims<U>) -> Result<(), AuthApiError> {
        let jti = token.jti.clone();
        match self.outstanding.entry(jti) {
            Entry::Occupied(e) => Err(
                AuthApiError::AlreadyExists { key: format!("{}", e.key()) }
            ),
            Entry::Vacant(e) => {
                e.insert(token);
                Ok(())
            }
        }
    }

    async fn flush_expired(&mut self) -> Result<(), AuthApiError> {
        Err(AuthApiError::InternalError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::simple::SimpleUser;

    #[actix_rt::test]
    async fn insert_outstanding() {
    }

    #[actix_rt::test]
    async fn insert() {
    }
}
