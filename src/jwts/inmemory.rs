use async_trait::async_trait;
use std::collections::hash_map::{HashMap, Entry};

use crate::errors::AuthApiError;
use crate::jwts::base::{JwtBlacklist, JwtStatus};
use crate::jwts::types::{Claims, Jti};
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

    async fn status(&self, jti: &Jti) -> JwtStatus {
        if self.outstanding.contains_key(jti) {
            JwtStatus::Outstanding
        } else if self.blacklist.contains_key(jti) {
            JwtStatus::Blacklisted
        } else {
            JwtStatus::NotFound
        }
    }

    async fn blacklist(&mut self, jti: Jti) -> Result<(), AuthApiError> {
        match self.outstanding.remove(&jti) {
            None => {
                Err(AuthApiError::NotFound { key: jti })
            },
            Some(v) => {
                self.blacklist.insert(jti, v);
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
    use crate::jwts::authenticator::{JwtAuthenticator, JwtAuthenticatorConfig};

    #[actix_rt::test]
    async fn create_pair() {
        let mut blacklist = InMemoryJwtBlacklist::<SimpleUser>::new();
        let config = JwtAuthenticatorConfig::test();
        let mut authenticator = JwtAuthenticator::from(config, blacklist);
        let user_id = SimpleUser::generate_id();
    }

    #[actix_rt::test]
    async fn create_pair_bad_id() {
        let mut blacklist = InMemoryJwtBlacklist::<SimpleUser>::new();
        let config = JwtAuthenticatorConfig::test();
        let mut authenticator = JwtAuthenticator::from(config, blacklist);
        let user_id = SimpleUser::generate_id();
    }

    #[actix_rt::test]
    async fn create_multiple_pairs() {
        let mut blacklist = InMemoryJwtBlacklist::<SimpleUser>::new();
        let config = JwtAuthenticatorConfig::test();
        let mut authenticator = JwtAuthenticator::from(config, blacklist);
        let user_id = SimpleUser::generate_id();
    }

    #[actix_rt::test]
    async fn create_authenticator_bad_secret() {
        let mut blacklist = InMemoryJwtBlacklist::<SimpleUser>::new();
        let config = JwtAuthenticatorConfig::test();
        let mut authenticator = JwtAuthenticator::from(config, blacklist);
        let user_id = SimpleUser::generate_id();
    }

    #[actix_rt::test]
    async fn decode_refresh_token() {
        let mut blacklist = InMemoryJwtBlacklist::<SimpleUser>::new();
        let config = JwtAuthenticatorConfig::test();
        let mut authenticator = JwtAuthenticator::from(config, blacklist);
        let user_id = SimpleUser::generate_id();
    }

    #[actix_rt::test]
    async fn decode_access_token() {
        let mut blacklist = InMemoryJwtBlacklist::<SimpleUser>::new();
        let config = JwtAuthenticatorConfig::test();
        let mut authenticator = JwtAuthenticator::from(config, blacklist);
        let user_id = SimpleUser::generate_id();
    }

    #[actix_rt::test]
    async fn check_valid_token() {
        let mut blacklist = InMemoryJwtBlacklist::<SimpleUser>::new();
        let config = JwtAuthenticatorConfig::test();
        let mut authenticator = JwtAuthenticator::from(config, blacklist);
        let user_id = SimpleUser::generate_id();
    }

    #[actix_rt::test]
    async fn check_blacklisted_token() {
        let mut blacklist = InMemoryJwtBlacklist::<SimpleUser>::new();
        let config = JwtAuthenticatorConfig::test();
        let mut authenticator = JwtAuthenticator::from(config, blacklist);
        let user_id = SimpleUser::generate_id();
    }

    #[actix_rt::test]
    async fn check_not_found_token() {
        let mut blacklist = InMemoryJwtBlacklist::<SimpleUser>::new();
        let config = JwtAuthenticatorConfig::test();
        let mut authenticator = JwtAuthenticator::from(config, blacklist);
        let user_id = SimpleUser::generate_id();
    }

    #[actix_rt::test]
    async fn check_gibberish_token() {
        let mut blacklist = InMemoryJwtBlacklist::<SimpleUser>::new();
        let config = JwtAuthenticatorConfig::test();
        let mut authenticator = JwtAuthenticator::from(config, blacklist);
        let user_id = SimpleUser::generate_id();
    }
}
