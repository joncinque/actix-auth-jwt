use async_trait::async_trait;
use std::collections::hash_map::{HashMap, Entry};
use futures::future::{ready, FutureExt, LocalBoxFuture};

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
}

impl<U> Default for InMemoryJwtBlacklist<U> where U: User{
    fn default() -> Self {
        InMemoryJwtBlacklist::<U>::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};
    use jsonwebtoken::Algorithm;

    use crate::models::simple::SimpleUser;
    use crate::jwts::types::TokenType;
    use crate::jwts::authenticator::JwtAuthenticator;
    use crate::types::shareable_data;

    #[actix_rt::test]
    async fn create_pair() {
        let mut authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let user_id = SimpleUser::generate_id();
        let now = SystemTime::now();
        let token_pair = authenticator.create_token_pair(&user_id, now).await.unwrap();
        assert_ne!(token_pair.bearer, String::from(""));
        assert_ne!(token_pair.refresh, String::from(""));
    }

    #[actix_rt::test]
    async fn decode_bearer_token() {
        let mut authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let user_id = SimpleUser::generate_id();
        let now = SystemTime::now();
        let token_pair = authenticator.create_token_pair(&user_id, now).await.unwrap();

        let decoded = authenticator.decode(&token_pair.bearer).unwrap();
        let claims = decoded.claims;
        assert_eq!(claims.token_type, TokenType::Bearer);
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.iss, "issuer");
        let duration = Duration::new(claims.exp - claims.iat, 0);
        let bearer_token_lifetime = Duration::from_secs(60 * 60);
        assert_eq!(duration, bearer_token_lifetime);
        let status = authenticator.status(&claims.jti).await;
        assert_eq!(status, JwtStatus::Outstanding);
    }

    #[actix_rt::test]
    async fn decode_refresh_token() {
        let mut authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let user_id = SimpleUser::generate_id();
        let now = SystemTime::now();
        let token_pair = authenticator.create_token_pair(&user_id, now).await.unwrap();

        let decoded = authenticator.decode(&token_pair.refresh).unwrap();
        let claims = decoded.claims;
        assert_eq!(claims.token_type, TokenType::Refresh);
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.iss, "issuer");
        let duration = Duration::new(claims.exp - claims.iat, 0);
        let refresh_token_lifetime = Duration::from_secs(60 * 60 * 24);
        assert_eq!(duration, refresh_token_lifetime);
        let status = authenticator.status(&claims.jti).await;
        assert_eq!(status, JwtStatus::Outstanding);
    }

    #[actix_rt::test]
    async fn create_multiple_pairs() {
        let mut authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let user_id = SimpleUser::generate_id();

        let now = SystemTime::now();
        let pair1 = authenticator.create_token_pair(&user_id, now).await.unwrap();
        let bearer_claims1 = authenticator.decode(&pair1.bearer).unwrap().claims;
        let refresh_claims1 = authenticator.decode(&pair1.refresh).unwrap().claims;
        let now = SystemTime::now();
        let pair2 = authenticator.create_token_pair(&user_id, now).await.unwrap();
        let bearer_claims2 = authenticator.decode(&pair2.bearer).unwrap().claims;
        let refresh_claims2 = authenticator.decode(&pair2.refresh).unwrap().claims;

        assert_eq!(bearer_claims1.jti, refresh_claims1.jti);
        assert_eq!(bearer_claims2.jti, refresh_claims2.jti);

        assert_ne!(bearer_claims1.jti, bearer_claims2.jti);
        assert_ne!(refresh_claims1.jti, refresh_claims2.jti);

        let status = authenticator.status(&refresh_claims1.jti).await;
        assert_eq!(status, JwtStatus::Outstanding);
        let status = authenticator.status(&refresh_claims2.jti).await;
        assert_eq!(status, JwtStatus::Outstanding);
    }

    #[actix_rt::test]
    async fn decode_diff_authenticator() {
        let mut authenticator1: JwtAuthenticator<SimpleUser> = Default::default();
        let blacklist: InMemoryJwtBlacklist<SimpleUser> = Default::default();
        let authenticator2 = JwtAuthenticator::<SimpleUser>::new(
            String::from("issuer"),
            Algorithm::HS256,
            String::from("secret"),
            Duration::from_secs(60),
            Duration::from_secs(60 * 5),
            shareable_data(blacklist),
        );
        let user_id = SimpleUser::generate_id();
        let now = SystemTime::now();
        let pair = authenticator1.create_token_pair(&user_id, now).await.unwrap();
        let decoded = authenticator2.decode(&pair.bearer).unwrap();
        assert_eq!(decoded.claims.sub, user_id);
        let decoded = authenticator2.decode(&pair.refresh).unwrap();
        assert_eq!(decoded.claims.sub, user_id);
    }

    #[actix_rt::test]
    async fn fail_decode_diff_secret() {
        let mut authenticator1: JwtAuthenticator<SimpleUser> = Default::default();
        let blacklist: InMemoryJwtBlacklist<SimpleUser> = Default::default();
        let authenticator2 = JwtAuthenticator::<SimpleUser>::new(
            String::from("issuer"),
            Algorithm::HS256,
            String::from("othersecret"),
            Duration::from_secs(60),
            Duration::from_secs(60 * 5),
            shareable_data(blacklist),
        );
        let user_id = SimpleUser::generate_id();
        let now = SystemTime::now();
        let pair = authenticator1.create_token_pair(&user_id, now).await.unwrap();
        let err = authenticator2.decode(&pair.bearer).unwrap_err();
        assert_eq!(err, AuthApiError::JwtError);
    }

    #[actix_rt::test]
    async fn fail_decode_diff_alg() {
        let mut authenticator1: JwtAuthenticator<SimpleUser> = Default::default();
        let blacklist = InMemoryJwtBlacklist::<SimpleUser>::new();
        let authenticator2 = JwtAuthenticator::<SimpleUser>::new(
            String::from("issuer"),
            Algorithm::HS512,
            String::from("othersecret"),
            Duration::from_secs(60),
            Duration::from_secs(60 * 5),
            shareable_data(blacklist),
        );
        let user_id = SimpleUser::generate_id();
        let now = SystemTime::now();
        let pair = authenticator1.create_token_pair(&user_id, now).await.unwrap();
        let err = authenticator2.decode(&pair.bearer).unwrap_err();
        assert_eq!(err, AuthApiError::JwtError);
    }

    #[actix_rt::test]
    async fn valid_bearer_token_found() {
        let mut authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let user_id = SimpleUser::generate_id();
        let now = SystemTime::now();
        let token_pair = authenticator.create_token_pair(&user_id, now).await.unwrap();

        let decoded = authenticator.decode(&token_pair.bearer).unwrap();
        let claims = decoded.claims;
        let status = authenticator.status(&claims.jti).await;
        assert_eq!(status, JwtStatus::Outstanding);
    }

    #[actix_rt::test]
    async fn valid_refresh_token_found() {
        let mut authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let user_id = SimpleUser::generate_id();
        let now = SystemTime::now();
        let token_pair = authenticator.create_token_pair(&user_id, now).await.unwrap();

        let decoded = authenticator.decode(&token_pair.refresh).unwrap();
        let claims = decoded.claims;
        let status = authenticator.status(&claims.jti).await;
        assert_eq!(status, JwtStatus::Outstanding);
    }

    #[actix_rt::test]
    async fn refresh_token_with_blacklist() {
        let mut authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let user_id = SimpleUser::generate_id();

        let now = SystemTime::now();
        let pair1 = authenticator.create_token_pair(&user_id, now).await.unwrap();
        let bearer_claims1 = authenticator.decode(&pair1.bearer).unwrap().claims;
        let refresh_claims1 = authenticator.decode(&pair1.refresh.clone()).unwrap().claims;

        let pair2 = authenticator.refresh(pair1.refresh).await.unwrap();
        let bearer_claims2 = authenticator.decode(&pair2.bearer).unwrap().claims;
        let refresh_claims2 = authenticator.decode(&pair2.refresh).unwrap().claims;

        assert_ne!(bearer_claims1.jti, bearer_claims2.jti);
        assert_ne!(refresh_claims1.jti, refresh_claims2.jti);
        let status = authenticator.status(&refresh_claims1.jti).await;
        assert_eq!(status, JwtStatus::Blacklisted);
        let status = authenticator.status(&bearer_claims1.jti).await;
        assert_eq!(status, JwtStatus::Blacklisted);
        let status = authenticator.status(&refresh_claims2.jti).await;
        assert_eq!(status, JwtStatus::Outstanding);
    }

    #[actix_rt::test]
    async fn fail_refresh_using_bearer_token() {
        let mut authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let user_id = SimpleUser::generate_id();

        let now = SystemTime::now();
        let pair = authenticator.create_token_pair(&user_id, now).await.unwrap();
        let err = authenticator.refresh(pair.bearer).await.unwrap_err();
        assert_eq!(err, AuthApiError::JwtError);
    }

    #[actix_rt::test]
    async fn fail_decode_expired_token() {
        let blacklist = InMemoryJwtBlacklist::<SimpleUser>::new();
        let mut authenticator = JwtAuthenticator::new(
            String::from("issuer"),
            Algorithm::HS256,
            String::from("secret"),
            Duration::from_secs(60),
            Duration::from_secs(60 * 5),
            shareable_data(blacklist));
        let user_id = SimpleUser::generate_id();
        let time = SystemTime::now() - Duration::from_secs(61);

        let pair = authenticator.create_token_pair(&user_id, time).await.unwrap();
        let err = authenticator.decode(&pair.bearer).unwrap_err();
        assert_eq!(err, AuthApiError::JwtError);
    }

    #[actix_rt::test]
    async fn random_jti_not_found() {
        let authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let user_id = SimpleUser::generate_id();
        let status = authenticator.status(&user_id).await;
        assert_eq!(status, JwtStatus::NotFound);
    }

    #[actix_rt::test]
    async fn gibberish_token_fails_decode() {
        let authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let token = String::from("this_is_a_malformed_jwt");

        let err = authenticator.decode(&token).unwrap_err();
        assert_eq!(err, AuthApiError::JwtError);
    }

    #[actix_rt::test]
    async fn blacklist_bearer_token() {
        let mut authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let user_id = SimpleUser::generate_id();

        let now = SystemTime::now();
        let pair = authenticator.create_token_pair(&user_id, now).await.unwrap();
        let claims = authenticator.decode(&pair.refresh).unwrap().claims;
        let jti = claims.jti;
        let result = authenticator.blacklist(pair.bearer).await.unwrap();
        assert_eq!(result, ());
        let status = authenticator.status(&jti).await;
        assert_eq!(status, JwtStatus::Blacklisted);
    }

    #[actix_rt::test]
    async fn blacklist_refresh_token() {
        let mut authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let user_id = SimpleUser::generate_id();

        let now = SystemTime::now();
        let pair = authenticator.create_token_pair(&user_id, now).await.unwrap();
        let claims = authenticator.decode(&pair.bearer).unwrap().claims;
        let jti = claims.jti;
        let result = authenticator.blacklist(pair.refresh).await.unwrap();
        assert_eq!(result, ());
        let status = authenticator.status(&jti).await;
        assert_eq!(status, JwtStatus::Blacklisted);
    }

    #[actix_rt::test]
    async fn blacklist_gibberish_token() {
        let mut authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let user_id = SimpleUser::generate_id();
        let error = authenticator.blacklist(user_id).await.unwrap_err();
        assert_eq!(error, AuthApiError::JwtError);
    }
}
