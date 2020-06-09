use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, TokenData};
use serde::{Serialize, Deserialize};
use std::marker::PhantomData;
use std::time::Duration;

use crate::errors::AuthApiError;
use crate::models::base::User;

pub type Jti = String;
pub type AccessToken = String;
pub type RefreshToken = String;

pub struct JwtPair {
    pub access: AccessToken,
    pub refresh: RefreshToken,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims<U> where U: User {
    pub jti: Jti, // Unique id for the JWT
    pub exp: u32,    // Expiration time
    pub iat: u32,    // Issued at
    pub iss: String, // Issuer
    pub sub: U::Id,  // Subject (whom token refers to / user id)
}

pub enum TokenStatus {
    Outstanding,
    Blacklisted,
    NotFound,
}

#[async_trait]
pub trait JwtBlacklist<U> where U: User {
    async fn status(&self, jti: &Jti) -> TokenStatus;
    async fn blacklist(&mut self, token: Claims<U>) -> Result<(), AuthApiError>;
    async fn insert_outstanding(&mut self, token: Claims<U>) -> Result<(), AuthApiError>;
    async fn flush_expired(&mut self) -> Result<(), AuthApiError>;

    type Config: Send + Sync + Clone;
    fn from(config: &Self::Config) -> Self;
}

#[derive(Clone)]
pub struct JwtAuthenticatorConfig {
    pub alg: Algorithm,
    pub iss: String,
    pub secret: String,
    pub access_key_lifetime: Duration,
    pub refresh_key_lifetime: Duration,
}

impl JwtAuthenticatorConfig {
    pub fn default() -> Self {
        let alg = Algorithm::HS256;
        let iss = String::from("issuer");
        let secret = String::from("secret");
        let access_key_lifetime = Duration::from_secs(60 * 60);
        let refresh_key_lifetime = Duration::from_secs(60 * 60 * 24);
        JwtAuthenticatorConfig {
            alg,
            iss,
            secret,
            access_key_lifetime,
            refresh_key_lifetime,
        }
    }
}

pub struct JwtAuthenticator<U: User, B: JwtBlacklist<U>> {
    secret: String,
    iss: String,
    access_key_lifetime: Duration,
    refresh_key_lifetime: Duration,
    //encoding_key: EncodingKey,
    //decoding_key: DecodingKey<'a>,
    blacklist: B,
    phantom: PhantomData<U>,
}

impl<U, B> JwtAuthenticator<U, B> where U: User, B: JwtBlacklist<U> {
    pub async fn decode(&self, token: String) -> Result<TokenData<Claims<U>>, AuthApiError> {
        Err(AuthApiError::InternalError)
    }

    pub async fn create_token_pair(&mut self, id: U::Id) -> Result<JwtPair, AuthApiError> {
        Err(AuthApiError::InternalError)
    }

    pub async fn refresh(&mut self, refresh: String) -> Result<JwtPair, AuthApiError> {
        let data = self.decode(refresh).await?;
        let claims = &data.claims;
        match self.blacklist.status(&claims.jti).await {
            TokenStatus::Outstanding => {
                Err(AuthApiError::InternalError)
            },
            TokenStatus::NotFound => Err(AuthApiError::NotFound { key: data.claims.jti }),
            TokenStatus::Blacklisted => Err(AuthApiError::AlreadyUsed),
        }
    }

    pub fn from(config: &JwtAuthenticatorConfig, blacklist: B) -> Self {
        let secret = config.secret.clone();
        let iss = config.iss.clone();
        let access_key_lifetime = config.access_key_lifetime.clone();
        let refresh_key_lifetime = config.refresh_key_lifetime.clone();
        let phantom = PhantomData::<U>;
        JwtAuthenticator {
            secret,
            iss,
            access_key_lifetime,
            refresh_key_lifetime,
            blacklist,
            phantom,
        }
    }
}
