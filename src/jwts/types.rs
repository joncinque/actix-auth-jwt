use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::models::base::User;

/// JTI is typed to be a string, since they are sent from the oustide.
/// The type is provided for better compiler checks.
pub type Jti = String;

pub fn generate_jti() -> Jti {
    Uuid::new_v4().to_string()
}

pub fn unix_timestamp(time: SystemTime) -> u64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum TokenType {
    Bearer,
    Refresh,
}

/// The claims are the contents of the JWT, a base-64 encoded JSON object placed
/// as the second part of the JWT, e.g. if the JWT is "xxxxx.yyyyyy.zzzzzz",
/// then the claims would be "yyyyyy".
/// The JTI is used as
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims<U> where U: User {
    /// Unique id for the JWT, used for identification within the blacklist
    pub jti: Jti,
    /// Expiration time as a unix timestamp
    pub exp: u64,
    /// Issued time as a unix timestamp
    pub iat: u64,
    /// Issuer name, configured from the outside to always be the same
    pub iss: String,
    /// Token type, should be 'bearer' or 'refresh' depending on the type
    pub token_type: TokenType,
    /// Subject of the token -- whom token refers to.  The user id in our case.
    pub sub: U::Id,
}
