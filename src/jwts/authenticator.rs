use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey, TokenData};
use std::time::{SystemTime, Duration};

use crate::jwts::types::{generate_jti, unix_timestamp, Jti, TokenType, Claims};
use crate::jwts::base::{JwtBlacklist, JwtStatus};
use crate::jwts::inmemory::InMemoryJwtBlacklist;
use crate::errors::AuthApiError;
use crate::models::base::User;
use crate::types::{shareable_data, ShareableData};

/// Bearer token is typed to be a string, since they are sent from the oustide.
/// The type is provided for better compiler checks.
pub type BearerToken = String;

/// Refresh token is typed to be a string, since they are sent from the oustide.
/// The type is provided for better compiler checks.
pub type RefreshToken = String;

/// The result of token creation is an access token with its associated refresh
/// token, to be used when the access token expires.  This can eventually be
/// expanded for different token types, including simple access or sliding tokens.
#[derive(Debug)]
pub struct JwtPair {
    pub bearer: BearerToken,
    pub refresh: RefreshToken,
}

/// How JWTs will be created and decoded in the system
#[derive(Clone)]
pub struct JwtAuthenticatorConfig {
    pub iss: String,
    pub alg: Algorithm,
    pub secret: String,
    pub bearer_token_lifetime: Duration,
    pub refresh_token_lifetime: Duration,
}

impl Default for JwtAuthenticatorConfig {
    /// Convenience function for creating an authenticator with "sensible"
    /// defaults.  NOTE: this is not suitable from production use, since the
    /// JWT signature secret is known.
    fn default() -> Self {
        let iss = String::from("issuer");
        let alg = Algorithm::HS256;
        let secret = String::from("secret");
        let bearer_token_lifetime = Duration::from_secs(60 * 60);
        let refresh_token_lifetime = Duration::from_secs(60 * 60 * 24);
        JwtAuthenticatorConfig {
            iss,
            alg,
            secret,
            bearer_token_lifetime,
            refresh_token_lifetime,
        }
    }
}

/// Main authenticator used by the services
pub struct JwtAuthenticator<U: User> {
    iss: String,
    header: Header,
    validation: Validation,
    bearer_token_lifetime: Duration,
    refresh_token_lifetime: Duration,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey<'static>,
    blacklist: ShareableData<dyn JwtBlacklist<U>>,
}

impl<U> JwtAuthenticator<U> where U: User {
    fn new_refresh_claims(&self, jti: Jti, id: U::Id, time: SystemTime) -> Claims<U> {
        let iat = unix_timestamp(time);
        let exp = unix_timestamp(time + self.refresh_token_lifetime);
        let iss = self.iss.clone();
        let token_type = TokenType::Refresh;
        let sub = id;
        Claims::<U> {
            jti,
            exp,
            iat,
            iss,
            token_type,
            sub,
        }
    }

    fn new_bearer_claims(&self, jti: Jti, id: U::Id, time: SystemTime) -> Claims<U> {
        let iat = unix_timestamp(time);
        let exp = unix_timestamp(time + self.bearer_token_lifetime);
        let token_type = TokenType::Bearer;
        let iss = self.iss.clone();
        let sub = id.clone();
        Claims::<U> {
            jti,
            exp,
            iat,
            iss,
            token_type,
            sub,
        }
    }

    pub async fn decode(&self, token: String) -> Result<TokenData<Claims<U>>, AuthApiError> {
        decode::<Claims<U>>(&token, &self.decoding_key, &self.validation).map_err(|e| AuthApiError::from(e))
    }

    pub async fn create_token_pair(&mut self, id: &U::Id, time: SystemTime) -> Result<JwtPair, AuthApiError> {
        let jti = generate_jti();
        let refresh_claims = self.new_refresh_claims(jti.clone(), id.clone(), time);
        let refresh = encode(&self.header, &refresh_claims, &self.encoding_key).map_err(|e| AuthApiError::from(e))?;
        let bearer_claims = self.new_bearer_claims(jti.clone(), id.clone(), time);
        let bearer = encode(&self.header, &bearer_claims, &self.encoding_key).map_err(|e| AuthApiError::from(e))?;
        self.blacklist.write().unwrap().insert_outstanding(refresh_claims).await?;
        Ok(JwtPair { bearer, refresh })
    }

    pub async fn status(&self, jti: &Jti) -> JwtStatus {
        self.blacklist.read().unwrap().status(jti).await
    }

    pub async fn refresh(&mut self, refresh: String) -> Result<JwtPair, AuthApiError> {
        let data = self.decode(refresh).await?;
        if data.claims.token_type != TokenType::Refresh {
            return Err(AuthApiError::JwtError)
        }
        let jti = data.claims.jti;
        let id = data.claims.sub;
        match self.status(&jti).await {
            JwtStatus::Outstanding => {
                self.blacklist.write().unwrap().blacklist(jti).await?;
                let now = SystemTime::now();
                self.create_token_pair(&id, now).await
            },
            JwtStatus::NotFound => Err(AuthApiError::NotFound { key: jti }),
            JwtStatus::Blacklisted => Err(AuthApiError::AlreadyUsed),
        }
    }

    pub fn from(config: JwtAuthenticatorConfig, blacklist: ShareableData<dyn JwtBlacklist<U>>) -> Self {
        let iss = config.iss;
        let header = Header::new(config.alg);
        let validation = Validation::new(config.alg);
        let bearer_token_lifetime = config.bearer_token_lifetime;
        let refresh_token_lifetime = config.refresh_token_lifetime;
        let secret = config.secret;
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes()).into_static();
        JwtAuthenticator {
            iss,
            header,
            validation,
            bearer_token_lifetime,
            refresh_token_lifetime,
            encoding_key,
            decoding_key,
            blacklist,
        }
    }
}

impl<U> Default for JwtAuthenticator<U> where U: User + 'static {
    fn default() -> Self {
        let config: JwtAuthenticatorConfig = Default::default();
        let blacklist: InMemoryJwtBlacklist<U> = Default::default();
        JwtAuthenticator::from(config, shareable_data(blacklist))
    }
}
