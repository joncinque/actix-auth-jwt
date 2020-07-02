//! Extractor for checking JWT authentication and extracting User info

use actix_http::Payload;
use actix_http::http::header::Header;
use actix_web::{Error, HttpRequest, FromRequest};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use futures::future::{ok, err, FutureExt, LocalBoxFuture};

use crate::errors::AuthApiError;
use crate::models::base::User;
use crate::jwts::authenticator::JwtAuthenticator;
use crate::jwts::types::Claims;
use crate::jwts::base::JwtStatus;
use crate::types::{shareable_data, ShareableData};

#[derive(Debug)]
pub struct JwtUserId<U>
    where U: User {
    pub user_id: U::Id,
}

#[inline]
fn decode<U: User>(req: &HttpRequest, authenticator: &JwtAuthenticator<U>) -> Result<Claims<U>, Error> {
    let bearer = Authorization::<Bearer>::parse(req)?;
    let token = bearer.into_scheme().token().to_string();
    let decoded = authenticator.decode(token)?;
    Ok(decoded.claims)
}

impl<U> FromRequest for JwtUserId<U>
    where U: User + 'static {
    type Config = JwtUserIdConfig<U>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Error>>;

    #[inline]
    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let config = req.app_data::<Self::Config>();
        match config {
            Some(config) => {
                let authenticator = config.authenticator.read().unwrap();
                match decode(req, &authenticator) {
                    Ok(decoded) => {
                        let jti = decoded.jti;
                        let user_id = decoded.sub;
                        authenticator.status_static(&jti)
                            .then(|status| match status {
                                JwtStatus::Outstanding => ok(JwtUserId { user_id }),
                                _ => err(AuthApiError::JwtError.into()),
                            }).boxed_local()
                    },
                    Err(error) => err(error).boxed_local(),
                }
            },
            None => {
                let key = String::from("JwtUserIdConfig not provided");
                err(AuthApiError::ConfigurationError { key }.into()).boxed_local()
            }
        }
    }
}

#[derive(Clone)]
pub struct JwtUserIdConfig<U>
    where U: User + 'static {
    pub authenticator: ShareableData<JwtAuthenticator<U>>,
}

impl<U> Default for JwtUserIdConfig<U>
    where U: User + 'static {
    fn default() -> Self {
        let authenticator: JwtAuthenticator<U> = Default::default();
        let authenticator = shareable_data(authenticator);
        JwtUserIdConfig {
            authenticator,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::AUTHORIZATION;
    use actix_web::test::TestRequest;
    use actix_web::http::StatusCode;
    use std::time::SystemTime;

    use crate::models::simple::SimpleUser;

    #[actix_rt::test]
    async fn test_no_app_data() {
        let (req, mut pl) =
            TestRequest::default()
                .header(AUTHORIZATION, "Bearer blah.blah.blah")
                .to_http_parts();

        let err = JwtUserId::<SimpleUser>::from_request(&req, &mut pl).await.unwrap_err();
        assert_eq!(err.as_response_error().status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        let error = err.to_string();
        assert!(error.contains("Configuration"));
        assert!(error.contains("JwtUserIdConfig"));
    }

    #[actix_rt::test]
    async fn test_decode() {
        let authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let authenticator = shareable_data(authenticator);
        let now = SystemTime::now();
        let user_id = SimpleUser::generate_id();
        let token_pair = authenticator.write().unwrap().create_token_pair(&user_id, now).await.unwrap();
        let (req, mut pl) =
            TestRequest::default()
                .header(AUTHORIZATION, format!("Bearer {}", token_pair.bearer))
                .app_data(JwtUserIdConfig { authenticator: authenticator.clone() })
                .to_http_parts();

        let user = JwtUserId::<SimpleUser>::from_request(&req, &mut pl).await.unwrap();
        assert_eq!(user.user_id, user_id);
    }

    #[actix_rt::test]
    async fn test_gibberish() {
        let authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let authenticator = shareable_data(authenticator);
        let (req, mut pl) =
            TestRequest::default()
                .header(AUTHORIZATION, "Bearer blah.blah.blah")
                .app_data(JwtUserIdConfig { authenticator: authenticator.clone() })
                .to_http_parts();

        let error = JwtUserId::<SimpleUser>::from_request(&req, &mut pl).await.unwrap_err();
        assert_eq!(error.as_response_error().status_code(), StatusCode::UNAUTHORIZED);
        let error = error.to_string();
        assert_eq!(error, "Error with JWT");
    }

    #[actix_rt::test]
    async fn test_blacklisted() {
        let authenticator: JwtAuthenticator<SimpleUser> = Default::default();
        let authenticator = shareable_data(authenticator);
        let now = SystemTime::now();
        let user_id = SimpleUser::generate_id();
        let token_pair = authenticator.write().unwrap().create_token_pair(&user_id, now).await.unwrap();
        let new_pair = authenticator.write().unwrap().refresh(token_pair.refresh).await.unwrap();

        let (req, mut pl) =
            TestRequest::default()
                .header(AUTHORIZATION, format!("Bearer {}", token_pair.bearer))
                .app_data(JwtUserIdConfig { authenticator: authenticator.clone() })
                .to_http_parts();
        let error = JwtUserId::<SimpleUser>::from_request(&req, &mut pl).await.unwrap_err();
        assert_eq!(error.as_response_error().status_code(), StatusCode::UNAUTHORIZED);
        let error = error.to_string();
        assert_eq!(error, "Error with JWT");
    }
}
