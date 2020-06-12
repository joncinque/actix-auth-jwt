use actix_web::{Error, HttpRequest, FromRequest};
use actix_http::Payload;
use futures::future::{ok, FutureExt, LocalBoxFuture};

use crate::models::base::User;
use crate::jwts::authenticator::JwtAuthenticator;

#[derive(Debug)]
pub struct JwtUserId<U>
    where U: User {
    user_id: U::Id,
}

impl<U> FromRequest for JwtUserId<U>
    where U: User + 'static {
    type Config = JwtUserIdConfig<U>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Error>>;

    #[inline]
    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        let req2 = req.clone();
        /*
        authorization::Authorization::<authorization::Bearer>::parse(req)
                .map(|auth| BearerAuth(auth.into_scheme()))
                .map_err(|_| {
                    let bearer = req
                        .app_data::<Self::Config>()
                        .map(|config| config.0.clone())
                        .unwrap_or_else(Default::default);

                    AuthenticationError::new(bearer)
                }),
        */
        let authenticator = req.app_data::<JwtUserIdConfig<U>>().unwrap();
        let user_id = U::generate_id();
        ok(JwtUserId { user_id }).boxed_local()
    }
}

pub struct JwtUserIdConfig<U>
    where U: User + 'static {
    authenticator: JwtAuthenticator<U>,
}

impl<U> Default for JwtUserIdConfig<U>
    where U: User + 'static {
    fn default() -> Self {
        let authenticator: JwtAuthenticator<U> = Default::default();
        JwtUserIdConfig {
            authenticator,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::{HeaderValue, AUTHORIZATION};
    use actix_web::test::TestRequest;

    use crate::models::simple::SimpleUser;

    #[actix_rt::test]
    async fn test_no_app_data() {
        let (req, mut pl) =
            TestRequest::default()
                .header(AUTHORIZATION, "Bearer blah.blah.blah")
                .to_http_parts();

        let err = JwtUserId::<SimpleUser>::from_request(&req, &mut pl).await.unwrap_err();
        assert_eq!(err.to_string(), String::from(""));
    }

    #[actix_rt::test]
    async fn test_default_app_data() {
        let (req, mut pl) =
            TestRequest::default()
                .header(AUTHORIZATION, "Bearer blah.blah.blah")
                .app_data(JwtUserIdConfig::<SimpleUser>::default())
                .to_http_parts();

        let user = JwtUserId::<SimpleUser>::from_request(&req, &mut pl).await.unwrap();
        assert_eq!(user.user_id, SimpleUser::generate_id());
    }
}
