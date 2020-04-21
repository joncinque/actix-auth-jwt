use argon2::{self, Config};
use rand::rngs::ThreadRng;
use rand::prelude::*;

use crate::errors::{self, AuthApiError};
use crate::types::PinFutureObj;

pub type PasswordHasher = Box<dyn Fn(String) -> PinFutureObj<Result<String, AuthApiError>>>;
pub type PasswordVerifier = Box<dyn Fn(String, String) -> PinFutureObj<Result<bool, AuthApiError>>>;


fn random_salt(len: u32, rng: &mut ThreadRng) -> Result<Vec<u8>, AuthApiError> {
    let mut bytes = vec![0u8; len as usize];
    rng.try_fill_bytes(bytes.as_mut_slice())
        .map_err(errors::from_rand_error)?;
    Ok(bytes)
}

pub fn argon2_password_hasher(secret_key: String) -> PasswordHasher {
    Box::new(move |password| {
        let secret_key = secret_key.clone();
        Box::pin(async move {
            let mut config = Config::default();
            let mut rng = rand::thread_rng();
            config.secret = secret_key.as_bytes();
            let salt = random_salt(32, &mut rng)?;
            let password = password.as_bytes();
            argon2::hash_encoded(password, &salt, &config)
                .map_err(errors::from_argon_error)
        })
    })
}

pub fn argon2_password_verifier(secret_key: String) -> PasswordVerifier {
    Box::new(move |password, hash| {
        let secret_key = secret_key.clone();
        Box::pin(async move {
            let password = password.as_bytes();
            let secret_key = secret_key.as_bytes();
            argon2::verify_encoded_ext(&hash, password, secret_key, &[])
                .map_err(errors::from_argon_error)
        })
    })
}

pub fn empty_password_hasher() -> PasswordHasher {
    Box::new(|password| {
        Box::pin(async move {
            Ok(format!("{}-hash", password))
        })
    })
}

pub fn empty_password_verifier() -> PasswordVerifier {
    Box::new(|password, hash| {
        Box::pin(async move {
            Ok(format!("{}-hash", password) == hash)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn empty_password_hash_verify() {
        let hasher = empty_password_hasher();
        let verifier = empty_password_verifier();
        let password = String::from("p@ssword");
        let hash = (hasher)(password.clone()).await.unwrap();
        let verified = (verifier)(password.clone(), hash).await.unwrap();
        assert!(verified);
    }

    #[actix_rt::test]
    async fn argon2_password_hash_verify() {
        let secret_key = String::from("SECRET!");
        let hasher = argon2_password_hasher(secret_key.clone());
        let verifier = argon2_password_verifier(secret_key);
        let password = String::from("p@ssword");
        let hash = (hasher)(password.clone()).await.unwrap();
        let verified = (verifier)(password.clone(), hash).await.unwrap();
        assert!(verified);
    }
}
