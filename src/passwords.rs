use argon2::{self, Config};
use rand::rngs::ThreadRng;
use rand::prelude::*;

use crate::errors::{self, AuthApiError};
use crate::types::PinFutureObj;

pub type Hasher = Box<dyn Fn(String) -> PinFutureObj<Result<String, AuthApiError>>>;
pub type Verifier = Box<dyn Fn(String, String) -> PinFutureObj<Result<bool, AuthApiError>>>;

pub struct PasswordHasher {
    pub hasher: Hasher,
    pub verifier: Verifier,
}


fn random_salt(len: u32, rng: &mut ThreadRng) -> Result<Vec<u8>, AuthApiError> {
    let mut bytes = vec![0u8; len as usize];
    rng.try_fill_bytes(bytes.as_mut_slice())
        .map_err(errors::from_rand_error)?;
    Ok(bytes)
}

impl PasswordHasher {
    pub fn argon2(secret_key: String) -> Self {
        let hasher = argon2_password_hasher(secret_key.clone());
        let verifier = argon2_password_verifier(secret_key);
        PasswordHasher { hasher, verifier }
    }
}

impl Default for PasswordHasher {
    fn default() -> Self {
        let hasher = empty_password_hasher();
        let verifier = empty_password_verifier();
        PasswordHasher { hasher, verifier }
    }
}

pub fn empty_password_hasher() -> Hasher {
    Box::new(|password| {
        Box::pin(async move {
            Ok(format!("{}-hash", password))
        })
    })
}

pub fn empty_password_verifier() -> Verifier {
    Box::new(|password, hash| {
        Box::pin(async move {
            Ok(format!("{}-hash", password) == hash)
        })
    })
}

pub fn argon2_password_hasher(secret_key: String) -> Hasher {
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

pub fn argon2_password_verifier(secret_key: String) -> Verifier {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_rt::test]
    async fn empty_password_hash_verify() {
        let hasher: PasswordHasher = Default::default();
        let password = String::from("p@ssword");
        let hash = (hasher.hasher)(password.clone()).await.unwrap();
        let verified = (hasher.verifier)(password.clone(), hash).await.unwrap();
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
