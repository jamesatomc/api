use jsonwebtoken::{encode, Header, EncodingKey};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize)]
pub(crate) struct Claims {
    sub: String,
    exp: usize,
}

pub fn generate_jwt(username: &str, secret: &str) -> String { // Made this function public
    let expiration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() + 3600; // Token valid for 1 hour

    let claims = Claims {
        sub: username.to_owned(),
        exp: expiration as usize,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())).unwrap()
}