use base64::{engine::general_purpose, Engine as _};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use constant_time_eq::constant_time_eq;

pub const ITERATIONS: u32 = 100_000;

pub fn hash_password(password: &str, salt: &str) -> String {
    let salt_bytes = match general_purpose::STANDARD.decode(salt) {
        Ok(bytes) => bytes,
        Err(_) => return String::new(), // Or handle error properly
    };
    let mut password_hash = [0u8; 32]; // 256 bits
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt_bytes, ITERATIONS, &mut password_hash);
    general_purpose::STANDARD.encode(password_hash)
}

pub fn generate_salt() -> String {
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    general_purpose::STANDARD.encode(salt)
}

pub fn verify_password(password: &str, salt: &str, hash: &str) -> bool {
    let new_hash = hash_password(password, salt);
    constant_time_eq(new_hash.as_bytes(), hash.as_bytes())
}
