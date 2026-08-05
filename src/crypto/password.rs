use chrono::Utc;
use serde_json::Value;
use wasm_bindgen::JsValue;
use worker::D1Database;

use crate::{crypto, error::AppError};

#[derive(Debug)]
pub struct ServerPasswordHash {
    pub hash: String,
    pub salt: String,
    pub iterations: i32,
}

pub async fn hash_password(
    password_hash: &str,
    existing_salt: Option<&str>,
) -> Result<ServerPasswordHash, AppError> {
    let salt = existing_salt
        .map(str::to_owned)
        .unwrap_or_else(crypto::generate_password_salt);
    let iterations = crypto::PASSWORD_ITERATIONS_DEFAULT;
    let hash = crypto::hash_server_password(password_hash, &salt, iterations)
        .await
        .map_err(|error| {
            log::error!("Failed to hash server password: {error}");
            AppError::Internal
        })?;

    Ok(ServerPasswordHash {
        hash,
        salt,
        iterations,
    })
}

/// Verify the client-provided masterPasswordHash using Vaultwarden's server-side hash format.
pub async fn verify_user_password(
    db: &D1Database,
    user_id: &str,
    candidate: &str,
) -> Result<bool, AppError> {
    let row: Option<Value> = db
        .prepare(
            "SELECT master_password_hash, password_salt, password_iterations FROM users WHERE id = ?1",
        )
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|error| {
            log::error!("Failed to load password verifier for user {user_id}: {error:?}");
            AppError::Database
        })?;

    let Some(row) = row else {
        return Ok(false);
    };

    let stored_hash = row
        .get("master_password_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let salt = row.get("password_salt").and_then(Value::as_str);
    let password_iterations = row
        .get("password_iterations")
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok());

    let (Some(salt), Some(iterations)) = (salt, password_iterations) else {
        return Ok(false);
    };
    let valid = crypto::verify_server_password(candidate, salt, stored_hash, iterations).await;
    if valid && iterations < crypto::PASSWORD_ITERATIONS_DEFAULT {
        upgrade_password_hash(db, user_id, candidate, Some(salt)).await?;
    }
    Ok(valid)
}

async fn upgrade_password_hash(
    db: &D1Database,
    user_id: &str,
    password_hash: &str,
    existing_salt: Option<&str>,
) -> Result<(), AppError> {
    let password = hash_password(password_hash, existing_salt).await?;
    let now = Utc::now().to_rfc3339();

    db.prepare(
        "UPDATE users SET master_password_hash = ?1, password_salt = ?2, password_iterations = ?3, updated_at = ?4 WHERE id = ?5",
    )
    .bind(&[
        password.hash.into(),
        password.salt.into(),
        password.iterations.into(),
        now.into(),
        JsValue::from_str(user_id),
    ])?
    .run()
    .await
    .map_err(|error| {
        log::error!("Failed to upgrade password verifier for user {user_id}: {error:?}");
        AppError::Database
    })?;

    log::info!(
        "Updated server password verifier for user {user_id} to PBKDF2-HMAC-SHA256 ({} iterations)",
        crypto::PASSWORD_ITERATIONS_DEFAULT
    );
    Ok(())
}
