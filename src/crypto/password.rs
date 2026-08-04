use chrono::Utc;
use constant_time_eq::constant_time_eq;
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

/// 验证客户端提交的 masterPasswordHash，并将旧认证格式渐进迁移到 Vaultwarden 格式。
pub async fn verify_user_password(
    db: &D1Database,
    user_id: &str,
    candidate: &str,
) -> Result<bool, AppError> {
    let row: Option<Value> = db
        .prepare(
            "SELECT master_password_hash, password_salt, password_iterations, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism FROM users WHERE id = ?1",
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

    if let (Some(salt), Some(iterations)) = (salt, password_iterations) {
        let valid = crypto::verify_server_password(candidate, salt, stored_hash, iterations).await;
        if valid && iterations < crypto::PASSWORD_ITERATIONS_DEFAULT {
            upgrade_password_hash(db, user_id, candidate, Some(salt)).await?;
        }
        return Ok(valid);
    }

    // 兼容 2026-02-18 至本次迁移前的格式：服务端哈希错误地复用了客户端 KDF。
    let legacy_valid = if let Some(salt) = salt {
        let kdf_type = value_i32(&row, "kdf_type", crypto::KDF_TYPE_PBKDF2);
        let kdf_iterations = value_i32(&row, "kdf_iterations", crypto::PBKDF2_ITERATIONS_DEFAULT);
        let kdf_memory = optional_i32(&row, "kdf_memory");
        let kdf_parallelism = optional_i32(&row, "kdf_parallelism");
        crypto::verify_password(
            candidate,
            salt,
            stored_hash,
            kdf_type,
            kdf_iterations,
            kdf_memory,
            kdf_parallelism,
        )
        .await
    } else {
        // 更早的记录直接存储客户端 masterPasswordHash。
        constant_time_eq(stored_hash.as_bytes(), candidate.as_bytes())
    };

    if legacy_valid {
        // 旧 salt 只有 32 字节；迁移时换成 Vaultwarden 使用的 64 字节随机 salt。
        upgrade_password_hash(db, user_id, candidate, None).await?;
    }

    Ok(legacy_valid)
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
        "Migrated server password verifier for user {user_id} to PBKDF2-HMAC-SHA256 ({} iterations)",
        crypto::PASSWORD_ITERATIONS_DEFAULT
    );
    Ok(())
}

fn value_i32(row: &Value, key: &str, default: i32) -> i32 {
    optional_i32(row, key).unwrap_or(default)
}

fn optional_i32(row: &Value, key: &str) -> Option<i32> {
    row.get(key)
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
}
