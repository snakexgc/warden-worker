use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use worker::D1Database;

use crate::error::AppError;

const TWO_FACTOR_KEY_ID: &str = "global";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactorKey {
    pub key_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorKeyRow {
    pub id: String,
    pub key_b64: String,
    pub created_at: String,
    pub updated_at: String,
}

pub struct TwoFactorKeyManager;

fn generate_random_key() -> Result<String, AppError> {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    Ok(general_purpose::STANDARD.encode(buf))
}

impl TwoFactorKeyManager {
    pub async fn get_or_create_key(db: &D1Database) -> Result<TwoFactorKey, AppError> {
        if let Ok(k) = Self::get_key(db).await {
            return Ok(TwoFactorKey { key_b64: k.key_b64 });
        }

        Self::create_key(db).await?;

        let k = Self::get_key(db).await.map_err(|_| AppError::Database)?;

        Ok(TwoFactorKey { key_b64: k.key_b64 })
    }

    pub async fn get_key(db: &D1Database) -> Result<TwoFactorKeyRow, AppError> {
        let stmt = db.prepare(
            "SELECT id, key_b64, created_at, updated_at FROM two_factor_keys WHERE id = ?1",
        );

        let stmt = stmt
            .bind(&[TWO_FACTOR_KEY_ID.into()])
            .map_err(|_| AppError::Database)?;

        let result: Option<TwoFactorKeyRow> =
            stmt.first(None).await.map_err(|_| AppError::Database)?;

        result.ok_or_else(|| AppError::NotFound("Two-factor key not found".into()))
    }

    pub async fn create_key(db: &D1Database) -> Result<(), AppError> {
        let now = Utc::now().to_rfc3339();

        let key_b64 = generate_random_key()?;

        db.prepare(
            "INSERT OR IGNORE INTO two_factor_keys (id, key_b64, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)"
        )
        .bind(&[
            TWO_FACTOR_KEY_ID.into(),
            key_b64.into(),
            now.clone().into(),
            now.into(),
        ])
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        log::info!("Two-factor encryption key generated and stored in database");
        Ok(())
    }
}
