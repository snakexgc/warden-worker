use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use worker::D1Database;

use crate::error::AppError;

const JWT_KEYS_ID: &str = "global";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtKeys {
    pub access_secret: String,
    pub refresh_secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtKeysRow {
    pub id: String,
    pub access_secret: String,
    pub refresh_secret: String,
    pub created_at: String,
    pub updated_at: String,
}

pub struct JwtKeyManager;

fn generate_random_secret() -> Result<String, AppError> {
    let mut buf = [0u8; 64];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

impl JwtKeyManager {
    pub async fn get_or_create_keys(db: &D1Database) -> Result<JwtKeys, AppError> {
        if let Ok(k) = Self::get_keys(db).await {
            return Ok(JwtKeys {
                access_secret: k.access_secret,
                refresh_secret: k.refresh_secret,
            });
        }

        Self::create_keys(db).await?;

        let k = Self::get_keys(db).await.map_err(|_| AppError::Database)?;

        Ok(JwtKeys {
            access_secret: k.access_secret,
            refresh_secret: k.refresh_secret,
        })
    }

    pub async fn get_keys(db: &D1Database) -> Result<JwtKeysRow, AppError> {
        let stmt = db
            .prepare("SELECT id, access_secret, refresh_secret, created_at, updated_at FROM jwt_keys WHERE id = ?1");

        let stmt = stmt
            .bind(&[JWT_KEYS_ID.into()])
            .map_err(|_| AppError::Database)?;

        let result: Option<JwtKeysRow> = stmt.first(None).await.map_err(|_| AppError::Database)?;

        result.ok_or_else(|| AppError::NotFound("JWT keys not found".into()))
    }

    pub async fn create_keys(db: &D1Database) -> Result<(), AppError> {
        let now = Utc::now().to_rfc3339();

        let access_secret = generate_random_secret()?;
        let refresh_secret = generate_random_secret()?;

        db.prepare(
            "INSERT OR IGNORE INTO jwt_keys (id, access_secret, refresh_secret, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)"
        )
        .bind(&[
            JWT_KEYS_ID.into(),
            access_secret.into(),
            refresh_secret.into(),
            now.clone().into(),
            now.into(),
        ])
        .map_err(|_| AppError::Database)?
        .run()
        .await
        .map_err(|_| AppError::Database)?;

        log::info!("JWT keys generated and stored in database");
        Ok(())
    }
}
