use chrono::Utc;
use serde::Deserialize;
use worker::D1Database;

use crate::error::AppError;

#[derive(Debug, Clone, Deserialize)]
pub struct TwoFactorDuoContext {
    pub state: String,
    pub user_email: String,
    pub nonce: String,
    pub exp: i64,
}

impl TwoFactorDuoContext {
    pub async fn ensure_table(db: &D1Database) -> Result<(), AppError> {
        db.prepare(
            "CREATE TABLE IF NOT EXISTS twofactor_duo_ctx (
                state TEXT PRIMARY KEY NOT NULL,
                user_email TEXT NOT NULL,
                nonce TEXT NOT NULL,
                exp INTEGER NOT NULL
            )",
        )
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        Ok(())
    }

    pub async fn save(
        db: &D1Database,
        state: &str,
        user_email: &str,
        nonce: &str,
        ttl_seconds: i64,
    ) -> Result<(), AppError> {
        Self::ensure_table(db).await?;
        let exp = Utc::now().timestamp() + ttl_seconds;
        db.prepare(
            "INSERT OR IGNORE INTO twofactor_duo_ctx (state, user_email, nonce, exp)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(&[state.into(), user_email.into(), nonce.into(), exp.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        Ok(())
    }

    /// Consume a context in one D1 statement so an OIDC response cannot be replayed.
    pub async fn take(db: &D1Database, state: &str) -> Result<Option<Self>, AppError> {
        Self::ensure_table(db).await?;
        db.prepare(
            "DELETE FROM twofactor_duo_ctx
             WHERE state = ?1 AND exp > ?2
             RETURNING state, user_email, nonce, exp",
        )
        .bind(&[state.into(), Utc::now().timestamp().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)
    }

    pub async fn purge_expired(db: &D1Database) -> Result<(), AppError> {
        Self::ensure_table(db).await?;
        db.prepare("DELETE FROM twofactor_duo_ctx WHERE exp <= ?1")
            .bind(&[Utc::now().timestamp().into()])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        Ok(())
    }
}
