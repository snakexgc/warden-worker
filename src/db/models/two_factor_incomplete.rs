use serde::Deserialize;
use worker::{D1Database, Env};

use crate::{db, error::AppError};

#[derive(Debug, Clone, Deserialize)]
pub struct TwoFactorIncomplete {
    pub user_id: String,
    pub device_id: String,
    pub device_name: String,
    pub device_type: i32,
    pub login_time: String,
    pub ip_address: String,
}

impl TwoFactorIncomplete {
    pub fn time_limit_minutes(env: &Env) -> i64 {
        env.var("INCOMPLETE_2FA_TIME_LIMIT")
            .ok()
            .or_else(|| env.secret("INCOMPLETE_2FA_TIME_LIMIT").ok())
            .and_then(|value| value.to_string().parse::<i64>().ok())
            .unwrap_or(3)
    }

    pub async fn ensure_table(db: &D1Database) -> Result<(), AppError> {
        db.prepare(
            "CREATE TABLE IF NOT EXISTS two_factor_incomplete (
                user_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                device_name TEXT NOT NULL,
                device_type INTEGER NOT NULL,
                login_time TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                PRIMARY KEY (user_id, device_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )",
        )
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        Ok(())
    }

    pub async fn mark_incomplete(
        db: &D1Database,
        user_id: &str,
        device_id: &str,
        device_name: &str,
        device_type: i32,
        ip_address: &str,
    ) -> Result<(), AppError> {
        Self::ensure_table(db).await?;
        let login_time = db::now_rfc3339_millis();
        db.prepare(
            "INSERT OR IGNORE INTO two_factor_incomplete
             (user_id, device_id, device_name, device_type, login_time, ip_address)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&[
            user_id.into(),
            device_id.into(),
            device_name.into(),
            device_type.into(),
            login_time.into(),
            ip_address.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
        Ok(())
    }

    pub async fn mark_complete(
        db: &D1Database,
        user_id: &str,
        device_id: &str,
    ) -> Result<(), AppError> {
        Self::ensure_table(db).await?;
        db.prepare("DELETE FROM two_factor_incomplete WHERE user_id = ?1 AND device_id = ?2")
            .bind(&[user_id.into(), device_id.into()])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        Ok(())
    }

    pub async fn find_logins_before(
        db: &D1Database,
        time_before: &str,
    ) -> Result<Vec<Self>, AppError> {
        Self::ensure_table(db).await?;
        db.prepare("SELECT * FROM two_factor_incomplete WHERE login_time < ?1 ORDER BY login_time")
            .bind(&[time_before.into()])?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results()
            .map_err(AppError::Worker)
    }

    pub async fn delete(&self, db: &D1Database) -> Result<(), AppError> {
        Self::mark_complete(db, &self.user_id, &self.device_id).await
    }

    pub async fn delete_all_by_user(db: &D1Database, user_id: &str) -> Result<(), AppError> {
        Self::ensure_table(db).await?;
        db.prepare("DELETE FROM two_factor_incomplete WHERE user_id = ?1")
            .bind(&[user_id.into()])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        Ok(())
    }
}
