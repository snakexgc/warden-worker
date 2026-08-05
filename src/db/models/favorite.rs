use serde::{Deserialize, Serialize};
use worker::D1Database;

use crate::{db, error::AppError};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct Favorite {
    pub user_id: String,
    pub cipher_id: String,
}

#[allow(dead_code)]
impl Favorite {
    pub async fn is_favorite(
        db: &D1Database,
        cipher_id: &str,
        user_id: &str,
    ) -> Result<bool, AppError> {
        let found: Option<i32> = db
            .prepare(
                "SELECT 1 AS favorite FROM favorites
                 WHERE user_id = ?1 AND cipher_id = ?2 LIMIT 1",
            )
            .bind(&[user_id.into(), cipher_id.into()])?
            .first(Some("favorite"))
            .await
            .map_err(|_| AppError::Database)?;
        Ok(found.is_some())
    }

    pub async fn set_favorite(
        db: &D1Database,
        favorite: bool,
        cipher_id: &str,
        user_id: &str,
    ) -> Result<(), AppError> {
        if favorite {
            db.prepare("INSERT OR IGNORE INTO favorites (user_id, cipher_id) VALUES (?1, ?2)")
                .bind(&[user_id.into(), cipher_id.into()])?
                .run()
                .await
                .map_err(|_| AppError::Database)?;
        } else {
            db.prepare("DELETE FROM favorites WHERE user_id = ?1 AND cipher_id = ?2")
                .bind(&[user_id.into(), cipher_id.into()])?
                .run()
                .await
                .map_err(|_| AppError::Database)?;
        }
        db::update_user_revision(db, user_id).await?;
        Ok(())
    }

    pub async fn delete_all_by_cipher(db: &D1Database, cipher_id: &str) -> Result<(), AppError> {
        db.prepare("DELETE FROM favorites WHERE cipher_id = ?1")
            .bind(&[cipher_id.into()])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        Ok(())
    }

    pub async fn delete_all_by_user(db: &D1Database, user_id: &str) -> Result<(), AppError> {
        db.prepare("DELETE FROM favorites WHERE user_id = ?1")
            .bind(&[user_id.into()])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        Ok(())
    }

    pub async fn get_all_cipher_ids_by_user(
        db: &D1Database,
        user_id: &str,
    ) -> Result<Vec<String>, AppError> {
        db.prepare("SELECT cipher_id FROM favorites WHERE user_id = ?1 ORDER BY cipher_id")
            .bind(&[user_id.into()])?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results()
            .map_err(AppError::Worker)
    }
}
