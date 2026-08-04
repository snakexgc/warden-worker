use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use uuid::Uuid;

use crate::{db, error::AppError};

use super::{ActionLinkType, Notification, dispatcher};

const ACTION_LINK_KIND: &str = "action_link";
const MAX_ATTEMPTS: i64 = 10;

#[derive(Debug, Serialize, Deserialize)]
struct ActionLinkPayload {
    email: String,
    url: String,
    link_type: ActionLinkType,
    organization_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OutboxRow {
    id: String,
    kind: String,
    payload: String,
    attempts: i64,
}

pub async fn enqueue_action_link(
    env: &worker::Env,
    email: &str,
    url: &str,
    link_type: ActionLinkType,
    organization_name: Option<String>,
) -> Result<String, AppError> {
    let db = db::get_db(env)?;
    let id = Uuid::new_v4().to_string();
    let payload = serde_json::to_string(&ActionLinkPayload {
        email: email.to_string(),
        url: url.to_string(),
        link_type,
        organization_name,
    })
    .map_err(|_| AppError::Internal)?;
    let dedupe_key = format!(
        "{}:{}",
        match link_type {
            ActionLinkType::Registration => "registration",
            ActionLinkType::OrganizationInvite => "organization_invite",
        },
        hex::encode(sha2::Sha256::digest(url.as_bytes()))
    );
    let now = db::now_rfc3339_millis();
    db.prepare(
        "INSERT INTO notification_outbox
         (id, dedupe_key, kind, payload, attempts, next_attempt_at, sent_at,
          last_error, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 0, ?5, NULL, NULL, ?6, ?7)
         ON CONFLICT(dedupe_key) DO UPDATE SET
             payload = excluded.payload,
             attempts = 0,
             next_attempt_at = excluded.next_attempt_at,
             sent_at = NULL,
             last_error = NULL,
             updated_at = excluded.updated_at",
    )
    .bind(&[
        id.clone().into(),
        dedupe_key.clone().into(),
        ACTION_LINK_KIND.into(),
        payload.into(),
        now.clone().into(),
        now.clone().into(),
        now.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;

    let stored_id: Option<String> = db
        .prepare("SELECT id FROM notification_outbox WHERE dedupe_key = ?1")
        .bind(&[dedupe_key.into()])?
        .first(Some("id"))
        .await
        .map_err(|_| AppError::Database)?;
    stored_id.ok_or(AppError::Database)
}

pub async fn deliver_one(env: &worker::Env, id: &str) -> Result<(), AppError> {
    let db = db::get_db(env)?;
    let row: Option<OutboxRow> = db
        .prepare(
            "SELECT id, kind, payload, attempts FROM notification_outbox
             WHERE id = ?1 AND sent_at IS NULL AND attempts < ?2",
        )
        .bind(&[id.into(), MAX_ATTEMPTS.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let Some(row) = row else {
        return Ok(());
    };
    deliver_row(env, &db, row).await
}

pub async fn deliver_pending(env: &worker::Env, limit: usize) -> Result<usize, AppError> {
    let db = db::get_db(env)?;
    let limit = limit.clamp(1, 40) as i64;
    let rows: Vec<OutboxRow> = db
        .prepare(
            "SELECT id, kind, payload, attempts FROM notification_outbox
             WHERE sent_at IS NULL AND attempts < ?1 AND next_attempt_at <= ?2
             ORDER BY next_attempt_at, created_at LIMIT ?3",
        )
        .bind(&[
            MAX_ATTEMPTS.into(),
            db::now_rfc3339_millis().into(),
            limit.into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let count = rows.len();
    for row in rows {
        if let Err(error) = deliver_row(env, &db, row).await {
            log::warn!(
                target: crate::worker_runtime::logging::targets::NOTIFY,
                "outbox retry failed: {error}"
            );
        }
    }
    Ok(count)
}

async fn deliver_row(
    env: &worker::Env,
    db: &worker::D1Database,
    row: OutboxRow,
) -> Result<(), AppError> {
    if row.kind != ACTION_LINK_KIND {
        mark_failure(db, &row, "Unsupported outbox notification kind").await?;
        return Ok(());
    }
    let payload: ActionLinkPayload =
        serde_json::from_str(&row.payload).map_err(|_| AppError::Internal)?;
    let notification = Notification::action_link(
        &payload.email,
        &payload.url,
        payload.link_type,
        payload.organization_name,
    );
    match dispatcher::dispatch(env, notification).await {
        Ok(()) => {
            let now = db::now_rfc3339_millis();
            db.prepare(
                "UPDATE notification_outbox SET sent_at = ?1, updated_at = ?2, last_error = NULL
                 WHERE id = ?3 AND sent_at IS NULL",
            )
            .bind(&[now.clone().into(), now.into(), row.id.into()])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        }
        Err(error) => {
            mark_failure(db, &row, &error.to_string()).await?;
        }
    }
    Ok(())
}

async fn mark_failure(
    db: &worker::D1Database,
    row: &OutboxRow,
    error: &str,
) -> Result<(), AppError> {
    let attempts = row.attempts + 1;
    let delay_minutes = 2_i64.pow(attempts.min(5) as u32).min(60);
    let now = Utc::now();
    let next_attempt_at = (now + Duration::minutes(delay_minutes)).to_rfc3339();
    let last_error = error.chars().take(500).collect::<String>();
    db.prepare(
        "UPDATE notification_outbox
         SET attempts = ?1, next_attempt_at = ?2, last_error = ?3, updated_at = ?4
         WHERE id = ?5 AND sent_at IS NULL",
    )
    .bind(&[
        attempts.into(),
        next_attempt_at.into(),
        last_error.into(),
        now.to_rfc3339().into(),
        row.id.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

pub async fn purge_expired(env: &worker::Env) -> Result<(), AppError> {
    let db = db::get_db(env)?;
    let now = db::now_rfc3339_millis();
    let sent_before = (Utc::now() - Duration::days(7)).to_rfc3339();
    db.batch(vec![
        db.prepare(
            "DELETE FROM registration_tokens
             WHERE expires_at <= ?1 OR (consumed_at IS NOT NULL AND consumed_at <= ?2)",
        )
        .bind(&[now.into(), sent_before.clone().into()])?,
        db.prepare(
            "DELETE FROM notification_outbox
             WHERE (sent_at IS NOT NULL AND sent_at <= ?1)
                OR (attempts >= ?2 AND updated_at <= ?1)",
        )
        .bind(&[sent_before.into(), MAX_ATTEMPTS.into()])?,
    ])
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_link_payload_round_trips() {
        let payload = ActionLinkPayload {
            email: "user@example.com".to_string(),
            url: "https://vault.test/#/finish-signup".to_string(),
            link_type: ActionLinkType::Registration,
            organization_name: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        let decoded: ActionLinkPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.email, payload.email);
        assert_eq!(decoded.link_type, ActionLinkType::Registration);
    }
}
