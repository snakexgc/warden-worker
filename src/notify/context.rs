use axum::http::HeaderMap;
use chrono::Utc;

use super::types::{Geo, RequestMeta};

const MAX_UA_HISTORY: usize = 3;

#[derive(Debug, Clone, Default)]
pub struct NotifyContext {
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub device_identifier: Option<String>,
    pub device_name: Option<String>,
    pub device_type: Option<i32>,
    pub cipher_id: Option<String>,
    pub send_id: Option<String>,
    pub detail: Option<String>,
    pub meta: RequestMeta,
    pub is_new_ua: bool,
}

pub fn extract_request_meta(headers: &HeaderMap) -> RequestMeta {
    let get = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).map(|s| s.to_string());

    let ip = get("CF-Connecting-IP")
        .or_else(|| {
            get("X-Forwarded-For").and_then(|v| {
                v.split(',')
                    .next()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
            })
        })
        .or_else(|| get("X-Real-IP"));

    let user_agent = get("User-Agent");

    let geo = if get("X-CF-Country").is_some() {
        Some(Geo {
            country: get("X-CF-Country"),
            region: get("X-CF-Region"),
            city: get("X-CF-City"),
        })
    } else {
        None
    };

    RequestMeta { ip, user_agent, geo }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct UaRecord {
    ua: String,
    last_seen_at: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct UaHistory {
    records: Vec<UaRecord>,
}

impl UaHistory {
    fn is_new_ua(&self, ua: &str) -> bool {
        !self.records.iter().any(|r| r.ua == ua)
    }

    fn update_ua(&mut self, ua: &str) {
        let now = Utc::now()
            .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        if let Some(pos) = self.records.iter().position(|r| r.ua == ua) {
            self.records.remove(pos);
        }

        self.records.push(UaRecord {
            ua: ua.to_string(),
            last_seen_at: now,
        });

        if self.records.len() > MAX_UA_HISTORY {
            self.records.remove(0);
        }
    }

    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{\"records\":[]}".to_string())
    }

    fn from_json(json_str: &str) -> Self {
        serde_json::from_str(json_str).unwrap_or_default()
    }
}

async fn get_user_ua_history(user_id: &str, env: &worker::Env) -> Result<UaHistory, worker::Error> {
    let db = match crate::db::get_db(env) {
        Ok(db) => db,
        Err(e) => return Err(worker::Error::RustError(e.to_string())),
    };
    let query = "SELECT ua_history FROM users WHERE id = ?";
    let result = db.prepare(query).bind(&[user_id.into()])?.first::<serde_json::Value>(None).await?;

    match result {
        Some(row) => {
            let history_json = row.get("ua_history").and_then(|v| v.as_str()).unwrap_or("{\"records\":[]}");
            Ok(UaHistory::from_json(history_json))
        }
        None => Ok(UaHistory::default()),
    }
}

async fn update_user_ua_history(user_id: &str, env: &worker::Env, ua: &str) -> Result<(), worker::Error> {
    let db = match crate::db::get_db(env) {
        Ok(db) => db,
        Err(e) => return Err(worker::Error::RustError(e.to_string())),
    };

    let query = "SELECT ua_history FROM users WHERE id = ?";
    let result = db.prepare(query).bind(&[user_id.into()])?.first::<serde_json::Value>(None).await?;

    let mut history = match result {
        Some(row) => {
            let history_json = row.get("ua_history").and_then(|v| v.as_str()).unwrap_or("{\"records\":[]}");
            UaHistory::from_json(history_json)
        }
        None => UaHistory::default(),
    };

    history.update_ua(ua);

    let update_query = "UPDATE users SET ua_history = ? WHERE id = ?";
    db.prepare(update_query)
        .bind(&[history.to_json().into(), user_id.into()])?
        .run()
        .await?;

    Ok(())
}

pub async fn check_and_update_ua(ctx: &mut NotifyContext, env: &worker::Env) {
    if let (Some(user_id), Some(ua)) = (ctx.user_id.as_deref(), ctx.meta.user_agent.as_deref()) {
        match get_user_ua_history(user_id, env).await {
            Ok(history) => {
                ctx.is_new_ua = history.is_new_ua(ua);
                if let Err(e) = update_user_ua_history(user_id, env, ua).await {
                    log::warn!(target: crate::logging::targets::NOTIFY, "update ua history failed user_id={} err={:?}", user_id, e);
                }
            }
            Err(e) => {
                log::warn!(target: crate::logging::targets::NOTIFY, "get ua history failed user_id={} err={:?}", user_id, e);
            }
        }
    }
}
