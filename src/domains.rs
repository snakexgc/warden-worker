use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::RwLock;
use worker::{D1Database, Fetch, Method, Request};

use crate::error::AppError;
use crate::logging::targets;

const GLOBAL_DOMAINS_URL: &str =
    "https://raw.githubusercontent.com/dani-garcia/vaultwarden/main/src/static/global_domains.json";

static GLOBAL_DOMAINS_CACHE: Lazy<RwLock<Vec<GlobalDomain>>> = Lazy::new(|| RwLock::new(Vec::new()));

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalDomain {
    #[serde(rename = "type")]
    pub r#type: i32,
    pub domains: Vec<String>,
    #[serde(default)]
    pub excluded: bool,
}

#[derive(Debug, Deserialize)]
struct UserDomainsRow {
    equivalent_domains: String,
    excluded_globals: String,
}

pub async fn build_domains_object(
    db: &D1Database,
    user_id: &str,
    no_excluded: bool,
) -> Result<Value, AppError> {
    let row: UserDomainsRow = db
        .prepare("SELECT equivalent_domains, excluded_globals FROM users WHERE id = ?1")
        .bind(&[user_id.to_string().into()])?
        .first::<UserDomainsRow>(None)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let equivalent_domains: Vec<Vec<String>> =
        serde_json::from_str(&row.equivalent_domains).unwrap_or_default();
    let excluded_globals: Vec<i32> = serde_json::from_str(&row.excluded_globals).unwrap_or_default();

    let mut global_domains = get_global_domains().await;
    for g in &mut global_domains {
        g.excluded = excluded_globals.contains(&g.r#type);
    }
    if no_excluded {
        global_domains.retain(|g| !g.excluded);
    }

    Ok(json!({
        "equivalentDomains": equivalent_domains,
        "globalEquivalentDomains": global_domains,
        "object": "domains",
    }))
}

pub async fn update_domains_settings(
    db: &D1Database,
    user_id: &str,
    equivalent_domains: Vec<Vec<String>>,
    excluded_globals: Vec<i32>,
    now: &str,
) -> Result<(), AppError> {
    let equivalent_domains = serde_json::to_string(&equivalent_domains).unwrap_or_else(|_| "[]".to_string());
    let excluded_globals = serde_json::to_string(&excluded_globals).unwrap_or_else(|_| "[]".to_string());

    db.prepare(
        "UPDATE users SET equivalent_domains = ?1, excluded_globals = ?2, updated_at = ?3 WHERE id = ?4",
    )
    .bind(&[
        equivalent_domains.into(),
        excluded_globals.into(),
        now.into(),
        user_id.into(),
    ])?
    .run()
    .await?;

    Ok(())
}

async fn get_global_domains() -> Vec<GlobalDomain> {
    let request = match Request::new(GLOBAL_DOMAINS_URL, Method::Get) {
        Ok(r) => r,
        Err(e) => {
            log::error!(target: targets::EXTERNAL, "Failed to create request for global domains: {:?}", e);
            return cached_global_domains();
        }
    };

    let mut response = match Fetch::Request(request).send().await {
        Ok(r) => r,
        Err(e) => {
            log::error!(target: targets::EXTERNAL, "Failed to fetch global domains: {:?}", e);
            return cached_global_domains();
        }
    };

    let status = response.status_code();
    if !(200..300).contains(&status) {
        log::warn!(target: targets::EXTERNAL, "Global domains fetch returned non-2xx status: {}", status);
        return cached_global_domains();
    }

    let bytes = match response.bytes().await {
        Ok(b) => b,
        Err(e) => {
            log::error!(target: targets::EXTERNAL, "Failed to read global domains response: {:?}", e);
            return cached_global_domains();
        }
    };

    let text = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => {
            log::error!(target: targets::EXTERNAL, "Global domains response was not valid UTF-8: {:?}", e);
            return cached_global_domains();
        }
    };

    let parsed: Vec<GlobalDomain> = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            log::error!(target: targets::EXTERNAL, "Failed to parse global domains JSON: {:?}", e);
            return cached_global_domains();
        }
    };

    if let Ok(mut cache) = GLOBAL_DOMAINS_CACHE.write() {
        *cache = parsed.clone();
    }
    parsed
}

fn cached_global_domains() -> Vec<GlobalDomain> {
    GLOBAL_DOMAINS_CACHE
        .read()
        .map(|cache| cache.clone())
        .unwrap_or_default()
}
