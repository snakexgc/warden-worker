use axum::{Json, extract::State};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::{
    api::notifications::{self, UpdateType},
    api::router::AppState,
    auth::Claims,
    db, domains,
    error::AppError,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainsUpdateRequest {
    pub excluded_global_equivalent_domains: Option<Vec<i32>>,
    pub equivalent_domains: Option<Vec<Vec<String>>>,
}

#[worker::send]
pub async fn get_domains(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let domains = domains::build_domains_object(&db, &claims.sub, false).await?;
    Ok(Json(domains))
}

#[worker::send]
pub async fn post_domains(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DomainsUpdateRequest>,
) -> Result<Json<Value>, AppError> {
    update_domains(claims, &state, payload).await
}

#[worker::send]
pub async fn put_domains(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<DomainsUpdateRequest>,
) -> Result<Json<Value>, AppError> {
    update_domains(claims, &state, payload).await
}

async fn update_domains(
    claims: Claims,
    state: &Arc<AppState>,
    payload: DomainsUpdateRequest,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let now = db::now_rfc3339_millis();

    let equivalent_domains = payload.equivalent_domains.unwrap_or_default();
    let excluded_globals = payload
        .excluded_global_equivalent_domains
        .unwrap_or_default();

    domains::update_domains_settings(&db, &claims.sub, equivalent_domains, excluded_globals, &now)
        .await?;
    notifications::publish_user_update_background(
        &state.ctx,
        state.env.clone(),
        UpdateType::SyncSettings,
        claims.sub,
        now,
        claims.device,
    );

    Ok(Json(json!({})))
}
