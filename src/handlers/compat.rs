use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::{auth::Claims, db, error::AppError, router::AppState};

#[worker::send]
pub async fn get_collections(
    _claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    _claims.verify_security_stamp(&db).await?;
    Ok(Json(json!([])))
}

#[worker::send]
pub async fn get_policies(
    _claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    _claims.verify_security_stamp(&db).await?;
    Ok(Json(json!([])))
}

#[worker::send]
pub async fn get_organizations(
    _claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    _claims.verify_security_stamp(&db).await?;
    Ok(Json(json!([])))
}
