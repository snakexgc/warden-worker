use axum::Json;
use serde_json::{json, Value};

use crate::{auth::Claims, error::AppError};

#[worker::send]
pub async fn get_collections(_claims: Claims) -> Result<Json<Value>, AppError> {
    Ok(Json(json!([])))
}

#[worker::send]
pub async fn get_policies(_claims: Claims) -> Result<Json<Value>, AppError> {
    Ok(Json(json!([])))
}

#[worker::send]
pub async fn get_organizations(_claims: Claims) -> Result<Json<Value>, AppError> {
    Ok(Json(json!([])))
}
