use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

use crate::api::router::AppState;
use crate::auth::Claims;
use crate::db;
use crate::error::AppError;
use crate::worker_runtime::logging::targets;

#[derive(Debug, Deserialize)]
pub struct HibpBreachQuery {
    pub username: String,
}

#[worker::send]
pub async fn hibp_breach(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<HibpBreachQuery>,
) -> Result<Response, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let username = &query.username;
    let encoded: String = url::form_urlencoded::byte_serialize(username.as_bytes()).collect();

    let api_key = state.env.secret("HIBP_API_KEY").ok().and_then(|s| {
        let v = s.as_ref().as_string()?;
        if v.is_empty() { None } else { Some(v) }
    });

    if let Some(api_key) = api_key {
        let url = format!(
            "https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=false&includeUnverified=false"
        );

        let mut init = worker::RequestInit::new();
        init.with_method(worker::Method::Get);

        let mut request =
            worker::Request::new_with_init(&url, &init).map_err(|_| AppError::Internal)?;

        if let Ok(headers) = request.headers_mut() {
            let _ = headers.set("hibp-api-key", &api_key);
            let _ = headers.set("user-agent", "warden-worker");
        }

        let mut response = worker::Fetch::Request(request).send().await.map_err(|e| {
            log::error!(target: targets::EXTERNAL, "HIBP fetch failed: {e:?}");
            AppError::Internal
        })?;

        if response.status_code() == 404 {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(axum::body::Body::empty())
                .unwrap());
        }

        if response.status_code() != 200 {
            log::error!(target: targets::EXTERNAL, "HIBP returned status {}", response.status_code());
            return Err(AppError::BadRequest("HIBP API error".to_string()));
        }

        let value: Value = response.json().await.map_err(|e| {
            log::error!(target: targets::EXTERNAL, "HIBP response parse failed: {e:?}");
            AppError::Internal
        })?;

        Ok((StatusCode::OK, Json(value)).into_response())
    } else {
        Ok((StatusCode::OK, Json(json!([{
            "name": "HaveIBeenPwned",
            "title": "Manual HIBP Check",
            "domain": "haveibeenpwned.com",
            "breachDate": "2019-08-18T00:00:00Z",
            "addedDate": "2019-08-18T00:00:00Z",
            "description": format!("Go to: <a href=\"https://haveibeenpwned.com/account/{0}\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/account/{0}</a> for a manual check.<br/><br/>HaveIBeenPwned API key not set!<br/>Go to <a href=\"https://haveibeenpwned.com/API/Key\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/API/Key</a> to purchase an API key from HaveIBeenPwned.<br/><br/>", encoded),
            "logoPath": "vw_static/hibp.png",
            "pwnCount": 0,
            "dataClasses": [
                "Error - No API key set!"
            ]
        }]))).into_response())
    }
}
