use axum::{Json, extract::State, http::HeaderMap};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha1::Sha1;
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;
use worker::{Env, Fetch, Method, Request};

use crate::{
    api::AppState,
    auth::Claims,
    db,
    db::models::two_factor,
    error::AppError,
    extensions::notify::{self, NotifyContext, NotifyEvent},
};

use super::PasswordOrOtpData;

const DEFAULT_YUBICO_SERVER: &str = "https://api.yubico.com/wsapi/2.0/verify";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableYubikeyData {
    key1: Option<String>,
    key2: Option<String>,
    key3: Option<String>,
    key4: Option<String>,
    key5: Option<String>,
    #[serde(default)]
    nfc: bool,
    master_password_hash: Option<String>,
    otp: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct YubikeyMetadata {
    #[serde(alias = "Keys")]
    pub keys: Vec<String>,
    #[serde(alias = "Nfc")]
    pub nfc: bool,
}

fn env_value(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .ok()
        .map(|value| value.to_string())
        .or_else(|| env.var(name).ok().map(|value| value.to_string()))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn yubico_credentials(env: &Env) -> Result<(String, Vec<u8>, String), AppError> {
    let client_id = env_value(env, "YUBICO_CLIENT_ID").ok_or_else(|| {
        AppError::BadRequest("YUBICO_CLIENT_ID or YUBICO_SECRET_KEY is not configured".to_string())
    })?;
    let secret = env_value(env, "YUBICO_SECRET_KEY").ok_or_else(|| {
        AppError::BadRequest("YUBICO_CLIENT_ID or YUBICO_SECRET_KEY is not configured".to_string())
    })?;
    let secret = STANDARD
        .decode(secret)
        .map_err(|_| AppError::BadRequest("YUBICO_SECRET_KEY must be valid base64".to_string()))?;
    let server =
        env_value(env, "YUBICO_SERVER").unwrap_or_else(|| DEFAULT_YUBICO_SERVER.to_string());
    if !server.starts_with("https://") {
        return Err(AppError::BadRequest(
            "YUBICO_SERVER must use HTTPS".to_string(),
        ));
    }
    Ok((client_id, secret, server))
}

pub fn is_configured(env: &Env) -> bool {
    yubico_credentials(env).is_ok()
}

fn sign_params(secret: &[u8], value: &str) -> Result<String, AppError> {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).map_err(|_| AppError::Internal)?;
    mac.update(value.as_bytes());
    Ok(STANDARD.encode(mac.finalize().into_bytes()))
}

fn canonical_params(params: &BTreeMap<String, String>) -> String {
    params
        .iter()
        .filter(|(key, _)| key.as_str() != "h")
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

async fn verify_yubikey_otp(env: &Env, otp: &str) -> Result<(), AppError> {
    if otp.len() != 44 || !otp.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return Err(AppError::BadRequest("Invalid YubiKey OTP".to_string()));
    }
    let (client_id, secret, server) = yubico_credentials(env)?;
    let nonce = Uuid::new_v4().simple().to_string();
    let mut params = BTreeMap::from([
        ("id".to_string(), client_id),
        ("nonce".to_string(), nonce.clone()),
        ("otp".to_string(), otp.to_string()),
        ("timestamp".to_string(), "1".to_string()),
    ]);
    let signature = sign_params(&secret, &canonical_params(&params))?;
    params.insert("h".to_string(), signature);
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(params.iter())
        .finish();
    let request = Request::new(
        &format!("{}?{query}", server.trim_end_matches('?')),
        Method::Get,
    )
    .map_err(|_| AppError::Internal)?;
    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|_| AppError::BadRequest("YubiKey OTP service is unavailable".to_string()))?;
    if response.status_code() != 200 {
        return Err(AppError::BadRequest(
            "YubiKey OTP service rejected the request".to_string(),
        ));
    }
    let body = response
        .text()
        .await
        .map_err(|_| AppError::BadRequest("Invalid YubiKey OTP response".to_string()))?;
    let response_params = body
        .lines()
        .filter_map(|line| line.trim().split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect::<BTreeMap<_, _>>();
    let response_signature = response_params
        .get("h")
        .ok_or_else(|| AppError::BadRequest("Unsigned YubiKey OTP response".to_string()))?;
    let expected = sign_params(&secret, &canonical_params(&response_params))?;
    if !constant_time_eq::constant_time_eq(expected.as_bytes(), response_signature.as_bytes())
        || response_params.get("status").map(String::as_str) != Some("OK")
        || response_params.get("otp").map(String::as_str) != Some(otp)
        || response_params.get("nonce").map(String::as_str) != Some(nonce.as_str())
    {
        return Err(AppError::Unauthorized(
            "Failed to verify YubiKey OTP".to_string(),
        ));
    }
    Ok(())
}

fn keys_from_request(data: &EnableYubikeyData) -> Vec<String> {
    [
        data.key1.as_deref(),
        data.key2.as_deref(),
        data.key3.as_deref(),
        data.key4.as_deref(),
        data.key5.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(str::trim)
    .filter(|key| !key.is_empty())
    .map(str::to_string)
    .collect()
}

fn response(metadata: Option<&YubikeyMetadata>) -> Value {
    let Some(metadata) = metadata else {
        return json!({
            "enabled": false,
            "object": "twoFactorU2f"
        });
    };
    let mut result = Map::new();
    for (index, key) in metadata.keys.iter().enumerate() {
        result.insert(format!("Key{}", index + 1), Value::String(key.clone()));
    }
    result.insert("enabled".to_string(), Value::Bool(true));
    result.insert("nfc".to_string(), Value::Bool(metadata.nfc));
    result.insert(
        "object".to_string(),
        Value::String("twoFactorU2f".to_string()),
    );
    Value::Object(result)
}

#[worker::send]
pub async fn generate_yubikey(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(data): Json<PasswordOrOtpData>,
) -> Result<Json<Value>, AppError> {
    yubico_credentials(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    data.validate(&db, &claims.sub).await?;
    let data = two_factor::get_external_two_factor(
        &db,
        &claims.sub,
        two_factor::TWO_FACTOR_PROVIDER_YUBIKEY,
    )
    .await?;
    let metadata = data
        .map(|data| serde_json::from_str::<YubikeyMetadata>(&data))
        .transpose()
        .map_err(|_| AppError::Internal)?;
    Ok(Json(response(metadata.as_ref())))
}

async fn activate_yubikey_impl(
    claims: Claims,
    state: Arc<AppState>,
    headers: HeaderMap,
    data: EnableYubikeyData,
) -> Result<Json<Value>, AppError> {
    yubico_credentials(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    PasswordOrOtpData {
        master_password_hash: data.master_password_hash.clone(),
        otp: data.otp.clone(),
    }
    .validate(&db, &claims.sub)
    .await?;
    let keys = keys_from_request(&data);
    if keys.is_empty() {
        two_factor::delete_external_two_factor(
            &db,
            &claims.sub,
            Some(two_factor::TWO_FACTOR_PROVIDER_YUBIKEY),
        )
        .await?;
        return Ok(Json(response(None)));
    }
    for key in &keys {
        if key.len() == 12 {
            continue;
        }
        verify_yubikey_otp(&state.env, key).await?;
    }
    let mut public_ids = Vec::new();
    for key in keys {
        let public_id = key
            .get(..12)
            .ok_or_else(|| AppError::BadRequest("Invalid YubiKey OTP".to_string()))?
            .to_string();
        if !public_ids.contains(&public_id) {
            public_ids.push(public_id);
        }
    }
    let metadata = YubikeyMetadata {
        keys: public_ids,
        nfc: data.nfc,
    };
    let serialized = serde_json::to_string(&metadata).map_err(|_| AppError::Internal)?;
    two_factor::upsert_external_two_factor(
        &db,
        &claims.sub,
        two_factor::TWO_FACTOR_PROVIDER_YUBIKEY,
        &serialized,
    )
    .await?;
    let _ = two_factor::get_or_create_recovery_code(&db, &claims.sub).await?;
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        NotifyEvent::TwoFactorEnable,
        NotifyContext {
            user_id: Some(claims.sub),
            user_email: Some(claims.email),
            detail: Some("provider=yubikey".to_string()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );
    Ok(Json(response(Some(&metadata))))
}

#[worker::send]
pub async fn activate_yubikey(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(data): Json<EnableYubikeyData>,
) -> Result<Json<Value>, AppError> {
    activate_yubikey_impl(claims, state, headers, data).await
}

#[worker::send]
pub async fn activate_yubikey_put(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(data): Json<EnableYubikeyData>,
) -> Result<Json<Value>, AppError> {
    activate_yubikey_impl(claims, state, headers, data).await
}

pub async fn validate_yubikey_login(
    env: &Env,
    response: &str,
    two_factor_data: &str,
) -> Result<(), AppError> {
    if response.len() != 44 {
        return Err(AppError::Unauthorized(
            "Invalid YubiKey OTP length".to_string(),
        ));
    }
    let metadata: YubikeyMetadata =
        serde_json::from_str(two_factor_data).map_err(|_| AppError::Internal)?;
    let response_id = response
        .get(..12)
        .ok_or_else(|| AppError::Unauthorized("Invalid YubiKey OTP".to_string()))?;
    if !metadata.keys.iter().any(|key| key == response_id) {
        return Err(AppError::Unauthorized(
            "Given YubiKey is not registered".to_string(),
        ));
    }
    verify_yubikey_otp(env, response).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form_is_sorted_and_omits_signature() {
        let params = BTreeMap::from([
            ("otp".to_string(), "otp".to_string()),
            ("h".to_string(), "signature".to_string()),
            ("id".to_string(), "1".to_string()),
        ]);
        assert_eq!(canonical_params(&params), "id=1&otp=otp");
    }

    #[test]
    fn response_exposes_vaultwarden_key_fields() {
        let value = response(Some(&YubikeyMetadata {
            keys: vec!["ccccccabcdef".to_string()],
            nfc: true,
        }));
        assert_eq!(value["Key1"], "ccccccabcdef");
        assert_eq!(value["object"], "twoFactorU2f");
    }
}
