use axum::{
    extract::{Path, State},
    http::{header, HeaderMap},
    Json,
};
use constant_time_eq::constant_time_eq;
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::{auth::Claims, db, error::AppError, jwt, webauthn, router::AppState, notify, two_factor};
use crate::logging::targets;
use crate::notify::{NotifyContext, NotifyEvent, extract_request_meta};

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SecretVerificationData {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
}

impl SecretVerificationData {
    async fn validate(&self, db: &worker::D1Database, user_id: &str) -> Result<(), AppError> {
        match (&self.master_password_hash, &self.otp) {
            (Some(master_password_hash), None) => {
                // 查询用户的密码哈希和salt
                let result: Option<serde_json::Value> = db
                    .prepare("SELECT master_password_hash, password_salt FROM users WHERE id = ?1")
                    .bind(&[user_id.into()])?
                    .first(None)
                    .await
                    .map_err(|_| AppError::Database)?;

                let Some(row) = result else {
                    return Err(AppError::NotFound("User not found".to_string()));
                };

                let stored_hash = row.get("master_password_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let password_salt = row.get("password_salt")
                    .and_then(|v| v.as_str());

                // 根据是否有salt选择验证方式
                let password_valid = if let Some(salt) = password_salt {
                    // 使用PBKDF2验证
                    crate::crypto::verify_password(master_password_hash, salt, stored_hash).await
                } else {
                    // 直接比较哈希值
                    constant_time_eq(stored_hash.as_bytes(), master_password_hash.as_bytes())
                };

                if !password_valid {
                    return Err(AppError::Unauthorized("Invalid credentials".to_string()));
                }
                Ok(())
            }
            (None, Some(otp)) => two_factor::validate_protected_action_otp(db, user_id, otp, true).await,
            _ => Err(AppError::BadRequest("No validation provided".to_string())),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTwoFactorWebAuthnRequest {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
    id: i32,
    #[serde(alias = "Name", alias = "keyName", alias = "KeyName", alias = "deviceName", alias = "DeviceName")]
    name: Option<String>,
    #[serde(rename = "deviceResponse")]
    device_response: WebAuthnDeviceResponse,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateTwoFactorWebAuthnDeleteRequest {
    #[serde(alias = "MasterPasswordHash")]
    master_password_hash: Option<String>,
    otp: Option<String>,
    id: i32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnDeviceResponse {
    response: WebAuthnDeviceResponseInner,
}

#[derive(Debug, Deserialize)]
struct WebAuthnDeviceResponseInner {
    #[serde(rename = "AttestationObject", alias = "attestationObject")]
    attestation_object: String,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    client_data_json: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveWebAuthnCredentialRequest {
    #[serde(rename = "token")]
    _token: Option<String>,
    #[serde(alias = "Name", alias = "keyName", alias = "KeyName", alias = "deviceName", alias = "DeviceName")]
    name: Option<String>,
    #[serde(rename = "deviceResponse")]
    device_response: WebAuthnDeviceResponse,
    #[serde(rename = "supportsPrf")]
    supports_prf: Option<bool>,
    #[serde(rename = "encryptedUserKey")]
    encrypted_user_key: Option<String>,
    #[serde(rename = "encryptedPublicKey")]
    encrypted_public_key: Option<String>,
    #[serde(rename = "encryptedPrivateKey")]
    encrypted_private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateWebAuthnCredentialRequest {
    #[serde(rename = "token")]
    _token: Option<String>,
    #[serde(rename = "deviceResponse")]
    device_response: Value,
    #[serde(rename = "encryptedUserKey")]
    encrypted_user_key: Option<String>,
    #[serde(rename = "encryptedPublicKey")]
    encrypted_public_key: Option<String>,
    #[serde(rename = "encryptedPrivateKey")]
    encrypted_private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebAuthnPrfProbeRequest {
    #[serde(rename = "supportsPrf")]
    supports_prf: Option<bool>,
}

async fn webauthn_response(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<serde_json::Value, AppError> {
    webauthn_response_with_object(db, user_id, "twoFactorWebAuthn").await
}

async fn webauthn_response_u2f(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<serde_json::Value, AppError> {
    webauthn_response_with_object(db, user_id, "twoFactorU2f").await
}

async fn webauthn_response_with_object(
    db: &worker::D1Database,
    user_id: &str,
    object_name: &str,
) -> Result<serde_json::Value, AppError> {
    let keys = webauthn::list_webauthn_2fa_keys(db, user_id).await?;
    let enabled = webauthn::is_webauthn_enabled(db, user_id).await?;
    let key_items: Vec<Value> = keys
        .into_iter()
        .map(|k| {
            json!({
                "id": k.id,
                "name": k.name,
                "migrated": k.migrated
            })
        })
        .collect();
    Ok(json!({
        "enabled": enabled,
        "keys": key_items,
        "object": object_name
    }))
}

async fn webauthn_credentials_response(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<serde_json::Value, AppError> {
    fn enc_obj(v: &Option<String>) -> Value {
        match v {
            Some(s) => json!({ "encryptedString": s }),
            None => Value::Null,
        }
    }

    let keys = webauthn::list_webauthn_api_items(db, user_id).await?;
    let data: Vec<Value> = keys
        .into_iter()
        .map(|k| {
            json!({
                "Id": k.id,
                "id": k.id,
                "Name": k.name,
                "name": k.name,
                "PrfStatus": k.prf_status,
                "prfStatus": k.prf_status,
                "EncryptedPublicKey": k.encrypted_public_key,
                "EncryptedPublicKeyObj": enc_obj(&k.encrypted_public_key),
                "encryptedPublicKey": k.encrypted_public_key,
                "encryptedPublicKeyObject": enc_obj(&k.encrypted_public_key),
                "EncryptedUserKey": k.encrypted_user_key,
                "EncryptedUserKeyObj": enc_obj(&k.encrypted_user_key),
                "encryptedUserKey": k.encrypted_user_key,
                "encryptedUserKeyObject": enc_obj(&k.encrypted_user_key),
                "EncryptedPrivateKey": k.encrypted_private_key,
                "EncryptedPrivateKeyObj": enc_obj(&k.encrypted_private_key),
                "encryptedPrivateKey": k.encrypted_private_key,
                "encryptedPrivateKeyObject": enc_obj(&k.encrypted_private_key)
            })
        })
        .collect();
    let data_lower = data.clone();

    Ok(json!({
        "Object": "list",
        "object": "list",
        "Data": data,
        "data": data_lower,
        "ContinuationToken": Value::Null,
        "continuationToken": Value::Null
    }))
}

async fn next_available_webauthn_slot_id(
    db: &worker::D1Database,
    user_id: &str,
) -> Result<i32, AppError> {
    let keys = webauthn::list_webauthn_keys(db, user_id).await?;
    for slot_id in 1..=5 {
        if !keys.iter().any(|k| k.id == slot_id) {
            return Ok(slot_id);
        }
    }
    Err(AppError::BadRequest(
        "WebAuthn key slots are full".to_string(),
    ))
}

fn bearer_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

async fn claims_from_bearer(
    headers: &HeaderMap,
    env: &worker::Env,
) -> Result<Option<Claims>, AppError> {
    let Some(token) = bearer_token_from_headers(headers) else {
        return Ok(None);
    };
    let jwt_secret = env.secret("JWT_SECRET")?.to_string();
    let claims = jwt::decode_hs256(&token, &jwt_secret)?;
    Ok(Some(claims))
}

#[worker::send]
pub async fn api_webauthn_get(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    if let Some(claims) = claims_from_bearer(&headers, &state.env).await? {
        return Ok(Json(webauthn_credentials_response(&db, &claims.sub).await?));
    }
    Ok(Json(json!({
        "object": "list",
        "data": [],
        "continuationToken": null
    })))
}

#[worker::send]
pub async fn webauthn_attestation_options(
    claims: Claims,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    payload.validate(&db, &claims.sub).await?;

    let user_row: Value = db
        .prepare("SELECT name, email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let user_name = user_row.get("name").and_then(|v| v.as_str());
    let user_email = user_row
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?;

    let rp_id = webauthn::rp_id_from_headers(&headers);
    let origin = webauthn::origin_from_headers(&headers);
    let options = webauthn::issue_registration_challenge(
        &db,
        &claims.sub,
        user_name,
        user_email,
        &rp_id,
        &origin,
        webauthn::WEBAUTHN_USE_LOGIN,
    )
    .await?;

    let token = options
        .get("challenge")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    Ok(Json(json!({
        "options": options,
        "token": token,
        "prfProbe": {
            "requiredForUnlock": true,
            "fallback": "master_password",
            "endpoint": "/api/webauthn/prf-probe"
        }
    })))
}

#[worker::send]
pub async fn webauthn_prf_probe(
    _claims: Claims,
    Json(payload): Json<WebAuthnPrfProbeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let supports_prf = payload.supports_prf.unwrap_or(false);
    Ok(Json(json!({
        "supportsPrf": supports_prf,
        "canUsePasskeyUnlock": supports_prf,
        "requiresPasswordLogin": !supports_prf,
        "message": if supports_prf {
            "PRF is available. You can continue passkey unlock setup."
        } else {
            "PRF is unavailable on this authenticator/browser. Passkey can be saved for authentication, but vault unlock will fall back to master password."
        }
    })))
}

#[worker::send]
pub async fn webauthn_assertion_options(
    claims: Claims,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    payload.validate(&db, &claims.sub).await?;

    let rp_id = webauthn::rp_id_from_headers(&headers);
    let origin = webauthn::origin_from_headers(&headers);
    let options = webauthn::issue_login_challenge(
        &db,
        &claims.sub,
        &rp_id,
        &origin,
        webauthn::WEBAUTHN_USE_LOGIN,
    )
    .await?
    .ok_or_else(|| AppError::BadRequest("No WebAuthn credentials registered".to_string()))?;

    let token = options
        .get("challenge")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    Ok(Json(json!({
        "options": options,
        "token": token
    })))
}

#[worker::send]
pub async fn webauthn_save_credential(
    claims: Claims,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SaveWebAuthnCredentialRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    let slot_id = next_available_webauthn_slot_id(&db, &claims.sub).await?;
    let name = payload
        .name
        .clone()
        .map(|v| v.trim().to_string())
        .unwrap_or_default();

    log::info!(
        target: targets::AUTH,
        "webauthn_save_credential start user_id={} slot_id={} supports_prf={:?} has_enc_pub={} has_enc_user={} has_enc_priv={}",
        claims.sub,
        slot_id,
        payload.supports_prf,
        payload
            .encrypted_public_key
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_some(),
        payload
            .encrypted_user_key
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_some(),
        payload
            .encrypted_private_key
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_some()
    );

    webauthn::register_webauthn_credential(
        &db,
        &claims.sub,
        slot_id,
        &name,
        &payload.device_response.response.attestation_object,
        &payload.device_response.response.client_data_json,
        webauthn::WEBAUTHN_USE_LOGIN,
    )
    .await?;

    let encrypted_public_key = payload
        .encrypted_public_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let encrypted_user_key = payload
        .encrypted_user_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let encrypted_private_key = payload
        .encrypted_private_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let prf_status = if payload.supports_prf.unwrap_or(false) {
        if encrypted_user_key.is_some() && encrypted_private_key.is_some() {
            webauthn::WEBAUTHN_PRF_STATUS_ENABLED
        } else {
            webauthn::WEBAUTHN_PRF_STATUS_SUPPORTED
        }
    } else {
        webauthn::WEBAUTHN_PRF_STATUS_UNSUPPORTED
    };
    webauthn::update_webauthn_prf_by_slot(
        &db,
        &claims.sub,
        slot_id,
        prf_status,
        encrypted_public_key,
        encrypted_user_key,
        encrypted_private_key,
    )
    .await?;

    let requires_password_login = prf_status != webauthn::WEBAUTHN_PRF_STATUS_ENABLED;
    if requires_password_login {
        log::warn!(
            target: targets::AUTH,
            "webauthn_save_credential downgraded_to_password user_id={} slot_id={} supports_prf={:?} prf_status={}",
            claims.sub,
            slot_id,
            payload.supports_prf,
            prf_status
        );
    }

    log::info!(
        target: targets::AUTH,
        "webauthn_save_credential stored user_id={} slot_id={} prf_status={} has_enc_user={} has_enc_priv={}",
        claims.sub,
        slot_id,
        prf_status,
        encrypted_user_key.is_some(),
        encrypted_private_key.is_some()
    );

    // Send notification
    let user_email: Option<String> = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(Some("email"))
        .await
        .ok()
        .flatten();

    let meta = extract_request_meta(&headers);
    let notify_ctx = NotifyContext {
        user_id: Some(claims.sub.clone()),
        user_email,
        device_identifier: None,
        device_name: Some(name.clone()),
        device_type: None,
        cipher_id: None,
        send_id: None,
        detail: Some(format!("创建 Passkey 凭证: {}", name)),
        meta,
        is_new_ua: false,
    };
    notify::notify_best_effort(&state.env, NotifyEvent::WebAuthnCredentialCreate, notify_ctx).await;

    Ok(Json(json!({
        "success": true,
        "prfStatus": prf_status,
        "canUsePasskeyUnlock": !requires_password_login,
        "requiresPasswordLogin": requires_password_login,
        "message": if requires_password_login {
            "Passkey saved. PRF key material is unavailable on this authenticator/browser, so vault unlock will fall back to master password."
        } else {
            "Passkey saved with PRF unlock enabled."
        }
    })))
}

#[worker::send]
pub async fn webauthn_update_credential(
    claims: Claims,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateWebAuthnCredentialRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    let assertion_token_json = serde_json::to_string(&payload.device_response)
        .map_err(|_| AppError::BadRequest("Invalid WebAuthn assertion".to_string()))?;

    log::info!(
        target: targets::AUTH,
        "webauthn_update_credential start user_id={} has_enc_pub={} has_enc_user={} has_enc_priv={}",
        claims.sub,
        payload
            .encrypted_public_key
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_some(),
        payload
            .encrypted_user_key
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_some(),
        payload
            .encrypted_private_key
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .is_some()
    );

    webauthn::verify_login_assertion(
        &db,
        &claims.sub,
        &assertion_token_json,
        webauthn::WEBAUTHN_USE_LOGIN,
    )
    .await?;
    let credential_id_b64url =
        webauthn::extract_assertion_credential_id_b64url(&assertion_token_json)?;
    let encrypted_public_key = payload
        .encrypted_public_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let encrypted_user_key = payload
        .encrypted_user_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let encrypted_private_key = payload
        .encrypted_private_key
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    if encrypted_user_key.is_none() || encrypted_private_key.is_none() {
        let mut missing = Vec::new();
        if encrypted_user_key.is_none() {
            missing.push("encryptedUserKey");
        }
        if encrypted_private_key.is_none() {
            missing.push("encryptedPrivateKey");
        }
        return Err(AppError::BadRequest(format!(
            "Missing encrypted keyset fields: {}. Passkey PRF key generation likely failed or is unsupported on this authenticator/browser. Re-create the passkey with PRF support, then retry enable encryption.",
            missing.join(", ")
        )));
    }
    webauthn::update_webauthn_prf_by_credential_id(
        &db,
        &claims.sub,
        &credential_id_b64url,
        webauthn::WEBAUTHN_PRF_STATUS_ENABLED,
        encrypted_public_key,
        encrypted_user_key,
        encrypted_private_key,
    )
    .await?;

    log::info!(
        target: targets::AUTH,
        "webauthn_update_credential updated user_id={} credential_id={} has_enc_user={} has_enc_priv={}",
        claims.sub,
        credential_id_b64url,
        encrypted_user_key.is_some(),
        encrypted_private_key.is_some()
    );

    // Send notification
    let user_email: Option<String> = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(Some("email"))
        .await
        .ok()
        .flatten();

    let meta = extract_request_meta(&headers);
    let notify_ctx = NotifyContext {
        user_id: Some(claims.sub.clone()),
        user_email,
        device_identifier: None,
        device_name: Some(credential_id_b64url.clone()),
        device_type: None,
        cipher_id: None,
        send_id: None,
        detail: Some("启用 Passkey PRF 加密".to_string()),
        meta,
        is_new_ua: false,
    };
    notify::notify_best_effort(&state.env, NotifyEvent::WebAuthnCredentialUpdate, notify_ctx).await;

    Ok(Json(json!({ "success": true })))
}

#[worker::send]
pub async fn webauthn_delete_credential(
    claims: Claims,
    Path(id): Path<i32>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    payload.validate(&db, &claims.sub).await?;

    // Get credential name before deletion for notification
    let credential_name: Option<String> = db
        .prepare("SELECT name FROM two_factor_webauthn WHERE user_id = ?1 AND slot_id = ?2")
        .bind(&[claims.sub.clone().into(), (id as f64).into()])?
        .first(Some("name"))
        .await
        .ok()
        .flatten();

    webauthn::delete_webauthn_key(&db, &claims.sub, id).await?;

    // Send notification
    let user_email: Option<String> = db
        .prepare("SELECT email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(Some("email"))
        .await
        .ok()
        .flatten();

    let meta = extract_request_meta(&headers);
    let notify_ctx = NotifyContext {
        user_id: Some(claims.sub.clone()),
        user_email,
        device_identifier: None,
        device_name: credential_name.clone(),
        device_type: None,
        cipher_id: None,
        send_id: None,
        detail: Some(format!("删除 Passkey 凭证: {}", credential_name.unwrap_or_else(|| format!("ID {}", id)))),
        meta,
        is_new_ua: false,
    };
    notify::notify_best_effort(&state.env, NotifyEvent::WebAuthnCredentialDelete, notify_ctx).await;

    Ok(Json(json!({ "success": true })))
}

#[worker::send]
pub async fn get_webauthn(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    payload.validate(&db, &claims.sub).await?;
    Ok(Json(webauthn_response(&db, &claims.sub).await?))
}

#[worker::send]
pub async fn get_webauthn_challenge(
    claims: Claims,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    payload.validate(&db, &claims.sub).await?;

    let user_row: Value = db
        .prepare("SELECT name, email FROM users WHERE id = ?1")
        .bind(&[claims.sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let user_name = user_row.get("name").and_then(|v| v.as_str());
    let user_email = user_row
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or(AppError::Database)?;

    let rp_id = webauthn::rp_id_from_headers(&headers);
    let origin = webauthn::origin_from_headers(&headers);
    let challenge = webauthn::issue_registration_challenge(
        &db,
        &claims.sub,
        user_name,
        user_email,
        &rp_id,
        &origin,
        webauthn::WEBAUTHN_USE_2FA,
    )
    .await?;

    Ok(Json(challenge))
}

#[worker::send]
pub async fn put_webauthn(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateTwoFactorWebAuthnRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    SecretVerificationData {
        master_password_hash: payload.master_password_hash.clone(),
        otp: payload.otp.clone(),
    }
    .validate(&db, &claims.sub)
    .await?;

    let desired_slot_id = payload.id;
    let all_keys = webauthn::list_webauthn_keys(&db, &claims.sub).await?;
    let occupied: std::collections::HashSet<i32> = all_keys.into_iter().map(|k| k.id).collect();
    let slot_id = if occupied.contains(&desired_slot_id) {
        (1..=5)
            .find(|id| !occupied.contains(id))
            .ok_or_else(|| AppError::BadRequest("WebAuthn key slots are full".to_string()))?
    } else {
        desired_slot_id
    };

    webauthn::register_webauthn_credential(
        &db,
        &claims.sub,
        slot_id,
        payload
            .name
            .as_deref()
            .map(str::trim)
            .unwrap_or(""),
        &payload.device_response.response.attestation_object,
        &payload.device_response.response.client_data_json,
        webauthn::WEBAUTHN_USE_2FA,
    )
    .await?;
    webauthn::set_webauthn_two_factor_enabled(&db, &claims.sub, true).await?;

    Ok(Json(webauthn_response_u2f(&db, &claims.sub).await?))
}

#[worker::send]
pub async fn delete_webauthn(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UpdateTwoFactorWebAuthnDeleteRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    SecretVerificationData {
        master_password_hash: payload.master_password_hash.clone(),
        otp: payload.otp.clone(),
    }
    .validate(&db, &claims.sub)
    .await?;

    webauthn::delete_webauthn_key(&db, &claims.sub, payload.id).await?;
    if !webauthn::has_webauthn_credentials(&db, &claims.sub).await? {
        webauthn::set_webauthn_two_factor_enabled(&db, &claims.sub, false).await?;
    }
    Ok(Json(webauthn_response_u2f(&db, &claims.sub).await?))
}

#[worker::send]
pub async fn identity_assertion_options(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let db = db::get_db(&state.env)?;
    let rp_id = webauthn::rp_id_from_headers(&headers);
    let origin = webauthn::origin_from_headers(&headers);
    let jwt_secret = state.env.secret("JWT_SECRET")?.to_string();
    let payload =
        webauthn::issue_passwordless_assertion_options(&db, &rp_id, &origin, &jwt_secret).await?;
    Ok(Json(payload))
}

#[worker::send]
pub async fn create_credential(
    claims: Claims,
    headers: HeaderMap,
    state: State<Arc<AppState>>,
    Json(payload): Json<SaveWebAuthnCredentialRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    webauthn_save_credential(claims, headers, state, Json(payload)).await
}

#[worker::send]
pub async fn update_credential(
    claims: Claims,
    headers: HeaderMap,
    state: State<Arc<AppState>>,
    Json(payload): Json<UpdateWebAuthnCredentialRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    webauthn_update_credential(claims, headers, state, Json(payload)).await
}

#[worker::send]
pub async fn delete_credential(
    claims: Claims,
    Path(id): Path<i32>,
    headers: HeaderMap,
    state: State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    webauthn_delete_credential(claims, Path(id), headers, state, Json(payload)).await
}

#[worker::send]
pub async fn list_credentials(
    headers: HeaderMap,
    state: State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    api_webauthn_get(headers, state).await
}

#[worker::send]
pub async fn two_factor_get_webauthn(
    claims: Claims,
    state: State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    get_webauthn(claims, state, Json(payload)).await
}

#[worker::send]
pub async fn two_factor_get_webauthn_challenge(
    claims: Claims,
    headers: HeaderMap,
    state: State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    get_webauthn_challenge(claims, headers, state, Json(payload)).await
}

#[worker::send]
pub async fn two_factor_put_webauthn(
    claims: Claims,
    state: State<Arc<AppState>>,
    Json(payload): Json<UpdateTwoFactorWebAuthnRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    put_webauthn(claims, state, Json(payload)).await
}

#[worker::send]
pub async fn two_factor_delete_webauthn(
    claims: Claims,
    state: State<Arc<AppState>>,
    Json(payload): Json<UpdateTwoFactorWebAuthnDeleteRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    delete_webauthn(claims, state, Json(payload)).await
}

// Aliases for router compatibility
#[worker::send]
pub async fn attestation_options(
    claims: Claims,
    headers: HeaderMap,
    state: State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    webauthn_attestation_options(claims, headers, state, Json(payload)).await
}

#[worker::send]
pub async fn assertion_options(
    claims: Claims,
    headers: HeaderMap,
    state: State<Arc<AppState>>,
    Json(payload): Json<SecretVerificationData>,
) -> Result<Json<serde_json::Value>, AppError> {
    webauthn_assertion_options(claims, headers, state, Json(payload)).await
}
