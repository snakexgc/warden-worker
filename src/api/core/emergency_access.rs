use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;
use worker::{D1Database, Env};

use crate::{
    api::{
        AppState,
        notifications::{self, UpdateType},
    },
    auth::{Claims, EmergencyAccessInviteClaims, normalize_email},
    crypto::password,
    db,
    db::models::{
        EmergencyAccess,
        cipher::{Cipher, CipherDBModel},
        emergency_access::{
            EMERGENCY_STATUS_ACCEPTED, EMERGENCY_STATUS_CONFIRMED, EMERGENCY_STATUS_INVITED,
            EMERGENCY_STATUS_RECOVERY_APPROVED, EMERGENCY_STATUS_RECOVERY_INITIATED,
            EMERGENCY_TYPE_TAKEOVER, EMERGENCY_TYPE_VIEW,
        },
        user::User,
    },
    error::AppError,
    extensions::notify::{self, ActionLinkType},
};

const INVITE_ISSUER: &str = "warden-worker.emergency-access-invite";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyAccessUpdateData {
    #[serde(rename = "type")]
    access_type: Value,
    wait_time_days: i32,
    #[serde(default)]
    key_encrypted: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyAccessInviteData {
    email: String,
    #[serde(rename = "type")]
    access_type: Value,
    wait_time_days: i32,
}

#[derive(Debug, Deserialize)]
pub struct AcceptData {
    token: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmData {
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyAccessPasswordData {
    new_master_password_hash: String,
    key: String,
}

#[derive(Debug, Deserialize)]
struct UserSummary {
    id: String,
    email: String,
    name: Option<String>,
    avatar_color: Option<String>,
}

fn env_bool(env: &Env, name: &str, default: bool) -> bool {
    let value = env
        .var(name)
        .ok()
        .map(|value| value.to_string())
        .or_else(|| env.secret(name).ok().map(|value| value.to_string()));
    match value.as_deref().map(str::trim).map(str::to_ascii_lowercase) {
        Some(value) if matches!(value.as_str(), "1" | "true" | "yes" | "on") => true,
        Some(value) if matches!(value.as_str(), "0" | "false" | "no" | "off") => false,
        _ => default,
    }
}

pub(crate) fn emergency_access_enabled(env: &Env) -> bool {
    env_bool(env, "EMERGENCY_ACCESS_ALLOWED", true)
}

fn ensure_enabled(env: &Env) -> Result<(), AppError> {
    if emergency_access_enabled(env) {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "Emergency access is not enabled.".to_string(),
        ))
    }
}

fn list_response(data: Vec<Value>) -> Value {
    json!({
        "data": data,
        "object": "list",
        "continuationToken": null
    })
}

fn parse_access_type(value: &Value) -> Result<i32, AppError> {
    let value = value
        .as_i64()
        .map(|value| value.to_string())
        .or_else(|| value.as_str().map(str::to_string))
        .ok_or_else(|| AppError::BadRequest("Invalid emergency access type.".to_string()))?;
    match value.to_ascii_lowercase().as_str() {
        "0" | "view" => Ok(EMERGENCY_TYPE_VIEW),
        "1" | "takeover" => Ok(EMERGENCY_TYPE_TAKEOVER),
        _ => Err(AppError::BadRequest(
            "Invalid emergency access type.".to_string(),
        )),
    }
}

fn validate_wait_time(wait_time_days: i32) -> Result<(), AppError> {
    if (0..=365).contains(&wait_time_days) {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "Emergency access wait time must be between 0 and 365 days.".to_string(),
        ))
    }
}

async fn load_user(db: &D1Database, user_id: &str) -> Result<User, AppError> {
    db.prepare("SELECT * FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))
}

async fn load_user_by_email(db: &D1Database, email: &str) -> Result<User, AppError> {
    db.prepare("SELECT * FROM users WHERE email = ?1")
        .bind(&[email.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))
}

async fn load_summary_by_id(db: &D1Database, user_id: &str) -> Result<UserSummary, AppError> {
    db.prepare("SELECT id, email, name, avatar_color FROM users WHERE id = ?1")
        .bind(&[user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))
}

async fn load_summary_by_email(db: &D1Database, email: &str) -> Result<UserSummary, AppError> {
    db.prepare("SELECT id, email, name, avatar_color FROM users WHERE email = ?1")
        .bind(&[email.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))
}

async fn load_emergency(db: &D1Database, id: &str) -> Result<EmergencyAccess, AppError> {
    db.prepare("SELECT * FROM emergency_access WHERE id = ?1")
        .bind(&[id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::BadRequest("Emergency access not valid.".to_string()))
}

async fn load_by_grantor(
    db: &D1Database,
    id: &str,
    grantor_id: &str,
) -> Result<EmergencyAccess, AppError> {
    let emergency = load_emergency(db, id).await?;
    if emergency.grantor_uuid == grantor_id {
        Ok(emergency)
    } else {
        Err(AppError::BadRequest(
            "Emergency access not valid.".to_string(),
        ))
    }
}

async fn load_by_grantee(
    db: &D1Database,
    id: &str,
    grantee_id: &str,
) -> Result<EmergencyAccess, AppError> {
    let emergency = load_emergency(db, id).await?;
    if emergency.grantee_uuid.as_deref() == Some(grantee_id) {
        Ok(emergency)
    } else {
        Err(AppError::BadRequest(
            "Emergency access not valid.".to_string(),
        ))
    }
}

async fn touch_participants(db: &D1Database, emergency: &EmergencyAccess) -> Result<(), AppError> {
    db::update_user_revision(db, &emergency.grantor_uuid).await?;
    if let Some(grantee_id) = emergency.grantee_uuid.as_deref() {
        db::update_user_revision(db, grantee_id).await?;
    }
    Ok(())
}

async fn grantee_details(db: &D1Database, emergency: &EmergencyAccess) -> Result<Value, AppError> {
    let user = match emergency.grantee_uuid.as_deref() {
        Some(user_id) => load_summary_by_id(db, user_id).await?,
        None => {
            load_summary_by_email(
                db,
                emergency
                    .email
                    .as_deref()
                    .ok_or_else(|| AppError::NotFound("Grantee user not found".to_string()))?,
            )
            .await?
        }
    };
    Ok(json!({
        "id": emergency.id,
        "status": emergency.status,
        "type": emergency.access_type,
        "waitTimeDays": emergency.wait_time_days,
        "granteeId": user.id,
        "email": user.email,
        "name": user.name,
        "avatarColor": user.avatar_color,
        "object": "emergencyAccessGranteeDetails"
    }))
}

async fn grantor_details(db: &D1Database, emergency: &EmergencyAccess) -> Result<Value, AppError> {
    let user = load_summary_by_id(db, &emergency.grantor_uuid).await?;
    Ok(json!({
        "id": emergency.id,
        "status": emergency.status,
        "type": emergency.access_type,
        "waitTimeDays": emergency.wait_time_days,
        "grantorId": user.id,
        "email": user.email,
        "name": user.name,
        "avatarColor": user.avatar_color,
        "object": "emergencyAccessGrantorDetails"
    }))
}

#[worker::send]
pub async fn get_contacts(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    if !emergency_access_enabled(&state.env) {
        return Ok(Json(list_response(Vec::new())));
    }
    let rows: Vec<EmergencyAccess> = db
        .prepare("SELECT * FROM emergency_access WHERE grantor_uuid = ?1 ORDER BY created_at")
        .bind(&[claims.sub.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        data.push(grantee_details(&db, &row).await?);
    }
    Ok(Json(list_response(data)))
}

#[worker::send]
pub async fn get_grantees(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    if !emergency_access_enabled(&state.env) {
        return Ok(Json(list_response(Vec::new())));
    }
    let rows: Vec<EmergencyAccess> = db
        .prepare("SELECT * FROM emergency_access WHERE grantee_uuid = ?1 ORDER BY created_at")
        .bind(&[claims.sub.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let mut data = Vec::with_capacity(rows.len());
    for row in rows {
        data.push(grantor_details(&db, &row).await?);
    }
    Ok(Json(list_response(data)))
}

#[worker::send]
pub async fn get_emergency_access(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let emergency = load_by_grantor(&db, &id, &claims.sub).await?;
    let details = grantee_details(&db, &emergency).await?;
    Ok(Json(details))
}

async fn update_emergency_access_impl(
    claims: Claims,
    state: Arc<AppState>,
    id: String,
    data: EmergencyAccessUpdateData,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    validate_wait_time(data.wait_time_days)?;
    let access_type = parse_access_type(&data.access_type)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let emergency = load_by_grantor(&db, &id, &claims.sub).await?;
    let now = db::now_rfc3339_millis();
    db.prepare(
        "UPDATE emergency_access
         SET type = ?1, wait_time_days = ?2,
             key_encrypted = COALESCE(?3, key_encrypted), updated_at = ?4
         WHERE id = ?5",
    )
    .bind(&[
        access_type.into(),
        data.wait_time_days.into(),
        data.key_encrypted.into(),
        now.into(),
        id.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    touch_participants(&db, &emergency).await?;
    let response = load_emergency(&db, &emergency.id).await?.to_json();
    Ok(Json(response))
}

#[worker::send]
pub async fn put_emergency_access(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(data): Json<EmergencyAccessUpdateData>,
) -> Result<Json<Value>, AppError> {
    update_emergency_access_impl(claims, state, id, data).await
}

#[worker::send]
pub async fn post_emergency_access(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(data): Json<EmergencyAccessUpdateData>,
) -> Result<Json<Value>, AppError> {
    update_emergency_access_impl(claims, state, id, data).await
}

async fn delete_emergency_access_impl(
    claims: Claims,
    state: Arc<AppState>,
    id: String,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let emergency = load_emergency(&db, &id).await?;
    if emergency.grantor_uuid != claims.sub
        && emergency.grantee_uuid.as_deref() != Some(claims.sub.as_str())
    {
        return Err(AppError::BadRequest(
            "Emergency access not valid.".to_string(),
        ));
    }
    db.prepare("DELETE FROM emergency_access WHERE id = ?1")
        .bind(&[id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    touch_participants(&db, &emergency).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn delete_emergency_access(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    delete_emergency_access_impl(claims, state, id).await
}

#[worker::send]
pub async fn post_delete_emergency_access(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    delete_emergency_access_impl(claims, state, id).await
}

async fn send_invite_link(
    state: &AppState,
    emergency: &EmergencyAccess,
    grantee: &User,
    grantor: &User,
) -> Result<(), AppError> {
    let now = Utc::now();
    let expiry_hours = state
        .env
        .var("INVITATION_EXPIRATION_HOURS")
        .ok()
        .and_then(|value| value.to_string().parse::<i64>().ok())
        .filter(|hours| (1..=720).contains(hours))
        .unwrap_or(120);
    let grantor_name = grantor
        .name
        .clone()
        .unwrap_or_else(|| grantor.email.clone());
    let claims = EmergencyAccessInviteClaims {
        nbf: now.timestamp() as usize,
        exp: (now + Duration::hours(expiry_hours)).timestamp() as usize,
        iss: INVITE_ISSUER.to_string(),
        sub: grantee.id.clone(),
        email: grantee.email.clone(),
        emer_id: emergency.id.clone(),
        grantor_name: grantor_name.clone(),
        grantor_email: grantor.email.clone(),
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_keys.access_secret.as_ref()),
    )?;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("id", &emergency.id)
        .append_pair("name", &grantor_name)
        .append_pair("email", &grantee.email)
        .append_pair("token", &token)
        .finish();
    let url = state.public_url(&format!("/#/accept-emergency/?{query}"));
    let outbox_id = notify::enqueue_action_link(
        &state.env,
        &grantee.email,
        &url,
        ActionLinkType::EmergencyAccessInvite,
        Some(grantor_name),
    )
    .await?;
    notify::deliver_outbox_background(&state.ctx, state.env.clone(), outbox_id);
    Ok(())
}

#[worker::send]
pub async fn send_invite(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(data): Json<EmergencyAccessInviteData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    validate_wait_time(data.wait_time_days)?;
    let access_type = parse_access_type(&data.access_type)?;
    let email = normalize_email(&data.email);
    if email.is_empty() || email == normalize_email(&claims.email) {
        return Err(AppError::BadRequest(
            "You can not set yourself as an emergency contact.".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let grantor = load_user(&db, &claims.sub).await?;
    let existing: Option<User> = db
        .prepare("SELECT * FROM users WHERE email = ?1")
        .bind(&[email.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let grantee_id = existing
        .as_ref()
        .map(|user| user.id.clone())
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let duplicate: Option<i32> = db
        .prepare(
            "SELECT 1 AS duplicate FROM emergency_access
             WHERE grantor_uuid = ?1 AND (grantee_uuid = ?2 OR email = ?3) LIMIT 1",
        )
        .bind(&[
            claims.sub.clone().into(),
            grantee_id.clone().into(),
            email.clone().into(),
        ])?
        .first(Some("duplicate"))
        .await
        .map_err(|_| AppError::Database)?;
    if duplicate.is_some() {
        return Err(AppError::BadRequest(format!(
            "Grantee user already invited: {email}"
        )));
    }

    let now = db::now_rfc3339_millis();
    let emergency_id = Uuid::new_v4().to_string();
    let mut statements = Vec::new();
    if existing.is_none() {
        statements.push(
            db.prepare(
                "INSERT INTO users
                 (id, name, email, email_verified, avatar_color, master_password_hash,
                  master_password_hint, key, private_key, public_key, kdf_type, kdf_iterations,
                  kdf_memory, kdf_parallelism, security_stamp, password_salt,
                  password_iterations, created_at, updated_at)
                 VALUES (?1, NULL, ?2, 0, NULL, '', NULL, '', '', '', 1, 3, 64, 4, ?3,
                         NULL, 600000, ?4, ?5)",
            )
            .bind(&[
                grantee_id.clone().into(),
                email.clone().into(),
                Uuid::new_v4().to_string().into(),
                now.clone().into(),
                now.clone().into(),
            ])?,
        );
    }
    statements.push(
        db.prepare(
            "INSERT INTO emergency_access
             (id, grantor_uuid, grantee_uuid, email, key_encrypted, type, status,
              wait_time_days, recovery_initiated_at, last_notification_at, updated_at, created_at)
             VALUES (?1, ?2, NULL, ?3, NULL, ?4, ?5, ?6, NULL, NULL, ?7, ?8)",
        )
        .bind(&[
            emergency_id.clone().into(),
            claims.sub.clone().into(),
            email.clone().into(),
            access_type.into(),
            EMERGENCY_STATUS_INVITED.into(),
            data.wait_time_days.into(),
            now.clone().into(),
            now.clone().into(),
        ])?,
    );
    statements.push(
        db.prepare(
            "INSERT INTO invitations (email, created_at, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(email) DO UPDATE SET updated_at = excluded.updated_at",
        )
        .bind(&[email.clone().into(), now.clone().into(), now.into()])?,
    );
    db.batch(statements).await.map_err(|_| AppError::Database)?;
    db::update_user_revision(&db, &claims.sub).await?;
    let emergency = load_emergency(&db, &emergency_id).await?;
    let grantee = load_user_by_email(&db, &email).await?;
    send_invite_link(&state, &emergency, &grantee, &grantor).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn resend_invite(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let emergency = load_by_grantor(&db, &id, &claims.sub).await?;
    if emergency.status != EMERGENCY_STATUS_INVITED {
        return Err(AppError::BadRequest(
            "The grantee user has already accepted this invitation.".to_string(),
        ));
    }
    let email = emergency
        .email
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("Email not valid.".to_string()))?;
    let grantee = load_user_by_email(&db, email).await?;
    let grantor = load_user(&db, &claims.sub).await?;
    let now = db::now_rfc3339_millis();
    db.prepare(
        "INSERT INTO invitations (email, created_at, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(email) DO UPDATE SET updated_at = excluded.updated_at",
    )
    .bind(&[email.into(), now.clone().into(), now.into()])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    send_invite_link(&state, &emergency, &grantee, &grantor).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn accept_invite(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(data): Json<AcceptData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let invite = decode::<EmergencyAccessInviteClaims>(
        &data.token,
        &DecodingKey::from_secret(state.jwt_keys.access_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| AppError::BadRequest("Invalid emergency access invitation".to_string()))?
    .claims;
    if invite.iss != INVITE_ISSUER
        || invite.emer_id != id
        || normalize_email(&invite.email) != normalize_email(&claims.email)
        || invite.sub != claims.sub
    {
        return Err(AppError::BadRequest(
            "Emergency access invitation does not match the current account".to_string(),
        ));
    }
    let emergency: EmergencyAccess = db
        .prepare(
            "SELECT * FROM emergency_access
             WHERE id = ?1 AND email = ?2 AND status = ?3",
        )
        .bind(&[
            id.clone().into(),
            invite.email.clone().into(),
            EMERGENCY_STATUS_INVITED.into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| {
            AppError::BadRequest("Emergency access invitation is no longer pending.".to_string())
        })?;
    let grantor = load_user(&db, &emergency.grantor_uuid).await?;
    let grantor_name = grantor.name.unwrap_or_else(|| grantor.email.clone());
    if invite.grantor_email != grantor.email || invite.grantor_name != grantor_name {
        return Err(AppError::BadRequest(
            "Emergency access invitation is no longer valid".to_string(),
        ));
    }
    let now = db::now_rfc3339_millis();
    db.batch(vec![
        db.prepare(
            "UPDATE emergency_access SET grantee_uuid = ?1, email = NULL, status = ?2,
             updated_at = ?3 WHERE id = ?4",
        )
        .bind(&[
            claims.sub.clone().into(),
            EMERGENCY_STATUS_ACCEPTED.into(),
            now.into(),
            id.into(),
        ])?,
        db.prepare("DELETE FROM invitations WHERE email = ?1")
            .bind(&[invite.email.into()])?,
    ])
    .await
    .map_err(|_| AppError::Database)?;
    touch_participants(&db, &emergency).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn confirm_emergency_access(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(data): Json<ConfirmData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    if data.key.is_empty() {
        return Err(AppError::BadRequest(
            "Encrypted key is required.".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let emergency = load_by_grantor(&db, &id, &claims.sub).await?;
    if emergency.status != EMERGENCY_STATUS_ACCEPTED || emergency.grantee_uuid.is_none() {
        return Err(AppError::BadRequest(
            "Emergency access not valid.".to_string(),
        ));
    }
    let now = db::now_rfc3339_millis();
    db.prepare(
        "UPDATE emergency_access SET status = ?1, key_encrypted = ?2, email = NULL,
         updated_at = ?3 WHERE id = ?4",
    )
    .bind(&[
        EMERGENCY_STATUS_CONFIRMED.into(),
        data.key.into(),
        now.into(),
        id.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    touch_participants(&db, &emergency).await?;
    let response = load_emergency(&db, &emergency.id).await?.to_json();
    Ok(Json(response))
}

#[worker::send]
pub async fn initiate_emergency_access(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let emergency = load_by_grantee(&db, &id, &claims.sub).await?;
    if emergency.status != EMERGENCY_STATUS_CONFIRMED {
        return Err(AppError::BadRequest(
            "Emergency access not valid.".to_string(),
        ));
    }
    let now = db::now_rfc3339_millis();
    db.prepare(
        "UPDATE emergency_access SET status = ?1, recovery_initiated_at = ?2,
         last_notification_at = ?3, updated_at = ?4 WHERE id = ?5",
    )
    .bind(&[
        EMERGENCY_STATUS_RECOVERY_INITIATED.into(),
        now.clone().into(),
        now.clone().into(),
        now.into(),
        id.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    touch_participants(&db, &emergency).await?;
    let response = load_emergency(&db, &emergency.id).await?.to_json();
    Ok(Json(response))
}

#[worker::send]
pub async fn approve_emergency_access(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let emergency = load_by_grantor(&db, &id, &claims.sub).await?;
    if emergency.status != EMERGENCY_STATUS_RECOVERY_INITIATED {
        return Err(AppError::BadRequest(
            "Emergency access not valid.".to_string(),
        ));
    }
    let now = db::now_rfc3339_millis();
    db.prepare("UPDATE emergency_access SET status = ?1, updated_at = ?2 WHERE id = ?3")
        .bind(&[
            EMERGENCY_STATUS_RECOVERY_APPROVED.into(),
            now.into(),
            id.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    touch_participants(&db, &emergency).await?;
    let response = load_emergency(&db, &emergency.id).await?.to_json();
    Ok(Json(response))
}

#[worker::send]
pub async fn reject_emergency_access(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let emergency = load_by_grantor(&db, &id, &claims.sub).await?;
    if !matches!(
        emergency.status,
        EMERGENCY_STATUS_RECOVERY_INITIATED | EMERGENCY_STATUS_RECOVERY_APPROVED
    ) {
        return Err(AppError::BadRequest(
            "Emergency access not valid.".to_string(),
        ));
    }
    let now = db::now_rfc3339_millis();
    db.prepare(
        "UPDATE emergency_access SET status = ?1, recovery_initiated_at = NULL,
         last_notification_at = NULL, updated_at = ?2 WHERE id = ?3",
    )
    .bind(&[EMERGENCY_STATUS_CONFIRMED.into(), now.into(), id.into()])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    touch_participants(&db, &emergency).await?;
    let response = load_emergency(&db, &emergency.id).await?.to_json();
    Ok(Json(response))
}

fn ensure_approved(
    emergency: &EmergencyAccess,
    user_id: &str,
    access_type: i32,
) -> Result<(), AppError> {
    if emergency.is_approved_for(user_id, access_type) {
        Ok(())
    } else {
        Err(AppError::BadRequest(
            "Emergency access not valid.".to_string(),
        ))
    }
}

#[worker::send]
pub async fn view_emergency_access(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let emergency = load_by_grantee(&db, &id, &claims.sub).await?;
    ensure_approved(&emergency, &claims.sub, EMERGENCY_TYPE_VIEW)?;
    let models: Vec<CipherDBModel> = db
        .prepare(
            "SELECT c.id, c.user_id, c.organization_id, c.type, c.data, c.key,
                    c.favorite, c.folder_id, c.deleted_at, a.archived_at,
                    c.created_at, c.updated_at, 1 AS access_edit, 1 AS access_view_password
             FROM ciphers c
             LEFT JOIN archives a ON a.cipher_id = c.id AND a.user_id = ?1
             WHERE c.user_id = ?1 ORDER BY c.updated_at",
        )
        .bind(&[emergency.grantor_uuid.clone().into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let mut ciphers = models.into_iter().map(Cipher::from).collect::<Vec<_>>();
    super::ciphers::attachments::enrich_ciphers(&db, &state, &mut ciphers).await?;
    Ok(Json(json!({
        "ciphers": ciphers,
        "keyEncrypted": emergency.key_encrypted,
        "object": "emergencyAccessView"
    })))
}

#[worker::send]
pub async fn takeover_emergency_access(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let emergency = load_by_grantee(&db, &id, &claims.sub).await?;
    ensure_approved(&emergency, &claims.sub, EMERGENCY_TYPE_TAKEOVER)?;
    let grantor = load_user(&db, &emergency.grantor_uuid).await?;
    Ok(Json(json!({
        "kdf": grantor.kdf_type,
        "kdfIterations": grantor.kdf_iterations,
        "kdfMemory": grantor.kdf_memory,
        "kdfParallelism": grantor.kdf_parallelism,
        "keyEncrypted": emergency.key_encrypted,
        "object": "emergencyAccessTakeover"
    })))
}

#[worker::send]
pub async fn password_emergency_access(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(data): Json<EmergencyAccessPasswordData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    if data.new_master_password_hash.is_empty() || data.key.is_empty() {
        return Err(AppError::BadRequest(
            "New master password hash and key are required.".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let emergency = load_by_grantee(&db, &id, &claims.sub).await?;
    ensure_approved(&emergency, &claims.sub, EMERGENCY_TYPE_TAKEOVER)?;
    let grantor = load_user(&db, &emergency.grantor_uuid).await?;
    let server_password = password::hash_password(&data.new_master_password_hash, None).await?;
    let security_stamp = Uuid::new_v4().to_string();
    let now = db::now_rfc3339_millis();
    db.prepare(
        "UPDATE users SET master_password_hash = ?1, key = ?2, security_stamp = ?3,
         password_salt = ?4, password_iterations = ?5, updated_at = ?6 WHERE id = ?7",
    )
    .bind(&[
        server_password.hash.into(),
        data.key.into(),
        security_stamp.into(),
        server_password.salt.into(),
        server_password.iterations.into(),
        now.clone().into(),
        grantor.id.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    crate::db::models::two_factor::delete_all_two_factors(&db, &grantor.id).await?;
    db.prepare("DELETE FROM users_organizations WHERE user_id = ?1 AND type <> 0")
        .bind(&[grantor.id.clone().into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    notifications::publish_user_update_background(
        &state.ctx,
        state.env.clone(),
        UpdateType::LogOut,
        grantor.id.clone(),
        now,
        None,
    );
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        crate::extensions::notify::NotifyEvent::PasswordChange,
        crate::extensions::notify::NotifyContext {
            user_id: Some(grantor.id),
            user_email: Some(grantor.email),
            detail: Some("Password changed by an approved emergency contact".to_string()),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn policies_emergency_access(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let emergency = load_by_grantee(&db, &id, &claims.sub).await?;
    ensure_approved(&emergency, &claims.sub, EMERGENCY_TYPE_TAKEOVER)?;
    let policies =
        super::organizations::sync_policies(&db, &state.env, &emergency.grantor_uuid).await?;
    Ok(Json(list_response(policies)))
}

pub async fn process_recovery_timeouts(env: &Env) -> Result<usize, AppError> {
    if !emergency_access_enabled(env) {
        return Ok(0);
    }
    let db = db::get_db(env)?;
    let due: Vec<EmergencyAccess> = db
        .prepare(
            "SELECT * FROM emergency_access
             WHERE status = ?1 AND recovery_initiated_at IS NOT NULL
               AND datetime(recovery_initiated_at, '+' || wait_time_days || ' days') <= datetime('now')",
        )
        .bind(&[EMERGENCY_STATUS_RECOVERY_INITIATED.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    for emergency in &due {
        let now = db::now_rfc3339_millis();
        db.prepare("UPDATE emergency_access SET status = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(&[
                EMERGENCY_STATUS_RECOVERY_APPROVED.into(),
                now.into(),
                emergency.id.clone().into(),
            ])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        touch_participants(&db, emergency).await?;
    }
    Ok(due.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_vaultwarden_emergency_access_types() {
        assert_eq!(parse_access_type(&json!(0)).unwrap(), EMERGENCY_TYPE_VIEW);
        assert_eq!(
            parse_access_type(&json!("View")).unwrap(),
            EMERGENCY_TYPE_VIEW
        );
        assert_eq!(
            parse_access_type(&json!("Takeover")).unwrap(),
            EMERGENCY_TYPE_TAKEOVER
        );
        assert!(parse_access_type(&json!("invalid")).is_err());
    }

    #[test]
    fn wait_time_is_bounded() {
        assert!(validate_wait_time(0).is_ok());
        assert!(validate_wait_time(365).is_ok());
        assert!(validate_wait_time(-1).is_err());
        assert!(validate_wait_time(366).is_err());
    }
}
