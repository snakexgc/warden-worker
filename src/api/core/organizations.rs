pub use super::imports::import_organization;

use axum::http::HeaderMap;
use axum::{
    Json,
    extract::{Path, Query, State},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;
use worker::D1Database;

use crate::{
    api::AppState,
    api::notifications::{self, UpdateType},
    auth::{Claims, InviteClaims},
    crypto::password,
    db,
    db::models::{
        Collection, Group, MEMBER_STATUS_ACCEPTED, MEMBER_STATUS_CONFIRMED, MEMBER_STATUS_INVITED,
        MEMBER_TYPE_ADMIN, MEMBER_TYPE_MANAGER, MEMBER_TYPE_OWNER, MEMBER_TYPE_USER, Membership,
        OrgPolicy, Organization, OrganizationApiKey,
    },
    error::AppError,
    extensions::notify::{self, ActionLinkType},
};

const INVITE_ISSUER: &str = "warden-worker.org-invite";
const REVOKE_OFFSET: i32 = 128;
const SSO_PLACEHOLDER_ORG_ID: &str = "00000000-01DC-01DC-01DC-000000000000";

#[worker::send]
pub async fn get_policies(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    Ok(Json(json!([])))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgData {
    billing_email: String,
    collection_name: String,
    key: String,
    name: String,
    #[serde(default)]
    keys: Option<OrgKeyData>,
    #[serde(default)]
    plan_type: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgKeyData {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrganizationUpdateData {
    billing_email: String,
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionData {
    name: String,
    #[serde(default)]
    external_id: Option<String>,
    #[serde(default)]
    users: Vec<CollectionAccessData>,
    #[serde(default)]
    groups: Vec<CollectionAccessData>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionAccessData {
    id: String,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    hide_passwords: bool,
    #[serde(default)]
    manage: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupRequest {
    name: String,
    #[serde(default)]
    access_all: bool,
    #[serde(default)]
    external_id: Option<String>,
    #[serde(default)]
    collections: Vec<CollectionAccessData>,
    #[serde(default)]
    users: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkCollectionAccessData {
    collection_ids: Vec<String>,
    #[serde(default)]
    groups: Vec<CollectionAccessData>,
    #[serde(default)]
    users: Vec<CollectionAccessData>,
}

#[derive(Debug, Deserialize)]
pub struct BulkIdsData {
    ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InviteData {
    emails: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(rename = "type")]
    member_type: Value,
    #[serde(default)]
    collections: Vec<CollectionAccessData>,
    #[serde(default)]
    permissions: serde_json::Map<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EditMemberData {
    #[serde(rename = "type")]
    member_type: Value,
    #[serde(default)]
    collections: Option<Vec<CollectionAccessData>>,
    #[serde(default)]
    groups: Option<Vec<String>>,
    #[serde(default)]
    permissions: serde_json::Map<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcceptData {
    token: String,
    #[serde(default)]
    reset_password_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmData {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BulkConfirmData {
    #[serde(default)]
    keys: Vec<ConfirmData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteOrganizationData {
    #[serde(default)]
    master_password_hash: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberQuery {
    #[serde(default)]
    include_collections: bool,
    #[serde(default)]
    include_groups: bool,
}

#[derive(Debug, Deserialize)]
pub struct PolicyData {
    enabled: bool,
    #[serde(default)]
    data: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub struct PutPolicyData {
    policy: PolicyData,
}

#[derive(Debug, Deserialize)]
pub struct InviteTokenQuery {
    token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordEnrollmentData {
    #[serde(default)]
    reset_password_key: Option<String>,
    #[serde(default)]
    master_password_hash: Option<String>,
    #[serde(default)]
    otp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverAccountData {
    new_master_password_hash: String,
    key: String,
    #[serde(default)]
    reset_master_password: bool,
    #[serde(default)]
    reset_two_factor: bool,
}

#[derive(Debug, Deserialize)]
struct MemberUserRow {
    id: String,
    user_id: String,
    organization_id: String,
    invited_by_email: Option<String>,
    access_all: i32,
    key: String,
    status: i32,
    #[serde(rename = "type")]
    member_type: i32,
    reset_password_key: Option<String>,
    external_id: Option<String>,
    permissions: String,
    created_at: String,
    updated_at: String,
    user_name: Option<String>,
    user_email: String,
    avatar_color: Option<String>,
    has_master_password: i32,
}

impl MemberUserRow {
    fn membership(&self) -> Membership {
        Membership {
            id: self.id.clone(),
            user_id: self.user_id.clone(),
            organization_id: self.organization_id.clone(),
            invited_by_email: self.invited_by_email.clone(),
            access_all: self.access_all,
            key: self.key.clone(),
            status: self.status,
            member_type: self.member_type,
            reset_password_key: self.reset_password_key.clone(),
            external_id: self.external_id.clone(),
            permissions: self.permissions.clone(),
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
        }
    }
}

pub(crate) fn organizations_enabled(_env: &worker::Env) -> bool {
    true
}

pub(crate) fn events_enabled(env: &worker::Env) -> bool {
    env_bool(env, "ORG_EVENTS_ENABLED", false)
}

pub(crate) fn groups_enabled(env: &worker::Env) -> bool {
    env_bool(env, "ORG_GROUPS_ENABLED", false)
}

fn env_bool(env: &worker::Env, name: &str, default: bool) -> bool {
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

fn ensure_enabled(env: &worker::Env) -> Result<(), AppError> {
    if organizations_enabled(env) {
        Ok(())
    } else {
        Err(AppError::NotFound(
            "Organization support is disabled".to_string(),
        ))
    }
}

pub(crate) fn validate_name(name: &str, field: &str) -> Result<String, AppError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(AppError::BadRequest(format!(
            "{field} must contain between 1 and 100 characters"
        )));
    }
    Ok(name.to_string())
}

fn list_response(data: Vec<Value>) -> Value {
    json!({
        "data": data,
        "object": "list",
        "continuationToken": null
    })
}

fn valid_policy_type(policy_type: i32) -> bool {
    matches!(policy_type, 0 | 1 | 2 | 3 | 5 | 6 | 7 | 8 | 14 | 15 | 16)
}

pub(crate) async fn load_organization(
    db: &D1Database,
    org_id: &str,
) -> Result<Organization, AppError> {
    db.prepare("SELECT * FROM organizations WHERE id = ?1")
        .bind(&[org_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))
}

pub(crate) async fn load_membership(
    db: &D1Database,
    user_id: &str,
    org_id: &str,
) -> Result<Membership, AppError> {
    db.prepare("SELECT * FROM users_organizations WHERE user_id = ?1 AND organization_id = ?2")
        .bind(&[user_id.into(), org_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))
}

pub(crate) async fn validate_membership_policies(
    db: &D1Database,
    member: &Membership,
) -> Result<(), AppError> {
    if member.is_admin() {
        return Ok(());
    }
    let required_2fa: Option<i32> = db
        .prepare(
            "SELECT 1 AS enabled FROM org_policies
             WHERE organization_id = ?1 AND type = 0 AND enabled = 1 LIMIT 1",
        )
        .bind(&[member.organization_id.clone().into()])?
        .first(Some("enabled"))
        .await
        .map_err(|_| AppError::Database)?;
    if required_2fa.is_some()
        && !crate::db::models::two_factor::is_any_enabled(db, &member.user_id).await?
    {
        return Err(AppError::Forbidden(
            "Cannot join because two-factor authentication is required".to_string(),
        ));
    }

    let single_org_conflict: Option<i32> = db
        .prepare(
            "SELECT 1 AS conflict
             FROM users_organizations other
             JOIN org_policies p ON p.organization_id = other.organization_id
             WHERE other.user_id = ?1 AND other.organization_id <> ?2
               AND other.status IN (?3, ?4) AND other.type NOT IN (?5, ?6)
               AND p.type = 3 AND p.enabled = 1 LIMIT 1",
        )
        .bind(&[
            member.user_id.clone().into(),
            member.organization_id.clone().into(),
            MEMBER_STATUS_ACCEPTED.into(),
            MEMBER_STATUS_CONFIRMED.into(),
            MEMBER_TYPE_OWNER.into(),
            MEMBER_TYPE_ADMIN.into(),
        ])?
        .first(Some("conflict"))
        .await
        .map_err(|_| AppError::Database)?;
    if single_org_conflict.is_some() {
        return Err(AppError::Forbidden(
            "Another organization policy forbids joining this organization".to_string(),
        ));
    }

    let target_single_org: Option<i32> = db
        .prepare(
            "SELECT 1 AS enabled FROM org_policies
             WHERE organization_id = ?1 AND type = 3 AND enabled = 1 LIMIT 1",
        )
        .bind(&[member.organization_id.clone().into()])?
        .first(Some("enabled"))
        .await
        .map_err(|_| AppError::Database)?;
    if target_single_org.is_some() {
        let other_membership: Option<i32> = db
            .prepare(
                "SELECT 1 AS found FROM users_organizations
                 WHERE user_id = ?1 AND organization_id <> ?2
                   AND status IN (?3, ?4) LIMIT 1",
            )
            .bind(&[
                member.user_id.clone().into(),
                member.organization_id.clone().into(),
                MEMBER_STATUS_ACCEPTED.into(),
                MEMBER_STATUS_CONFIRMED.into(),
            ])?
            .first(Some("found"))
            .await
            .map_err(|_| AppError::Database)?;
        if other_membership.is_some() {
            return Err(AppError::Forbidden(
                "The organization policy forbids membership in another organization".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn require_confirmed(member: &Membership) -> Result<(), AppError> {
    if member.is_confirmed() {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Organization membership is not confirmed".to_string(),
        ))
    }
}

pub(crate) fn require_admin(member: &Membership) -> Result<(), AppError> {
    require_confirmed(member)?;
    if member.is_admin() {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Organization administrator access is required".to_string(),
        ))
    }
}

pub(crate) async fn member_has_group_full_access(
    db: &D1Database,
    member: &Membership,
) -> Result<bool, AppError> {
    let row: Option<Value> = db
        .prepare(
            "SELECT 1 AS allowed
             FROM groups_users gu
             JOIN groups g ON g.id = gu.group_id
             WHERE gu.membership_id = ?1
               AND g.organization_id = ?2
               AND g.access_all = 1
             LIMIT 1",
        )
        .bind(&[
            member.id.clone().into(),
            member.organization_id.clone().into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    Ok(row.is_some())
}

pub(crate) async fn member_has_full_access(
    db: &D1Database,
    member: &Membership,
) -> Result<bool, AppError> {
    if member.has_full_access() {
        return Ok(true);
    }
    member_has_group_full_access(db, member).await
}

pub(crate) fn require_owner(member: &Membership) -> Result<(), AppError> {
    require_confirmed(member)?;
    if member.is_owner() {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Organization owner access is required".to_string(),
        ))
    }
}

fn require_collection_manager(member: &Membership) -> Result<(), AppError> {
    require_confirmed(member)?;
    // 对齐 Vaultwarden ManagerHeadersLoose：Manager/Admin/Owner 均可，不要求 access_all
    if member.member_type != MEMBER_TYPE_USER {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Collection management access is required".to_string(),
        ))
    }
}

pub(crate) async fn touch_organization_members(
    db: &D1Database,
    org_id: &str,
) -> Result<String, AppError> {
    let revision = db::now_rfc3339_millis();
    db.prepare(
        "UPDATE users SET updated_at = ?1 WHERE id IN (
             SELECT user_id FROM users_organizations
             WHERE organization_id = ?2 AND status = ?3
         )",
    )
    .bind(&[
        revision.clone().into(),
        org_id.into(),
        MEMBER_STATUS_CONFIRMED.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(revision)
}

#[worker::send]
pub async fn get_organizations(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    if !organizations_enabled(&state.env) {
        return Ok(Json(json!([])));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let rows: Vec<Value> = db
        .prepare(
            "SELECT o.* FROM organizations o
             JOIN users_organizations m ON m.organization_id = o.id
             WHERE m.user_id = ?1 AND m.status >= ?2
             ORDER BY o.name COLLATE NOCASE",
        )
        .bind(&[claims.sub.into(), MEMBER_STATUS_INVITED.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let organizations = rows
        .into_iter()
        .filter_map(|row| serde_json::from_value::<Organization>(row).ok())
        .map(|org| {
            org.to_json(
                events_enabled(&state.env),
                groups_enabled(&state.env),
                notify::is_email_webhook_configured(&state.env),
            )
        })
        .collect();
    Ok(Json(Value::Array(organizations)))
}

#[worker::send]
pub async fn create_organization(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Json(data): Json<OrgData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;

    let name = validate_name(&data.name, "Organization name")?;
    let collection_name = validate_name(&data.collection_name, "Collection name")?;
    let billing_email = crate::auth::normalize_email(&data.billing_email);
    if billing_email.is_empty() || data.key.trim().is_empty() {
        return Err(AppError::BadRequest(
            "billingEmail and key are required".to_string(),
        ));
    }
    let _ = data.plan_type;
    let now = db::now_rfc3339_millis();
    let org_id = Uuid::new_v4().to_string();
    let org_id_for_event = org_id.clone();
    let member_id = Uuid::new_v4().to_string();
    let collection_id = Uuid::new_v4().to_string();
    let (private_key, public_key) = data
        .keys
        .map(|keys| (Some(keys.encrypted_private_key), Some(keys.public_key)))
        .unwrap_or((None, None));

    let org = Organization {
        id: org_id.clone(),
        name: name.clone(),
        billing_email: billing_email.clone(),
        private_key: private_key.clone(),
        public_key: public_key.clone(),
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    db.batch(vec![
        db.prepare(
            "INSERT INTO organizations
             (id, name, billing_email, private_key, public_key, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(&[
            org_id.clone().into(),
            name.into(),
            billing_email.into(),
            private_key.into(),
            public_key.into(),
            now.clone().into(),
            now.clone().into(),
        ])?,
        db.prepare(
            "INSERT INTO users_organizations
             (id, user_id, organization_id, invited_by_email, access_all, key, status, type,
              reset_password_key, external_id, permissions, created_at, updated_at)
             VALUES (?1, ?2, ?3, NULL, 1, ?4, ?5, ?6, NULL, NULL, '{}', ?7, ?8)",
        )
        .bind(&[
            member_id.into(),
            claims.sub.clone().into(),
            org_id.clone().into(),
            data.key.into(),
            MEMBER_STATUS_CONFIRMED.into(),
            MEMBER_TYPE_OWNER.into(),
            now.clone().into(),
            now.clone().into(),
        ])?,
        db.prepare(
            "INSERT INTO collections (id, organization_id, name, external_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, NULL, ?4, ?5)",
        )
        .bind(&[
            collection_id.into(),
            org_id.into(),
            collection_name.into(),
            now.clone().into(),
            now.into(),
        ])?,
    ])
    .await
    .map_err(|_| AppError::Database)?;

    super::events::log_event(
        &db,
        &state.env,
        1600,
        None,
        Some(&org_id_for_event),
        None,
        &claims.sub,
    )
    .await?;

    Ok(Json(org.to_json(
        events_enabled(&state.env),
        groups_enabled(&state.env),
        notify::is_email_webhook_configured(&state.env),
    )))
}

#[worker::send]
pub async fn get_organization(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_owner(&member)?;
    let org = load_organization(&db, &org_id).await?;
    Ok(Json(org.to_json(
        events_enabled(&state.env),
        groups_enabled(&state.env),
        notify::is_email_webhook_configured(&state.env),
    )))
}

#[worker::send]
pub async fn update_organization(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<OrganizationUpdateData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_owner(&member)?;
    let name = validate_name(&data.name, "Organization name")?;
    let billing_email = crate::auth::normalize_email(&data.billing_email);
    if billing_email.is_empty() {
        return Err(AppError::BadRequest("billingEmail is required".to_string()));
    }
    let now = db::now_rfc3339_millis();
    db.prepare(
        "UPDATE organizations SET name = ?1, billing_email = ?2, updated_at = ?3 WHERE id = ?4",
    )
    .bind(&[
        name.into(),
        billing_email.into(),
        now.into(),
        org_id.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    touch_organization_members(&db, &org_id).await?;
    let org = load_organization(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1600,
        None,
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(org.to_json(
        events_enabled(&state.env),
        groups_enabled(&state.env),
        notify::is_email_webhook_configured(&state.env),
    )))
}

#[worker::send]
pub async fn set_organization_keys(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<OrgKeyData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    let org = load_organization(&db, &org_id).await?;
    if org.private_key.is_some() || org.public_key.is_some() {
        return Err(AppError::BadRequest(
            "Organization keys already exist".to_string(),
        ));
    }
    db.prepare(
        "UPDATE organizations SET private_key = ?1, public_key = ?2, updated_at = ?3 WHERE id = ?4",
    )
    .bind(&[
        data.encrypted_private_key.clone().into(),
        data.public_key.clone().into(),
        db::now_rfc3339_millis().into(),
        org_id.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    let revision = touch_organization_members(&db, &org_id).await?;
    // 对齐 Vaultwarden：组织密钥变更后向全部已确认成员广播 SyncOrgKeys
    let members: Vec<Value> = db
        .prepare(
            "SELECT user_id FROM users_organizations
             WHERE organization_id = ?1 AND status = 2",
        )
        .bind(&[org_id.clone().into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    for member in members {
        let Some(user_id) = member.get("user_id").and_then(Value::as_str) else {
            continue;
        };
        notifications::publish_user_update_background(
            &state.ctx,
            state.env.clone(),
            UpdateType::SyncOrgKeys,
            user_id.to_string(),
            revision.clone(),
            if user_id == claims.sub {
                claims.device.clone()
            } else {
                None
            },
        );
    }
    Ok(Json(json!({
        "object": "organizationKeys",
        "publicKey": data.public_key,
        "privateKey": data.encrypted_private_key
    })))
}

/// Vaultwarden returns one synthetic verified SSO domain so current clients
/// can prefill their SSO organization selector. This project does not expose
/// an SSO login flow, but keeping the response contract avoids a client-side
/// dead end without claiming that SSO itself is enabled.
#[worker::send]
pub async fn get_org_domain_sso_verified(State(state): State<Arc<AppState>>) -> Json<Value> {
    let domain = state.public_url("");
    Json(json!({
        "object": "list",
        "data": [{
            "organizationIdentifier": "vaultwarden",
            "organizationName": "vaultwarden",
            "domainName": domain
        }],
        "continuationToken": null
    }))
}

async fn organization_api_key(
    claims: Claims,
    state: Arc<AppState>,
    org_id: String,
    data: crate::api::core::accounts::SecretVerificationRequest,
    rotate: bool,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    crate::api::core::accounts::validate_password_or_otp(&db, &claims.sub, &data).await?;

    let existing: Option<OrganizationApiKey> = db
        .prepare("SELECT id, organization_id, type, api_key, revision_date FROM organization_api_key WHERE organization_id = ?1")
        .bind(&[org_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;

    let record = match existing {
        Some(mut record) if rotate => {
            record.api_key = crate::crypto::generate_api_key();
            record.revision_date = db::now_rfc3339_millis();
            db.prepare(
                "UPDATE organization_api_key SET api_key = ?1, revision_date = ?2 WHERE id = ?3 AND organization_id = ?4",
            )
            .bind(&[
                record.api_key.clone().into(),
                record.revision_date.clone().into(),
                record.id.clone().into(),
                org_id.into(),
            ])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
            record
        }
        Some(record) => record,
        None => {
            let record = OrganizationApiKey {
                id: Uuid::new_v4().to_string(),
                organization_id: org_id.clone(),
                key_type: 0,
                api_key: crate::crypto::generate_api_key(),
                revision_date: db::now_rfc3339_millis(),
            };
            db.prepare(
                "INSERT INTO organization_api_key (id, organization_id, type, api_key, revision_date) VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&[
                record.id.clone().into(),
                record.organization_id.clone().into(),
                record.key_type.into(),
                record.api_key.clone().into(),
                record.revision_date.clone().into(),
            ])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
            record
        }
    };

    Ok(Json(json!({
        "apiKey": record.api_key,
        "revisionDate": record.revision_date,
        "object": "apiKey"
    })))
}

#[worker::send]
pub async fn post_organization_api_key(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<crate::api::core::accounts::SecretVerificationRequest>,
) -> Result<Json<Value>, AppError> {
    organization_api_key(claims, state, org_id, data, false).await
}

#[worker::send]
pub async fn rotate_organization_api_key(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<crate::api::core::accounts::SecretVerificationRequest>,
) -> Result<Json<Value>, AppError> {
    organization_api_key(claims, state, org_id, data, true).await
}

#[worker::send]
pub async fn delete_organization(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<DeleteOrganizationData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_owner(&member)?;
    let master_password_hash = data
        .master_password_hash
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("masterPasswordHash is required".to_string()))?;
    if !password::verify_user_password(&db, &claims.sub, master_password_hash).await? {
        return Err(AppError::BadRequest("Invalid credentials".to_string()));
    }
    let org_id_for_event = org_id.clone();
    db.prepare("DELETE FROM organizations WHERE id = ?1")
        .bind(&[org_id.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    db::update_user_revision(&db, &claims.sub).await?;
    super::events::log_event(
        &db,
        &state.env,
        1600,
        None,
        Some(&org_id_for_event),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn get_organization_public_key(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_confirmed(&member)?;
    let organization = load_organization(&db, &org_id).await?;
    Ok(Json(json!({
        "object": "organizationPublicKey",
        "publicKey": organization.public_key
    })))
}

#[worker::send]
pub async fn get_plans() -> Json<Value> {
    Json(json!({
        "object": "list",
        "data": [{
            "object": "plan",
            "type": 0,
            "product": 0,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 0,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        }, {
            "object": "plan",
            "type": 0,
            "product": 1,
            "name": "Free",
            "nameLocalizationKey": "planNameFree",
            "bitwardenProduct": 1,
            "maxUsers": 0,
            "descriptionLocalizationKey": "planDescFree"
        }],
        "continuationToken": null
    }))
}

#[worker::send]
pub async fn get_billing_metadata(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_confirmed(&member)?;
    Ok(Json(list_response(Vec::new())))
}

#[worker::send]
pub async fn get_billing_warnings(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_confirmed(&member)?;
    Ok(Json(json!({
        "freeTrial": null,
        "inactiveSubscription": null,
        "resellerRenewal": null,
        "taxId": null
    })))
}

#[worker::send]
pub async fn get_self_host_billing_metadata(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_confirmed(&member)?;
    Ok(Json(json!({
        "isOnSecretsManagerStandalone": false,
        "organizationOccupiedSeats": 0
    })))
}

#[worker::send]
pub async fn export_organization(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    let collections: Vec<Collection> = db
        .prepare(
            "SELECT * FROM collections WHERE organization_id = ?1 ORDER BY name COLLATE NOCASE",
        )
        .bind(&[org_id.clone().into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let mut ciphers = super::ciphers::get_accessible_ciphers(&db, true, &claims.sub).await?;
    ciphers.retain(|cipher| cipher.organization_id.as_deref() == Some(&org_id));
    Ok(Json(json!({
        "collections": collections.into_iter().map(|collection| collection.to_json()).collect::<Vec<_>>(),
        "ciphers": ciphers
    })))
}

#[worker::send]
pub async fn leave_organization(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_confirmed(&member)?;
    delete_membership_preserving_owner(&db, &org_id, &member.id).await?;
    db::update_user_revision(&db, &claims.sub).await?;
    super::events::log_event(
        &db,
        &state.env,
        1516,
        Some(&claims.sub),
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn get_collections(
    claims: Claims,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    if !organizations_enabled(&state.env) {
        return Ok(Json(list_response(Vec::new())));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let rows: Vec<Value> = db
        .prepare(
            "SELECT DISTINCT c.* FROM collections c
             JOIN users_organizations m ON m.organization_id = c.organization_id
             LEFT JOIN users_collections uc
                ON uc.collection_id = c.id AND uc.membership_id = m.id
             LEFT JOIN groups_users gu ON gu.membership_id = m.id
             LEFT JOIN groups g
                ON g.id = gu.group_id AND g.organization_id = m.organization_id
             LEFT JOIN collections_groups cg
                ON cg.group_id = g.id AND cg.collection_id = c.id
             WHERE m.user_id = ?1 AND m.status = ?2
               AND (m.type IN (?3, ?4) OR m.access_all = 1 OR uc.membership_id IS NOT NULL
                    OR cg.collection_id IS NOT NULL OR g.access_all = 1)
             ORDER BY c.name COLLATE NOCASE",
        )
        .bind(&[
            claims.sub.into(),
            MEMBER_STATUS_CONFIRMED.into(),
            MEMBER_TYPE_OWNER.into(),
            MEMBER_TYPE_ADMIN.into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let collections = rows
        .into_iter()
        .filter_map(|row| serde_json::from_value::<Collection>(row).ok())
        .map(|collection| collection.to_json())
        .collect();
    Ok(Json(list_response(collections)))
}

#[worker::send]
pub async fn get_auto_enroll_status(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(identifier): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let org_id = if identifier == SSO_PLACEHOLDER_ORG_ID {
        let org_id = db
            .prepare(
                "SELECT organization_id FROM users_organizations
             WHERE user_id = ?1 AND status = ?2
             ORDER BY created_at LIMIT 1",
            )
            .bind(&[claims.sub.clone().into(), MEMBER_STATUS_CONFIRMED.into()])?
            .first::<String>(Some("organization_id"))
            .await
            .map_err(|_| AppError::Database)?;
        let Some(org_id) = org_id else {
            return Ok(Json(json!({
                "id": identifier,
                "identifier": identifier,
                "resetPasswordEnabled": false
            })));
        };
        org_id
    } else {
        identifier.clone()
    };
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_confirmed(&member)?;
    let policy: Option<OrgPolicy> = db
        .prepare(
            "SELECT * FROM org_policies
             WHERE organization_id = ?1 AND type = 8 AND enabled = 1",
        )
        .bind(&[org_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let reset_password_enabled = policy.is_some_and(|policy| {
        serde_json::from_str::<Value>(&policy.data)
            .ok()
            .and_then(|value| {
                value
                    .get("autoEnrollEnabled")
                    .or_else(|| value.get("AutoEnrollEnabled"))
                    .and_then(Value::as_bool)
            })
            .unwrap_or(false)
    });
    Ok(Json(json!({
        "id": org_id,
        "identifier": org_id,
        "resetPasswordEnabled": reset_password_enabled
    })))
}

#[worker::send]
pub async fn get_org_collections(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_collection_manager(&member)?;
    let collections: Vec<Collection> = db
        .prepare(
            "SELECT * FROM collections WHERE organization_id = ?1 ORDER BY name COLLATE NOCASE",
        )
        .bind(&[org_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    Ok(Json(list_response(
        collections
            .into_iter()
            .map(|collection| collection.to_json())
            .collect(),
    )))
}

async fn collection_access_details_json(
    db: &D1Database,
    member: &Membership,
    collection: &Collection,
    include_groups: bool,
) -> Result<Value, AppError> {
    let (read_only, hide_passwords, manage) =
        collection_permissions(db, member, &collection.id).await?;
    let users: Vec<Value> = db
        .prepare(
            "SELECT uc.membership_id AS id, uc.read_only, uc.hide_passwords, uc.manage,
                    m.type AS member_type
             FROM users_collections uc
             JOIN users_organizations m ON m.id = uc.membership_id
             WHERE uc.collection_id = ?1 AND m.organization_id = ?2
             ORDER BY uc.membership_id",
        )
        .bind(&[
            collection.id.clone().into(),
            collection.organization_id.clone().into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results::<Value>()?
        .into_iter()
        .map(|row| {
            let elevated = row.get("member_type").and_then(Value::as_i64).unwrap_or(2) < 2;
            json!({
                "id": row.get("id").cloned().unwrap_or(Value::Null),
                "readOnly": if elevated { false } else { row.get("read_only").and_then(Value::as_i64) != Some(0) },
                "hidePasswords": if elevated { false } else { row.get("hide_passwords").and_then(Value::as_i64) != Some(0) },
                "manage": elevated || row.get("manage").and_then(Value::as_i64) == Some(1)
            })
        })
        .collect();
    let groups = if include_groups {
        db.prepare(
            "SELECT group_id AS id, read_only, hide_passwords, manage
             FROM collections_groups WHERE collection_id = ?1 ORDER BY group_id",
        )
        .bind(&[collection.id.clone().into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results::<Value>()?
        .into_iter()
        .map(|row| {
            json!({
                "id": row.get("id").cloned().unwrap_or(Value::Null),
                "readOnly": row.get("read_only").and_then(Value::as_i64) != Some(0),
                "hidePasswords": row.get("hide_passwords").and_then(Value::as_i64) != Some(0),
                "manage": row.get("manage").and_then(Value::as_i64) == Some(1)
            })
        })
        .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut value = collection.to_details_json(read_only, hide_passwords, manage);
    value["assigned"] = json!(true);
    value["users"] = json!(users);
    value["groups"] = json!(groups);
    value["object"] = json!("collectionAccessDetails");
    value["unmanaged"] = json!(false);
    Ok(value)
}

#[worker::send]
pub async fn get_org_collections_details(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_confirmed(&member)?;
    let full_access = member_has_full_access(&db, &member).await?;
    let rows: Vec<Collection> = db
        .prepare(
            "SELECT DISTINCT c.* FROM collections c
             LEFT JOIN users_collections uc
               ON uc.collection_id = c.id AND uc.membership_id = ?1
             LEFT JOIN groups_users gu ON gu.membership_id = ?1
             LEFT JOIN groups g
               ON g.id = gu.group_id AND g.organization_id = c.organization_id
             LEFT JOIN collections_groups cg
               ON cg.group_id = g.id AND cg.collection_id = c.id
             WHERE c.organization_id = ?2
               AND (?3 = 1 OR uc.membership_id IS NOT NULL
                    OR cg.collection_id IS NOT NULL OR g.access_all = 1)
             ORDER BY c.name COLLATE NOCASE",
        )
        .bind(&[member.id.clone().into(), org_id.into(), full_access.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let mut details = Vec::with_capacity(rows.len());
    for collection in rows {
        details.push(
            collection_access_details_json(&db, &member, &collection, groups_enabled(&state.env))
                .await?,
        );
    }
    Ok(Json(list_response(details)))
}

#[worker::send]
pub async fn create_collection(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<CollectionData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_collection_manager(&member)?;
    validate_collection_assignments(&db, &org_id, &data.users, &data.groups).await?;

    let collection = Collection {
        id: Uuid::new_v4().to_string(),
        organization_id: org_id.clone(),
        name: validate_name(&data.name, "Collection name")?,
        external_id: data.external_id.filter(|value| !value.trim().is_empty()),
        created_at: db::now_rfc3339_millis(),
        updated_at: db::now_rfc3339_millis(),
    };
    let mut statements = vec![
        db.prepare(
            "INSERT INTO collections (id, organization_id, name, external_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(&[
            collection.id.clone().into(),
            collection.organization_id.clone().into(),
            collection.name.clone().into(),
            collection.external_id.clone().into(),
            collection.created_at.clone().into(),
            collection.updated_at.clone().into(),
        ])?,
    ];
    for access in &data.users {
        statements.push(collection_user_statement(&db, &collection.id, access)?);
    }
    for access in &data.groups {
        statements.push(collection_group_statement(&db, &collection.id, access)?);
    }
    db.batch(statements).await.map_err(|_| AppError::Database)?;
    touch_organization_members(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1300,
        None,
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(collection.to_json()))
}

#[worker::send]
pub async fn get_org_collection(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, collection_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_confirmed(&member)?;
    let collection = load_collection(&db, &org_id, &collection_id).await?;
    let (read_only, hide_passwords, manage) =
        collection_permissions(&db, &member, &collection_id).await?;
    if !member.has_full_access() && !manage && read_only && hide_passwords {
        return Err(AppError::NotFound("Collection not found".to_string()));
    }
    Ok(Json(collection.to_details_json(
        read_only,
        hide_passwords,
        manage,
    )))
}

#[worker::send]
pub async fn get_org_collection_details(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, collection_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_confirmed(&member)?;
    let collection = load_collection(&db, &org_id, &collection_id).await?;
    let (read_only, hide_passwords, manage) =
        collection_permissions(&db, &member, &collection_id).await?;
    if !member.has_full_access() && !manage && read_only && hide_passwords {
        return Err(AppError::NotFound("Collection not found".to_string()));
    }
    let details =
        collection_access_details_json(&db, &member, &collection, groups_enabled(&state.env))
            .await?;
    Ok(Json(details))
}

#[worker::send]
pub async fn get_collection_users(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, collection_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_collection_manager(&member)?;
    load_collection(&db, &org_id, &collection_id).await?;
    let users: Vec<Value> = db
        .prepare(
            "SELECT membership_id AS id, read_only, hide_passwords, manage
             FROM users_collections WHERE collection_id = ?1 ORDER BY membership_id",
        )
        .bind(&[collection_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results::<Value>()?
        .into_iter()
        .map(|row| {
            json!({
                "id": row.get("id").cloned().unwrap_or(Value::Null),
                "readOnly": row.get("read_only").and_then(Value::as_i64) != Some(0),
                "hidePasswords": row.get("hide_passwords").and_then(Value::as_i64) != Some(0),
                "manage": row.get("manage").and_then(Value::as_i64) == Some(1)
            })
        })
        .collect();
    Ok(Json(Value::Array(users)))
}

#[worker::send]
pub async fn update_collection(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, collection_id)): Path<(String, String)>,
    Json(data): Json<CollectionData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_collection_manager(&member)?;
    load_collection(&db, &org_id, &collection_id).await?;
    validate_collection_assignments(&db, &org_id, &data.users, &data.groups).await?;
    let name = validate_name(&data.name, "Collection name")?;
    let external_id = data.external_id.filter(|value| !value.trim().is_empty());
    let now = db::now_rfc3339_millis();
    let mut statements = vec![
        db.prepare(
            "UPDATE collections SET name = ?1, external_id = ?2, updated_at = ?3
             WHERE id = ?4 AND organization_id = ?5",
        )
        .bind(&[
            name.clone().into(),
            external_id.clone().into(),
            now.clone().into(),
            collection_id.clone().into(),
            org_id.clone().into(),
        ])?,
        db.prepare("DELETE FROM users_collections WHERE collection_id = ?1")
            .bind(&[collection_id.clone().into()])?,
        db.prepare("DELETE FROM collections_groups WHERE collection_id = ?1")
            .bind(&[collection_id.clone().into()])?,
    ];
    for access in &data.users {
        statements.push(collection_user_statement(&db, &collection_id, access)?);
    }
    for access in &data.groups {
        statements.push(collection_group_statement(&db, &collection_id, access)?);
    }
    db.batch(statements).await.map_err(|_| AppError::Database)?;
    touch_organization_members(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1301,
        None,
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    let collection = Collection {
        id: collection_id,
        organization_id: org_id,
        name,
        external_id,
        created_at: now.clone(),
        updated_at: now,
    };
    Ok(Json(collection.to_json()))
}

#[worker::send]
pub async fn delete_collection(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, collection_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_collection_manager(&member)?;
    load_collection(&db, &org_id, &collection_id).await?;
    db.prepare("DELETE FROM collections WHERE id = ?1 AND organization_id = ?2")
        .bind(&[collection_id.into(), org_id.clone().into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    touch_organization_members(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1302,
        None,
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn bulk_access_collections(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkCollectionAccessData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    if data.collection_ids.len() > 20 {
        return Err(AppError::BadRequest(
            "At most 20 collections can be updated in one request".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_confirmed(&member)?;
    validate_collection_assignments(&db, &org_id, &data.users, &data.groups).await?;
    for collection_id in &data.collection_ids {
        load_collection(&db, &org_id, collection_id).await?;
        let (_, _, manage) = collection_permissions(&db, &member, collection_id).await?;
        if !member.has_full_access() && !manage {
            return Err(AppError::NotFound("Collection not found".to_string()));
        }
    }
    for collection_id in &data.collection_ids {
        let mut statements = vec![
            db.prepare("DELETE FROM users_collections WHERE collection_id = ?1")
                .bind(&[collection_id.clone().into()])?,
            db.prepare("DELETE FROM collections_groups WHERE collection_id = ?1")
                .bind(&[collection_id.clone().into()])?,
            db.prepare("UPDATE collections SET updated_at = ?1 WHERE id = ?2")
                .bind(&[
                    db::now_rfc3339_millis().into(),
                    collection_id.clone().into(),
                ])?,
        ];
        for access in &data.users {
            statements.push(collection_user_statement(&db, collection_id, access)?);
        }
        for access in &data.groups {
            statements.push(collection_group_statement(&db, collection_id, access)?);
        }
        db.batch(statements).await.map_err(|_| AppError::Database)?;
    }
    touch_organization_members(&db, &org_id).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn bulk_delete_collections(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkIdsData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    if data.ids.len() > 40 {
        return Err(AppError::BadRequest(
            "At most 40 collections can be deleted in one request".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_confirmed(&member)?;
    for collection_id in &data.ids {
        load_collection(&db, &org_id, collection_id).await?;
        let (_, _, manage) = collection_permissions(&db, &member, collection_id).await?;
        if !member.has_full_access() && !manage {
            return Err(AppError::NotFound("Collection not found".to_string()));
        }
    }
    let mut statements = Vec::with_capacity(data.ids.len());
    for collection_id in data.ids {
        statements.push(
            db.prepare("DELETE FROM collections WHERE id = ?1 AND organization_id = ?2")
                .bind(&[collection_id.into(), org_id.clone().into()])?,
        );
    }
    if !statements.is_empty() {
        db.batch(statements).await.map_err(|_| AppError::Database)?;
    }
    touch_organization_members(&db, &org_id).await?;
    Ok(Json(json!({})))
}

pub(crate) async fn load_collection(
    db: &D1Database,
    org_id: &str,
    collection_id: &str,
) -> Result<Collection, AppError> {
    db.prepare("SELECT * FROM collections WHERE id = ?1 AND organization_id = ?2")
        .bind(&[collection_id.into(), org_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Collection not found".to_string()))
}

async fn validate_collection_assignments(
    db: &D1Database,
    org_id: &str,
    users: &[CollectionAccessData],
    groups: &[CollectionAccessData],
) -> Result<(), AppError> {
    for access in users {
        let valid: Option<Value> = db
            .prepare(
                "SELECT 1 AS valid FROM users_organizations WHERE id = ?1 AND organization_id = ?2",
            )
            .bind(&[access.id.clone().into(), org_id.into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        if valid.is_none() {
            return Err(AppError::BadRequest(
                "Collection member does not belong to organization".to_string(),
            ));
        }
    }
    for access in groups {
        let valid: Option<Value> = db
            .prepare("SELECT 1 AS valid FROM groups WHERE id = ?1 AND organization_id = ?2")
            .bind(&[access.id.clone().into(), org_id.into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        if valid.is_none() {
            return Err(AppError::BadRequest(
                "Collection group does not belong to organization".to_string(),
            ));
        }
    }
    Ok(())
}

fn collection_user_statement(
    db: &D1Database,
    collection_id: &str,
    access: &CollectionAccessData,
) -> Result<worker::D1PreparedStatement, AppError> {
    Ok(db
        .prepare(
            "INSERT INTO users_collections
             (membership_id, collection_id, read_only, hide_passwords, manage)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&[
            access.id.clone().into(),
            collection_id.into(),
            access.read_only.into(),
            access.hide_passwords.into(),
            access.manage.into(),
        ])?)
}

fn collection_group_statement(
    db: &D1Database,
    collection_id: &str,
    access: &CollectionAccessData,
) -> Result<worker::D1PreparedStatement, AppError> {
    Ok(db
        .prepare(
            "INSERT INTO collections_groups
             (collection_id, group_id, read_only, hide_passwords, manage)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&[
            collection_id.into(),
            access.id.clone().into(),
            access.read_only.into(),
            access.hide_passwords.into(),
            access.manage.into(),
        ])?)
}

pub(crate) async fn collection_permissions(
    db: &D1Database,
    member: &Membership,
    collection_id: &str,
) -> Result<(bool, bool, bool), AppError> {
    if member.has_full_access() {
        return Ok((false, false, member.member_type != MEMBER_TYPE_USER));
    }
    if member_has_group_full_access(db, member).await? {
        // A full-access group grants read/write and password visibility for all
        // collections, but does not by itself grant collection administration.
        return Ok((false, false, false));
    }
    let direct: Option<Value> = db
        .prepare(
            "SELECT read_only, hide_passwords, manage FROM users_collections
             WHERE membership_id = ?1 AND collection_id = ?2",
        )
        .bind(&[member.id.clone().into(), collection_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    if let Some(direct) = direct {
        return Ok((
            direct.get("read_only").and_then(Value::as_i64) != Some(0),
            direct.get("hide_passwords").and_then(Value::as_i64) != Some(0),
            direct.get("manage").and_then(Value::as_i64) == Some(1),
        ));
    }
    let group: Option<Value> = db
        .prepare(
            "SELECT MIN(cg.read_only) AS read_only,
                    MIN(cg.hide_passwords) AS hide_passwords,
                    MAX(cg.manage) AS manage
             FROM collections_groups cg
             JOIN groups_users gu ON gu.group_id = cg.group_id
             WHERE gu.membership_id = ?1 AND cg.collection_id = ?2
             HAVING COUNT(*) > 0",
        )
        .bind(&[member.id.clone().into(), collection_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    if let Some(group) = group {
        return Ok((
            group.get("read_only").and_then(Value::as_i64) != Some(0),
            group.get("hide_passwords").and_then(Value::as_i64) != Some(0),
            group.get("manage").and_then(Value::as_i64) == Some(1),
        ));
    }
    Ok((true, true, false))
}

#[worker::send]
pub async fn get_members(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Query(query): Query<MemberQuery>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_collection_manager(&actor)?;
    let rows: Vec<MemberUserRow> = db
        .prepare(
            "SELECT m.*, u.name AS user_name, u.email AS user_email, u.avatar_color,
                    CASE WHEN u.master_password_hash = '' THEN 0 ELSE 1 END AS has_master_password
             FROM users_organizations m JOIN users u ON u.id = m.user_id
             WHERE m.organization_id = ?1 ORDER BY u.email COLLATE NOCASE",
        )
        .bind(&[org_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let mut output = Vec::with_capacity(rows.len());
    for row in rows {
        output.push(member_user_json(&db, &row, &query).await?);
    }
    Ok(Json(list_response(output)))
}

#[worker::send]
pub async fn get_member(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_collection_manager(&actor)?;
    let row = load_member_user(&db, &org_id, &member_id).await?;
    let value = member_user_json(&db, &row, &MemberQuery::default()).await?;
    Ok(Json(value))
}

#[worker::send]
pub async fn get_member_mini_details(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_collection_manager(&actor)?;
    let rows: Vec<MemberUserRow> = db
        .prepare(
            "SELECT m.*, u.name AS user_name, u.email AS user_email, u.avatar_color,
                    CASE WHEN u.master_password_hash = '' THEN 0 ELSE 1 END AS has_master_password
             FROM users_organizations m JOIN users u ON u.id = m.user_id
             WHERE m.organization_id = ?1 ORDER BY u.email COLLATE NOCASE",
        )
        .bind(&[org_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let members = rows
        .into_iter()
        .map(|row| {
            json!({
                "id": row.id,
                "userId": row.user_id,
                "name": row.user_name,
                "email": row.user_email,
                "status": if row.status < 0 { -1 } else { row.status },
                "type": if row.member_type == MEMBER_TYPE_MANAGER { 4 } else { row.member_type },
                "accessAll": row.access_all != 0,
                "externalId": row.external_id,
                "object": "organizationUserUserMiniDetails"
            })
        })
        .collect();
    Ok(Json(list_response(members)))
}

#[worker::send]
pub async fn edit_member(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(data): Json<EditMemberData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    let target_row = load_member_user(&db, &org_id, &member_id).await?;
    let target = target_row.membership();
    let (new_type, raw_custom) = parse_member_type(&data.member_type)?;
    if target.member_type != new_type
        && (target.member_type <= MEMBER_TYPE_ADMIN || new_type <= MEMBER_TYPE_ADMIN)
        && !actor.is_owner()
    {
        return Err(AppError::Forbidden(
            "Only owners can grant or remove administrator or owner privileges".to_string(),
        ));
    }
    if target.is_owner() && !actor.is_owner() {
        return Err(AppError::Forbidden(
            "Only owners can edit owner members".to_string(),
        ));
    }
    let access_all = new_type <= MEMBER_TYPE_ADMIN
        || (raw_custom
            && [
                "editAnyCollection",
                "deleteAnyCollection",
                "createNewCollections",
            ]
            .iter()
            .all(|key| data.permissions.get(*key) == Some(&Value::Bool(true))));
    let collections = data.collections.unwrap_or_default();
    validate_collection_assignments(&db, &org_id, &collections, &[]).await?;
    let groups = data.groups.unwrap_or_default();
    for group_id in &groups {
        load_group(&db, &org_id, group_id).await?;
    }
    let mut proposed = target.clone();
    proposed.member_type = new_type;
    proposed.access_all = i32::from(access_all);
    validate_membership_policies(&db, &proposed).await?;

    let update = db
        .prepare(
            "UPDATE users_organizations
             SET type = ?1, access_all = ?2, permissions = ?3, updated_at = ?4
             WHERE id = ?5 AND organization_id = ?6
               AND (type <> ?7 OR status <> ?8 OR ?1 = ?7 OR
                    (SELECT COUNT(*) FROM users_organizations owners
                     WHERE owners.organization_id = ?6 AND owners.type = ?7
                       AND owners.status = ?8) > 1)",
        )
        .bind(&[
            new_type.into(),
            access_all.into(),
            Value::Object(data.permissions).to_string().into(),
            db::now_rfc3339_millis().into(),
            member_id.clone().into(),
            org_id.clone().into(),
            MEMBER_TYPE_OWNER.into(),
            MEMBER_STATUS_CONFIRMED.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    if update.meta()?.and_then(|meta| meta.changes).unwrap_or(0) == 0 {
        return Err(AppError::BadRequest(
            "The last confirmed owner cannot be demoted".to_string(),
        ));
    }

    let mut statements = vec![
        db.prepare("DELETE FROM users_collections WHERE membership_id = ?1")
            .bind(&[member_id.clone().into()])?,
        db.prepare("DELETE FROM groups_users WHERE membership_id = ?1")
            .bind(&[member_id.clone().into()])?,
    ];
    if !access_all {
        for collection in &collections {
            statements.push(collection_user_statement_for_membership(
                &db, &member_id, collection,
            )?);
        }
    }
    for group_id in groups {
        statements.push(
            db.prepare("INSERT INTO groups_users (group_id, membership_id) VALUES (?1, ?2)")
                .bind(&[group_id.into(), member_id.clone().into()])?,
        );
    }
    db.batch(statements).await.map_err(|_| AppError::Database)?;
    touch_organization_members(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1502,
        Some(&target.user_id),
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn member_public_keys(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkIdsData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    if data.ids.len() > 40 {
        return Err(AppError::BadRequest(
            "At most 40 public keys can be requested".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    let mut output = Vec::new();
    for member_id in data.ids {
        let row: Option<Value> = db
            .prepare(
                "SELECT m.id, u.id AS user_id, u.public_key
                 FROM users_organizations m JOIN users u ON u.id = m.user_id
                 WHERE m.id = ?1 AND m.organization_id = ?2",
            )
            .bind(&[member_id.into(), org_id.clone().into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        if let Some(row) = row {
            output.push(json!({
                "object": "organizationUserPublicKeyResponseModel",
                "id": row.get("id").cloned().unwrap_or(Value::Null),
                "userId": row.get("user_id").cloned().unwrap_or(Value::Null),
                "key": row.get("public_key").cloned().unwrap_or(Value::Null)
            }));
        }
    }
    Ok(Json(list_response(output)))
}

async fn load_member_user(
    db: &D1Database,
    org_id: &str,
    member_id: &str,
) -> Result<MemberUserRow, AppError> {
    db.prepare(
        "SELECT m.*, u.name AS user_name, u.email AS user_email, u.avatar_color,
                CASE WHEN u.master_password_hash = '' THEN 0 ELSE 1 END AS has_master_password
         FROM users_organizations m JOIN users u ON u.id = m.user_id
         WHERE m.id = ?1 AND m.organization_id = ?2",
    )
    .bind(&[member_id.into(), org_id.into()])?
    .first(None)
    .await
    .map_err(|_| AppError::Database)?
    .ok_or_else(|| AppError::NotFound("Organization member not found".to_string()))
}

async fn member_user_json(
    db: &D1Database,
    row: &MemberUserRow,
    query: &MemberQuery,
) -> Result<Value, AppError> {
    let member = row.membership();
    let status = if member.status < MEMBER_STATUS_INVITED {
        -1
    } else {
        member.status
    };
    let group_full_access = member_has_group_full_access(db, &member).await?;
    let collections = if query.include_collections && member.access_all == 0 && !group_full_access {
        let rows: Vec<Value> = db
            .prepare(
                "SELECT collection_id AS id, read_only AS readOnly,
                        hide_passwords AS hidePasswords, manage
                 FROM users_collections WHERE membership_id = ?1",
            )
            .bind(&[member.id.clone().into()])?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results()?;
        rows
    } else {
        Vec::new()
    };
    let groups = if query.include_groups {
        db.prepare("SELECT group_id FROM groups_users WHERE membership_id = ?1")
            .bind(&[member.id.clone().into()])?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results::<Value>()?
            .into_iter()
            .filter_map(|row| row.get("group_id").cloned())
            .collect()
    } else {
        Vec::new()
    };
    let permissions = if member.client_type() == 4 && member.access_all != 0 {
        serde_json::from_str(&member.permissions).unwrap_or_else(|_| json!({}))
    } else {
        Value::Null
    };
    Ok(json!({
        "id": member.id,
        "userId": member.user_id,
        "name": if member.status >= MEMBER_STATUS_ACCEPTED { row.user_name.clone() } else { None },
        "email": row.user_email,
        "externalId": member.external_id,
        "avatarColor": row.avatar_color,
        "groups": groups,
        "collections": collections,
        "status": status,
        "type": member.client_type(),
        "accessAll": member.access_all != 0,
        "twoFactorEnabled": false,
        "resetPasswordEnrolled": member.reset_password_key.is_some(),
        "hasMasterPassword": row.has_master_password != 0,
        "permissions": permissions,
        "ssoBound": false,
        "managedByOrganization": false,
        "claimedByOrganization": false,
        "usesKeyConnector": false,
        "accessSecretsManager": false,
        "object": "organizationUserUserDetails"
    }))
}

#[worker::send]
pub async fn invite_members(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<InviteData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    if !env_bool(&state.env, "INVITATIONS_ALLOWED", true) {
        return Err(AppError::BadRequest("Invitations are disabled".to_string()));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    let org = load_organization(&db, &org_id).await?;
    let (member_type, raw_custom) = parse_member_type(&data.member_type)?;
    if member_type != MEMBER_TYPE_USER && !actor.is_owner() {
        return Err(AppError::Forbidden(
            "Only owners can invite managers, administrators, or owners".to_string(),
        ));
    }
    let access_all = member_type <= MEMBER_TYPE_ADMIN
        || (raw_custom
            && [
                "editAnyCollection",
                "deleteAnyCollection",
                "createNewCollections",
            ]
            .iter()
            .all(|key| data.permissions.get(*key) == Some(&Value::Bool(true))));
    validate_collection_assignments(&db, &org_id, &data.collections, &[]).await?;

    let mut seen = std::collections::HashSet::new();
    for raw_email in data.emails {
        let email = crate::auth::normalize_email(&raw_email);
        if email.is_empty() || !seen.insert(email.clone()) {
            continue;
        }
        let existing: Option<Value> = db
            .prepare("SELECT id, master_password_hash FROM users WHERE email = ?1")
            .bind(&[email.clone().into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        let user_id = existing
            .as_ref()
            .and_then(|row| row.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let has_existing_user = existing
            .as_ref()
            .and_then(|row| row.get("master_password_hash"))
            .and_then(Value::as_str)
            .is_some_and(|hash| !hash.is_empty());
        let duplicate: Option<Value> = db
            .prepare(
                "SELECT 1 AS duplicate FROM users_organizations WHERE user_id = ?1 AND organization_id = ?2",
            )
            .bind(&[user_id.clone().into(), org_id.clone().into()])?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;
        if duplicate.is_some() {
            return Err(AppError::BadRequest(format!(
                "User already in organization: {email}"
            )));
        }
        let now = db::now_rfc3339_millis();
        let membership_id = Uuid::new_v4().to_string();
        let permissions = Value::Object(data.permissions.clone()).to_string();
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
                    user_id.clone().into(),
                    email.clone().into(),
                    Uuid::new_v4().to_string().into(),
                    now.clone().into(),
                    now.clone().into(),
                ])?,
            );
        }
        statements.push(
            db.prepare(
                "INSERT INTO users_organizations
                 (id, user_id, organization_id, invited_by_email, access_all, key, status, type,
                  reset_password_key, external_id, permissions, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, '', ?6, ?7, NULL, NULL, ?8, ?9, ?10)",
            )
            .bind(&[
                membership_id.clone().into(),
                user_id.clone().into(),
                org_id.clone().into(),
                claims.email.clone().into(),
                access_all.into(),
                MEMBER_STATUS_INVITED.into(),
                member_type.into(),
                permissions.into(),
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
        if !access_all {
            for access in &data.collections {
                statements.push(collection_user_statement_for_membership(
                    &db,
                    &membership_id,
                    access,
                )?);
            }
        }
        for group_id in &data.groups {
            statements.push(
                db.prepare(
                    "INSERT INTO groups_users (group_id, membership_id)
                     SELECT id, ?1 FROM groups WHERE id = ?2 AND organization_id = ?3",
                )
                .bind(&[
                    membership_id.clone().into(),
                    group_id.clone().into(),
                    org_id.clone().into(),
                ])?,
            );
        }
        db.batch(statements).await.map_err(|_| AppError::Database)?;
        super::events::log_event(
            &db,
            &state.env,
            1500,
            None,
            Some(&org_id),
            None,
            &claims.sub,
        )
        .await?;
        send_invite_link(
            &state,
            &org,
            &email,
            &user_id,
            &membership_id,
            Some(claims.email.clone()),
            has_existing_user,
        )
        .await?;
    }
    touch_organization_members(&db, &org_id).await?;
    Ok(Json(json!({})))
}

fn collection_user_statement_for_membership(
    db: &D1Database,
    membership_id: &str,
    access: &CollectionAccessData,
) -> Result<worker::D1PreparedStatement, AppError> {
    Ok(db
        .prepare(
            "INSERT INTO users_collections
             (membership_id, collection_id, read_only, hide_passwords, manage)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(&[
            membership_id.into(),
            access.id.clone().into(),
            access.read_only.into(),
            access.hide_passwords.into(),
            access.manage.into(),
        ])?)
}

fn parse_member_type(value: &Value) -> Result<(i32, bool), AppError> {
    let raw = value
        .as_i64()
        .map(|value| value.to_string())
        .or_else(|| value.as_str().map(str::to_string))
        .ok_or_else(|| AppError::BadRequest("Invalid organization member type".to_string()))?;
    match raw.to_ascii_lowercase().as_str() {
        "0" | "owner" => Ok((MEMBER_TYPE_OWNER, false)),
        "1" | "admin" => Ok((MEMBER_TYPE_ADMIN, false)),
        "2" | "user" => Ok((MEMBER_TYPE_USER, false)),
        "3" | "manager" => Ok((MEMBER_TYPE_MANAGER, false)),
        "4" | "custom" => Ok((MEMBER_TYPE_MANAGER, true)),
        _ => Err(AppError::BadRequest(
            "Invalid organization member type".to_string(),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_invite_link(
    state: &AppState,
    org: &Organization,
    email: &str,
    user_id: &str,
    membership_id: &str,
    invited_by_email: Option<String>,
    has_existing_user: bool,
) -> Result<(), AppError> {
    let now = Utc::now();
    let expiry_hours = state
        .env
        .var("INVITATION_EXPIRATION_HOURS")
        .ok()
        .and_then(|value| value.to_string().parse::<i64>().ok())
        .filter(|hours| (1..=720).contains(hours))
        .unwrap_or(120);
    let claims = InviteClaims {
        nbf: now.timestamp() as usize,
        exp: (now + Duration::hours(expiry_hours)).timestamp() as usize,
        iss: INVITE_ISSUER.to_string(),
        sub: user_id.to_string(),
        email: email.to_string(),
        org_id: org.id.clone(),
        member_id: membership_id.to_string(),
        invited_by_email,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.jwt_keys.access_secret.as_ref()),
    )?;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("email", email)
        .append_pair("organizationName", &org.name)
        .append_pair("organizationId", &org.id)
        .append_pair("organizationUserId", membership_id)
        .append_pair("token", &token)
        .append_pair("initOrganization", "false")
        .append_pair(
            "orgUserHasExistingUser",
            if has_existing_user { "true" } else { "false" },
        )
        .finish();
    let url = state.public_url(&format!("/#/accept-organization/?{query}"));
    let outbox_id = notify::enqueue_action_link(
        &state.env,
        email,
        &url,
        ActionLinkType::OrganizationInvite,
        Some(org.name.clone()),
    )
    .await?;
    notify::deliver_outbox_background(&state.ctx, state.env.clone(), outbox_id);
    Ok(())
}

#[worker::send]
pub async fn accept_invite(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(data): Json<AcceptData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let invite = decode::<InviteClaims>(
        &data.token,
        &DecodingKey::from_secret(state.jwt_keys.access_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| AppError::BadRequest("Invalid organization invitation".to_string()))?
    .claims;
    if invite.iss != INVITE_ISSUER
        || invite.email != claims.email
        || invite.sub != claims.sub
        || invite.org_id != org_id
        || invite.member_id != member_id
    {
        return Err(AppError::BadRequest(
            "Organization invitation does not match the current account".to_string(),
        ));
    }
    let membership: Membership = db
        .prepare(
            "SELECT * FROM users_organizations
             WHERE id = ?1 AND user_id = ?2 AND organization_id = ?3 AND status = ?4",
        )
        .bind(&[
            member_id.clone().into(),
            claims.sub.clone().into(),
            org_id.clone().into(),
            MEMBER_STATUS_INVITED.into(),
        ])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| {
            AppError::BadRequest("Organization invitation is no longer pending".to_string())
        })?;
    validate_membership_policies(&db, &membership).await?;
    let reset_policy: Option<OrgPolicy> = db
        .prepare(
            "SELECT * FROM org_policies
             WHERE organization_id = ?1 AND type = 8 AND enabled = 1",
        )
        .bind(&[org_id.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let reset_auto_enroll = reset_policy.is_some_and(|policy| {
        serde_json::from_str::<Value>(&policy.data)
            .ok()
            .and_then(|data| {
                data.get("autoEnrollEnabled")
                    .or_else(|| data.get("AutoEnrollEnabled"))
                    .and_then(Value::as_bool)
            })
            .unwrap_or(false)
    });
    let reset_password_key = if reset_auto_enroll {
        Some(
            data.reset_password_key
                .filter(|key| !key.is_empty())
                .ok_or_else(|| {
                    AppError::BadRequest(
                        "Reset password key is required by the organization policy".to_string(),
                    )
                })?,
        )
    } else {
        None
    };
    let now = db::now_rfc3339_millis();
    let result = db
        .prepare(
            "UPDATE users_organizations
             SET status = ?1, reset_password_key = ?2,
                 invited_by_email = COALESCE(invited_by_email, ?3), updated_at = ?4
             WHERE id = ?5 AND user_id = ?6 AND organization_id = ?7 AND status = ?8",
        )
        .bind(&[
            MEMBER_STATUS_ACCEPTED.into(),
            reset_password_key.into(),
            invite.invited_by_email.into(),
            now.into(),
            member_id.into(),
            claims.sub.clone().into(),
            org_id.clone().into(),
            MEMBER_STATUS_INVITED.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    if result.meta()?.and_then(|meta| meta.changes).unwrap_or(0) == 0 {
        return Err(AppError::BadRequest(
            "Organization invitation is no longer pending".to_string(),
        ));
    }
    db.prepare("DELETE FROM invitations WHERE email = ?1")
        .bind(&[claims.email.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    db::update_user_revision(&db, &claims.sub).await?;
    super::events::log_event(
        &db,
        &state.env,
        1501,
        Some(&claims.sub),
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn confirm_invite(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, member_id)): Path<(String, String)>,
    Json(data): Json<ConfirmData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    let target_user_id = load_member_user(&db, &org_id, &member_id).await?.user_id;
    confirm_invite_impl(&db, &actor, &org_id, &member_id, data.key).await?;
    touch_organization_members(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1501,
        Some(&target_user_id),
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(json!({})))
}

async fn confirm_invite_impl(
    db: &D1Database,
    actor: &Membership,
    org_id: &str,
    member_id: &str,
    key: Option<String>,
) -> Result<(), AppError> {
    let target = load_member_user(db, org_id, member_id).await?;
    if target.member_type != MEMBER_TYPE_USER && !actor.is_owner() {
        return Err(AppError::Forbidden(
            "Only owners can confirm managers, administrators, or owners".to_string(),
        ));
    }
    validate_membership_policies(db, &target.membership()).await?;
    let key = key
        .filter(|key| !key.is_empty())
        .ok_or_else(|| AppError::BadRequest("Key is required".to_string()))?;
    let result = db
        .prepare(
            "UPDATE users_organizations SET status = ?1, key = ?2, updated_at = ?3
             WHERE id = ?4 AND organization_id = ?5 AND status = ?6",
        )
        .bind(&[
            MEMBER_STATUS_CONFIRMED.into(),
            key.into(),
            db::now_rfc3339_millis().into(),
            member_id.into(),
            org_id.into(),
            MEMBER_STATUS_ACCEPTED.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    if result.meta()?.and_then(|meta| meta.changes).unwrap_or(0) == 0 {
        return Err(AppError::BadRequest(
            "Organization member is not awaiting confirmation".to_string(),
        ));
    }
    Ok(())
}

#[worker::send]
pub async fn bulk_confirm_invites(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkConfirmData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    if data.keys.len() > 40 {
        return Err(AppError::BadRequest(
            "At most 40 members can be confirmed in one request".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    let mut responses = Vec::with_capacity(data.keys.len());
    for item in data.keys {
        let member_id = item.id.unwrap_or_default();
        let result = if member_id.is_empty() {
            Err(AppError::BadRequest("Member id is required".to_string()))
        } else {
            confirm_invite_impl(&db, &actor, &org_id, &member_id, item.key).await
        };
        responses.push(json!({
            "object": "OrganizationBulkConfirmResponseModel",
            "id": member_id,
            "error": result.err().map(|error| error.to_string()).unwrap_or_default()
        }));
    }
    touch_organization_members(&db, &org_id).await?;
    Ok(Json(list_response(responses)))
}

#[worker::send]
pub async fn reinvite_member(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    reinvite_member_impl(&state, &db, &org_id, &member_id, &claims.email).await?;
    Ok(Json(json!({})))
}

async fn reinvite_member_impl(
    state: &AppState,
    db: &D1Database,
    org_id: &str,
    member_id: &str,
    invited_by_email: &str,
) -> Result<(), AppError> {
    let target = load_member_user(db, org_id, member_id).await?;
    if target.status != MEMBER_STATUS_INVITED {
        return Err(AppError::BadRequest(
            "The user is already accepted or confirmed".to_string(),
        ));
    }
    let org = load_organization(db, org_id).await?;
    send_invite_link(
        state,
        &org,
        &target.user_email,
        &target.user_id,
        &target.id,
        Some(invited_by_email.to_string()),
        target.has_master_password != 0,
    )
    .await?;
    Ok(())
}

#[worker::send]
pub async fn bulk_reinvite_members(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkIdsData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    if data.ids.len() > 40 {
        return Err(AppError::BadRequest(
            "At most 40 members can be reinvited in one request".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    let mut responses = Vec::with_capacity(data.ids.len());
    for member_id in data.ids {
        let result = reinvite_member_impl(&state, &db, &org_id, &member_id, &claims.email).await;
        responses.push(json!({
            "object": "OrganizationBulkConfirmResponseModel",
            "id": member_id,
            "error": result.err().map(|error| error.to_string()).unwrap_or_default()
        }));
    }
    Ok(Json(list_response(responses)))
}

#[worker::send]
pub async fn revoke_member(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    let target = load_member_user(&db, &org_id, &member_id).await?;
    revoke_member_impl(&db, &actor, &org_id, &member_id).await?;
    touch_organization_members(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1511,
        Some(&target.user_id),
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(json!({})))
}

async fn revoke_member_impl(
    db: &D1Database,
    actor: &Membership,
    org_id: &str,
    member_id: &str,
) -> Result<(), AppError> {
    let target = load_member_user(db, org_id, member_id).await?;
    if target.user_id == actor.user_id {
        return Err(AppError::BadRequest(
            "You cannot revoke yourself".to_string(),
        ));
    }
    if target.member_type != MEMBER_TYPE_USER && !actor.is_owner() {
        return Err(AppError::Forbidden(
            "Only owners can revoke elevated members".to_string(),
        ));
    }
    if target.status < MEMBER_STATUS_INVITED {
        return Err(AppError::BadRequest(
            "Organization member is already revoked".to_string(),
        ));
    }
    let update = db
        .prepare(
            "UPDATE users_organizations SET status = status - ?1, updated_at = ?2
         WHERE id = ?3 AND organization_id = ?4 AND status >= ?5
           AND (type <> ?6 OR status <> ?7 OR
                (SELECT COUNT(*) FROM users_organizations owners
                 WHERE owners.organization_id = ?4 AND owners.type = ?6
                   AND owners.status = ?7) > 1)",
        )
        .bind(&[
            REVOKE_OFFSET.into(),
            db::now_rfc3339_millis().into(),
            member_id.into(),
            org_id.into(),
            MEMBER_STATUS_INVITED.into(),
            MEMBER_TYPE_OWNER.into(),
            MEMBER_STATUS_CONFIRMED.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    if update.meta()?.and_then(|meta| meta.changes).unwrap_or(0) == 0 {
        return Err(AppError::BadRequest(
            "The last confirmed owner cannot be revoked".to_string(),
        ));
    }
    Ok(())
}

#[worker::send]
pub async fn bulk_revoke_members(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkIdsData>,
) -> Result<Json<Value>, AppError> {
    bulk_member_status_change(claims, state, org_id, data, true).await
}

#[worker::send]
pub async fn restore_member(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    let target = load_member_user(&db, &org_id, &member_id).await?;
    restore_member_impl(&db, &actor, &org_id, &member_id).await?;
    touch_organization_members(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1512,
        Some(&target.user_id),
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(json!({})))
}

async fn restore_member_impl(
    db: &D1Database,
    actor: &Membership,
    org_id: &str,
    member_id: &str,
) -> Result<(), AppError> {
    let target = load_member_user(db, org_id, member_id).await?;
    if target.member_type != MEMBER_TYPE_USER && !actor.is_owner() {
        return Err(AppError::Forbidden(
            "Only owners can restore elevated members".to_string(),
        ));
    }
    if target.status >= MEMBER_STATUS_INVITED {
        return Err(AppError::BadRequest(
            "Organization member is not revoked".to_string(),
        ));
    }
    db.prepare(
        "UPDATE users_organizations SET status = status + ?1, updated_at = ?2
         WHERE id = ?3 AND organization_id = ?4 AND status < ?5",
    )
    .bind(&[
        REVOKE_OFFSET.into(),
        db::now_rfc3339_millis().into(),
        member_id.into(),
        org_id.into(),
        MEMBER_STATUS_INVITED.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

#[worker::send]
pub async fn bulk_restore_members(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkIdsData>,
) -> Result<Json<Value>, AppError> {
    bulk_member_status_change(claims, state, org_id, data, false).await
}

async fn bulk_member_status_change(
    claims: Claims,
    state: Arc<AppState>,
    org_id: String,
    data: BulkIdsData,
    revoke: bool,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    if data.ids.len() > 40 {
        return Err(AppError::BadRequest(
            "At most 40 members can be updated in one request".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    let mut responses = Vec::with_capacity(data.ids.len());
    for member_id in data.ids {
        let result = if revoke {
            revoke_member_impl(&db, &actor, &org_id, &member_id).await
        } else {
            restore_member_impl(&db, &actor, &org_id, &member_id).await
        };
        responses.push(json!({
            "object": "OrganizationUserBulkResponseModel",
            "id": member_id,
            "error": result.err().map(|error| error.to_string()).unwrap_or_default()
        }));
    }
    touch_organization_members(&db, &org_id).await?;
    Ok(Json(list_response(responses)))
}

#[worker::send]
pub async fn delete_member(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    let target = load_member_user(&db, &org_id, &member_id).await?;
    if target.member_type != MEMBER_TYPE_USER && !actor.is_owner() {
        return Err(AppError::Forbidden(
            "Only owners can remove elevated members".to_string(),
        ));
    }
    delete_membership_preserving_owner(&db, &org_id, &member_id).await?;
    db::update_user_revision(&db, &target.user_id).await?;
    touch_organization_members(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1503,
        Some(&target.user_id),
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn bulk_delete_members(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkIdsData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    if data.ids.len() > 40 {
        return Err(AppError::BadRequest(
            "At most 40 members can be deleted in one request".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    let mut responses = Vec::with_capacity(data.ids.len());
    for member_id in data.ids {
        let result = async {
            let target = load_member_user(&db, &org_id, &member_id).await?;
            if target.member_type != MEMBER_TYPE_USER && !actor.is_owner() {
                return Err(AppError::Forbidden(
                    "Only owners can remove elevated members".to_string(),
                ));
            }
            delete_membership_preserving_owner(&db, &org_id, &member_id).await?;
            db::update_user_revision(&db, &target.user_id).await?;
            super::events::log_event(
                &db,
                &state.env,
                1503,
                Some(&target.user_id),
                Some(&org_id),
                None,
                &claims.sub,
            )
            .await?;
            Ok::<(), AppError>(())
        }
        .await;
        responses.push(json!({
            "object": "OrganizationBulkConfirmResponseModel",
            "id": member_id,
            "error": result.err().map(|error| error.to_string()).unwrap_or_default()
        }));
    }
    touch_organization_members(&db, &org_id).await?;
    Ok(Json(list_response(responses)))
}

async fn require_reset_password_policy(
    db: &D1Database,
    org_id: &str,
) -> Result<OrgPolicy, AppError> {
    db.prepare(
        "SELECT * FROM org_policies
         WHERE organization_id = ?1 AND type = 8 AND enabled = 1",
    )
    .bind(&[org_id.into()])?
    .first(None)
    .await
    .map_err(|_| AppError::Database)?
    .ok_or_else(|| AppError::BadRequest("Reset password policy is not enabled".to_string()))
}

fn require_reset_target_access(actor: &Membership, target: &Membership) -> Result<(), AppError> {
    if target.member_type <= MEMBER_TYPE_ADMIN && !actor.is_owner() {
        Err(AppError::Forbidden(
            "Only owners can recover elevated organization accounts".to_string(),
        ))
    } else {
        Ok(())
    }
}

#[worker::send]
pub async fn get_reset_password_details(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, member_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    require_reset_password_policy(&db, &org_id).await?;
    let target = load_member_user(&db, &org_id, &member_id).await?;
    require_reset_target_access(&actor, &target.membership())?;
    let org = load_organization(&db, &org_id).await?;
    let user: Value = db
        .prepare(
            "SELECT kdf_type, kdf_iterations, kdf_memory, kdf_parallelism
             FROM users WHERE id = ?1",
        )
        .bind(&[target.user_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    Ok(Json(json!({
        "object": "organizationUserResetPasswordDetails",
        "organizationUserId": member_id,
        "kdf": user.get("kdf_type").cloned().unwrap_or(Value::Null),
        "kdfIterations": user.get("kdf_iterations").cloned().unwrap_or(Value::Null),
        "kdfMemory": user.get("kdf_memory").cloned().unwrap_or(Value::Null),
        "kdfParallelism": user.get("kdf_parallelism").cloned().unwrap_or(Value::Null),
        "resetPasswordKey": target.reset_password_key,
        "encryptedPrivateKey": org.private_key
    })))
}

async fn recover_account_impl(
    claims: Claims,
    state: Arc<AppState>,
    org_id: String,
    member_id: String,
    data: RecoverAccountData,
    headers: HeaderMap,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    if data.new_master_password_hash.is_empty() || data.key.is_empty() {
        return Err(AppError::BadRequest(
            "New master password hash and key are required".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    require_reset_password_policy(&db, &org_id).await?;
    let target = load_member_user(&db, &org_id, &member_id).await?;
    let target_membership = target.membership();
    require_reset_target_access(&actor, &target_membership)?;
    if target_membership.status != MEMBER_STATUS_CONFIRMED {
        return Err(AppError::BadRequest(
            "Organization user must be confirmed for account recovery".to_string(),
        ));
    }
    if target_membership.reset_password_key.is_none() {
        return Err(AppError::BadRequest(
            "Organization user is not enrolled in account recovery".to_string(),
        ));
    }

    let server_password = password::hash_password(&data.new_master_password_hash, None).await?;
    let security_stamp = Uuid::new_v4().to_string();
    let now = db::now_rfc3339_millis();
    db.prepare(
        "UPDATE users
         SET master_password_hash = ?1, key = ?2, security_stamp = ?3,
             password_salt = ?4, password_iterations = ?5, updated_at = ?6
         WHERE id = ?7",
    )
    .bind(&[
        server_password.hash.into(),
        data.key.into(),
        security_stamp.into(),
        server_password.salt.into(),
        server_password.iterations.into(),
        now.clone().into(),
        target.user_id.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    notifications::publish_user_update_background(
        &state.ctx,
        state.env.clone(),
        UpdateType::LogOut,
        target.user_id.clone(),
        now,
        None,
    );
    notify::notify_background(
        &state.ctx,
        state.env.clone(),
        crate::extensions::notify::NotifyEvent::PasswordChange,
        crate::extensions::notify::NotifyContext {
            user_id: Some(target.user_id),
            user_email: Some(target.user_email),
            detail: Some(format!("Account recovered by organization {org_id}")),
            meta: notify::extract_request_meta(&headers),
            ..Default::default()
        },
    );
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn recover_account(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, member_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(data): Json<RecoverAccountData>,
) -> Result<Json<Value>, AppError> {
    if !data.reset_master_password || data.reset_two_factor {
        return Err(AppError::BadRequest(
            "Only master password recovery is supported".to_string(),
        ));
    }
    recover_account_impl(claims, state, org_id, member_id, data, headers).await
}

#[worker::send]
pub async fn reset_member_password(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, member_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(data): Json<RecoverAccountData>,
) -> Result<Json<Value>, AppError> {
    recover_account_impl(claims, state, org_id, member_id, data, headers).await
}

#[worker::send]
pub async fn update_reset_password_enrollment(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, user_id)): Path<(String, String)>,
    Json(data): Json<ResetPasswordEnrollmentData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    if user_id != claims.sub {
        return Err(AppError::Forbidden(
            "Account recovery enrollment can only be changed by that user".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_confirmed(&member)?;
    let policy = require_reset_password_policy(&db, &org_id).await?;
    let reset_password_key = data.reset_password_key.filter(|key| !key.is_empty());
    let auto_enroll = serde_json::from_str::<Value>(&policy.data)
        .ok()
        .and_then(|value| {
            value
                .get("autoEnrollEnabled")
                .or_else(|| value.get("AutoEnrollEnabled"))
                .and_then(Value::as_bool)
        })
        .unwrap_or(false);
    if reset_password_key.is_none() && auto_enroll {
        return Err(AppError::BadRequest(
            "Account recovery enrollment is required by organization policy".to_string(),
        ));
    }
    if reset_password_key.is_some() {
        crate::api::core::accounts::validate_password_or_otp(
            &db,
            &claims.sub,
            &crate::api::core::accounts::SecretVerificationRequest {
                master_password_hash: data.master_password_hash,
                otp: data.otp,
            },
        )
        .await?;
    }
    db.prepare(
        "UPDATE users_organizations SET reset_password_key = ?1, updated_at = ?2
         WHERE id = ?3 AND organization_id = ?4 AND user_id = ?5",
    )
    .bind(&[
        reset_password_key.into(),
        db::now_rfc3339_millis().into(),
        member.id.into(),
        org_id.into(),
        claims.sub.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    db::update_user_revision(&db, &claims.sub).await?;
    Ok(Json(json!({})))
}

fn ensure_groups_enabled(env: &worker::Env) -> Result<(), AppError> {
    ensure_enabled(env)?;
    if groups_enabled(env) {
        Ok(())
    } else {
        Err(AppError::NotFound("Group support is disabled".to_string()))
    }
}

async fn load_group(db: &D1Database, org_id: &str, group_id: &str) -> Result<Group, AppError> {
    db.prepare("SELECT * FROM groups WHERE id = ?1 AND organization_id = ?2")
        .bind(&[group_id.into(), org_id.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Group not found".to_string()))
}

async fn group_details_json(db: &D1Database, group: &Group) -> Result<Value, AppError> {
    let collections: Vec<Value> = db
        .prepare(
            "SELECT collection_id AS id, read_only, hide_passwords, manage
             FROM collections_groups WHERE group_id = ?1 ORDER BY collection_id",
        )
        .bind(&[group.id.clone().into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    Ok(json!({
        "id": group.id,
        "organizationId": group.organization_id,
        "name": group.name,
        "accessAll": group.access_all != 0,
        "externalId": group.external_id,
        "collections": collections.into_iter().map(|row| json!({
            "id": row.get("id").cloned().unwrap_or(Value::Null),
            "readOnly": row.get("read_only").and_then(Value::as_i64) != Some(0),
            "hidePasswords": row.get("hide_passwords").and_then(Value::as_i64) != Some(0),
            "manage": row.get("manage").and_then(Value::as_i64) == Some(1)
        })).collect::<Vec<_>>(),
        "object": "groupDetails"
    }))
}

async fn validate_group_request(
    db: &D1Database,
    org_id: &str,
    request: &GroupRequest,
) -> Result<(), AppError> {
    for collection in &request.collections {
        load_collection(db, org_id, &collection.id).await?;
    }
    for member_id in &request.users {
        let valid: Option<i32> = db
            .prepare(
                "SELECT 1 AS valid FROM users_organizations
                 WHERE id = ?1 AND organization_id = ?2",
            )
            .bind(&[member_id.clone().into(), org_id.into()])?
            .first(Some("valid"))
            .await
            .map_err(|_| AppError::Database)?;
        if valid.is_none() {
            return Err(AppError::BadRequest(
                "Group member does not belong to the organization".to_string(),
            ));
        }
    }
    Ok(())
}

fn group_relation_statements(
    db: &D1Database,
    group_id: &str,
    request: &GroupRequest,
) -> Result<Vec<worker::D1PreparedStatement>, AppError> {
    let mut statements = Vec::new();
    for collection in &request.collections {
        statements.push(
            db.prepare(
                "INSERT INTO collections_groups
                 (collection_id, group_id, read_only, hide_passwords, manage)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )
            .bind(&[
                collection.id.clone().into(),
                group_id.into(),
                collection.read_only.into(),
                collection.hide_passwords.into(),
                collection.manage.into(),
            ])?,
        );
    }
    for member_id in &request.users {
        statements.push(
            db.prepare("INSERT INTO groups_users (group_id, membership_id) VALUES (?1, ?2)")
                .bind(&[group_id.into(), member_id.clone().into()])?,
        );
    }
    Ok(statements)
}

#[worker::send]
pub async fn get_groups(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    if !groups_enabled(&state.env) {
        return Ok(Json(list_response(Vec::new())));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_collection_manager(&member)?;
    let groups: Vec<Group> = db
        .prepare("SELECT * FROM groups WHERE organization_id = ?1 ORDER BY name COLLATE NOCASE")
        .bind(&[org_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    Ok(Json(list_response(
        groups.into_iter().map(|group| group.to_json()).collect(),
    )))
}

#[worker::send]
pub async fn get_groups_details(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_groups_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    let groups: Vec<Group> = db
        .prepare("SELECT * FROM groups WHERE organization_id = ?1 ORDER BY name COLLATE NOCASE")
        .bind(&[org_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let mut details = Vec::with_capacity(groups.len());
    for group in groups {
        details.push(group_details_json(&db, &group).await?);
    }
    Ok(Json(list_response(details)))
}

#[worker::send]
pub async fn create_group(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(request): Json<GroupRequest>,
) -> Result<Json<Value>, AppError> {
    ensure_groups_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    validate_group_request(&db, &org_id, &request).await?;
    let now = db::now_rfc3339_millis();
    let group = Group {
        id: Uuid::new_v4().to_string(),
        organization_id: org_id.clone(),
        name: validate_name(&request.name, "Group name")?,
        access_all: i32::from(request.access_all),
        external_id: request
            .external_id
            .clone()
            .filter(|id| !id.trim().is_empty()),
        created_at: now.clone(),
        updated_at: now,
    };
    let mut statements = vec![
        db.prepare(
            "INSERT INTO groups
             (id, organization_id, name, access_all, external_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(&[
            group.id.clone().into(),
            group.organization_id.clone().into(),
            group.name.clone().into(),
            group.access_all.into(),
            group.external_id.clone().into(),
            group.created_at.clone().into(),
            group.updated_at.clone().into(),
        ])?,
    ];
    statements.extend(group_relation_statements(&db, &group.id, &request)?);
    db.batch(statements).await.map_err(|_| AppError::Database)?;
    touch_organization_members(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1400,
        None,
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(group.to_json()))
}

#[worker::send]
pub async fn get_group(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, group_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_groups_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    let group = load_group(&db, &org_id, &group_id).await?;
    Ok(Json(group.to_json()))
}

#[worker::send]
pub async fn get_group_details(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, group_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_groups_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    let group = load_group(&db, &org_id, &group_id).await?;
    let details = group_details_json(&db, &group).await?;
    Ok(Json(details))
}

#[worker::send]
pub async fn update_group(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, group_id)): Path<(String, String)>,
    Json(request): Json<GroupRequest>,
) -> Result<Json<Value>, AppError> {
    ensure_groups_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    let existing = load_group(&db, &org_id, &group_id).await?;
    validate_group_request(&db, &org_id, &request).await?;
    let group = Group {
        name: validate_name(&request.name, "Group name")?,
        access_all: i32::from(request.access_all),
        updated_at: db::now_rfc3339_millis(),
        ..existing
    };
    let mut statements = vec![
        db.prepare(
            "UPDATE groups SET name = ?1, access_all = ?2, updated_at = ?3
             WHERE id = ?4 AND organization_id = ?5",
        )
        .bind(&[
            group.name.clone().into(),
            group.access_all.into(),
            group.updated_at.clone().into(),
            group.id.clone().into(),
            org_id.clone().into(),
        ])?,
        db.prepare("DELETE FROM collections_groups WHERE group_id = ?1")
            .bind(&[group.id.clone().into()])?,
        db.prepare("DELETE FROM groups_users WHERE group_id = ?1")
            .bind(&[group.id.clone().into()])?,
    ];
    statements.extend(group_relation_statements(&db, &group.id, &request)?);
    db.batch(statements).await.map_err(|_| AppError::Database)?;
    touch_organization_members(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1401,
        None,
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(group.to_json()))
}

#[worker::send]
pub async fn delete_group(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, group_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_groups_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    load_group(&db, &org_id, &group_id).await?;
    db.prepare("DELETE FROM groups WHERE id = ?1 AND organization_id = ?2")
        .bind(&[group_id.into(), org_id.clone().into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    touch_organization_members(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1402,
        None,
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn bulk_delete_groups(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Json(data): Json<BulkIdsData>,
) -> Result<Json<Value>, AppError> {
    ensure_groups_enabled(&state.env)?;
    if data.ids.len() > 40 {
        return Err(AppError::BadRequest(
            "At most 40 groups can be deleted in one request".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    for group_id in &data.ids {
        load_group(&db, &org_id, group_id).await?;
    }
    let mut statements = Vec::with_capacity(data.ids.len());
    for group_id in data.ids {
        statements.push(
            db.prepare("DELETE FROM groups WHERE id = ?1 AND organization_id = ?2")
                .bind(&[group_id.into(), org_id.clone().into()])?,
        );
    }
    if !statements.is_empty() {
        db.batch(statements).await.map_err(|_| AppError::Database)?;
        touch_organization_members(&db, &org_id).await?;
    }
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn get_group_members(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, group_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_groups_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    load_group(&db, &org_id, &group_id).await?;
    let members: Vec<String> = db
        .prepare("SELECT membership_id FROM groups_users WHERE group_id = ?1")
        .bind(&[group_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results::<Value>()?
        .into_iter()
        .filter_map(|row| {
            row.get("membership_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();
    Ok(Json(json!(members)))
}

#[worker::send]
pub async fn put_group_members(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, group_id)): Path<(String, String)>,
    Json(member_ids): Json<Vec<String>>,
) -> Result<Json<Value>, AppError> {
    ensure_groups_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    load_group(&db, &org_id, &group_id).await?;
    let request = GroupRequest {
        name: "validation".to_string(),
        access_all: false,
        external_id: None,
        collections: Vec::new(),
        users: member_ids,
    };
    validate_group_request(&db, &org_id, &request).await?;
    let mut statements = vec![
        db.prepare("DELETE FROM groups_users WHERE group_id = ?1")
            .bind(&[group_id.clone().into()])?,
    ];
    statements.extend(group_relation_statements(&db, &group_id, &request)?);
    db.batch(statements).await.map_err(|_| AppError::Database)?;
    touch_organization_members(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1504,
        None,
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn delete_group_member(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, group_id, member_id)): Path<(String, String, String)>,
) -> Result<Json<Value>, AppError> {
    ensure_groups_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let actor = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&actor)?;
    load_group(&db, &org_id, &group_id).await?;
    db.prepare(
        "DELETE FROM groups_users WHERE group_id = ?1 AND membership_id = ?2
         AND membership_id IN (SELECT id FROM users_organizations WHERE organization_id = ?3)",
    )
    .bind(&[group_id.into(), member_id.into(), org_id.clone().into()])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    touch_organization_members(&db, &org_id).await?;
    Ok(Json(json!({})))
}

#[worker::send]
pub async fn list_policies(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    let policies: Vec<OrgPolicy> = db
        .prepare("SELECT * FROM org_policies WHERE organization_id = ?1 ORDER BY type")
        .bind(&[org_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    Ok(Json(list_response(
        policies
            .into_iter()
            .map(|policy| policy.to_json())
            .collect(),
    )))
}

#[worker::send]
pub async fn list_policies_by_invite_token(
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Query(query): Query<InviteTokenQuery>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let invite = decode::<InviteClaims>(
        &query.token,
        &DecodingKey::from_secret(state.jwt_keys.access_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| AppError::BadRequest("Invalid organization invitation".to_string()))?
    .claims;
    if invite.iss != INVITE_ISSUER || invite.org_id != org_id {
        return Err(AppError::BadRequest(
            "Organization invitation does not match the requested organization".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    let policies: Vec<OrgPolicy> = db
        .prepare("SELECT * FROM org_policies WHERE organization_id = ?1 ORDER BY type")
        .bind(&[org_id.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    Ok(Json(list_response(
        policies
            .into_iter()
            .map(|policy| policy.to_json())
            .collect(),
    )))
}

async fn load_policy_or_default(
    db: &D1Database,
    org_id: &str,
    policy_type: i32,
) -> Result<OrgPolicy, AppError> {
    if !valid_policy_type(policy_type) {
        return Err(AppError::BadRequest(
            "Invalid or unsupported policy type".to_string(),
        ));
    }
    let policy: Option<OrgPolicy> = db
        .prepare("SELECT * FROM org_policies WHERE organization_id = ?1 AND type = ?2")
        .bind(&[org_id.into(), policy_type.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    Ok(policy.unwrap_or_else(|| {
        let now = db::now_rfc3339_millis();
        OrgPolicy {
            id: Uuid::new_v4().to_string(),
            organization_id: org_id.to_string(),
            policy_type,
            enabled: 0,
            data: "null".to_string(),
            created_at: now.clone(),
            updated_at: now,
        }
    }))
}

#[worker::send]
pub async fn get_policy(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, policy_type)): Path<(String, i32)>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    let policy = load_policy_or_default(&db, &org_id, policy_type).await?;
    Ok(Json(policy.to_json()))
}

#[worker::send]
pub async fn get_master_password_policy(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_confirmed(&member)?;
    let policy = load_policy_or_default(&db, &org_id, 1).await?;
    Ok(Json(policy.to_json()))
}

pub async fn get_sso_placeholder_master_password_policy() -> Json<Value> {
    Json(json!({
        "id": SSO_PLACEHOLDER_ORG_ID,
        "organizationId": SSO_PLACEHOLDER_ORG_ID,
        "type": 0,
        "enabled": false,
        "data": null,
        "object": "policy"
    }))
}

#[worker::send]
pub async fn put_policy(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, policy_type)): Path<(String, i32)>,
    Json(data): Json<PutPolicyData>,
) -> Result<Json<Value>, AppError> {
    ensure_enabled(&state.env)?;
    if !valid_policy_type(policy_type) {
        return Err(AppError::BadRequest(
            "Invalid or unsupported policy type".to_string(),
        ));
    }
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = load_membership(&db, &claims.sub, &org_id).await?;
    require_admin(&member)?;
    if data.policy.enabled && policy_type == 0 {
        db.prepare(
            "UPDATE users_organizations AS m SET status = status - ?1, updated_at = ?2
             WHERE m.organization_id = ?3 AND m.status = ?4
               AND m.type NOT IN (?5, ?6)
               AND NOT EXISTS(SELECT 1 FROM two_factor_authenticator t
                              WHERE t.user_id = m.user_id AND t.enabled = 1)
               AND NOT EXISTS(SELECT 1 FROM two_factor_email t
                              WHERE t.user_id = m.user_id AND t.enabled = 1)
               AND NOT EXISTS(SELECT 1 FROM two_factor_webauthn_settings t
                              WHERE t.user_id = m.user_id AND t.enabled = 1)",
        )
        .bind(&[
            REVOKE_OFFSET.into(),
            db::now_rfc3339_millis().into(),
            org_id.clone().into(),
            MEMBER_STATUS_CONFIRMED.into(),
            MEMBER_TYPE_OWNER.into(),
            MEMBER_TYPE_ADMIN.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }
    if data.policy.enabled && policy_type == 3 {
        db.prepare(
            "UPDATE users_organizations AS m SET status = status - ?1, updated_at = ?2
             WHERE m.organization_id = ?3 AND m.status IN (?4, ?5)
               AND m.type NOT IN (?6, ?7)
               AND EXISTS(SELECT 1 FROM users_organizations other
                          WHERE other.user_id = m.user_id
                            AND other.organization_id <> m.organization_id
                            AND other.status IN (?4, ?5))",
        )
        .bind(&[
            REVOKE_OFFSET.into(),
            db::now_rfc3339_millis().into(),
            org_id.clone().into(),
            MEMBER_STATUS_ACCEPTED.into(),
            MEMBER_STATUS_CONFIRMED.into(),
            MEMBER_TYPE_OWNER.into(),
            MEMBER_TYPE_ADMIN.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    }
    let existing: Option<OrgPolicy> = db
        .prepare("SELECT * FROM org_policies WHERE organization_id = ?1 AND type = ?2")
        .bind(&[org_id.clone().into(), policy_type.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let now = db::now_rfc3339_millis();
    let policy = OrgPolicy {
        id: existing
            .as_ref()
            .map(|policy| policy.id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        organization_id: org_id.clone(),
        policy_type,
        enabled: i32::from(data.policy.enabled),
        data: serde_json::to_string(&data.policy.data.unwrap_or(Value::Null))
            .map_err(|_| AppError::Internal)?,
        created_at: existing
            .as_ref()
            .map(|policy| policy.created_at.clone())
            .unwrap_or_else(|| now.clone()),
        updated_at: now,
    };
    db.prepare(
        "INSERT INTO org_policies
         (id, organization_id, type, enabled, data, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(organization_id, type) DO UPDATE SET
           enabled = excluded.enabled, data = excluded.data, updated_at = excluded.updated_at",
    )
    .bind(&[
        policy.id.clone().into(),
        policy.organization_id.clone().into(),
        policy.policy_type.into(),
        policy.enabled.into(),
        policy.data.clone().into(),
        policy.created_at.clone().into(),
        policy.updated_at.clone().into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    touch_organization_members(&db, &org_id).await?;
    super::events::log_event(
        &db,
        &state.env,
        1700,
        None,
        Some(&org_id),
        None,
        &claims.sub,
    )
    .await?;
    Ok(Json(policy.to_json()))
}

pub(crate) async fn sync_policies(
    db: &D1Database,
    env: &worker::Env,
    user_id: &str,
) -> Result<Vec<Value>, AppError> {
    if !organizations_enabled(env) {
        return Ok(Vec::new());
    }
    let policies: Vec<OrgPolicy> = db
        .prepare(
            "SELECT p.* FROM org_policies p
             JOIN users_organizations m ON m.organization_id = p.organization_id
             WHERE m.user_id = ?1 AND m.status = ?2 ORDER BY p.type",
        )
        .bind(&[user_id.into(), MEMBER_STATUS_CONFIRMED.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    Ok(policies
        .into_iter()
        .map(|policy| policy.to_json())
        .collect())
}

pub(crate) async fn policy_applies_to_user(
    db: &D1Database,
    user_id: &str,
    policy_type: i32,
) -> Result<bool, AppError> {
    let applies: Option<i32> = db
        .prepare(
            "SELECT 1 AS applies FROM org_policies p
             JOIN users_organizations m ON m.organization_id = p.organization_id
             WHERE m.user_id = ?1 AND m.status IN (?2, ?3)
               AND m.type NOT IN (?4, ?5) AND p.type = ?6 AND p.enabled = 1
             LIMIT 1",
        )
        .bind(&[
            user_id.into(),
            MEMBER_STATUS_ACCEPTED.into(),
            MEMBER_STATUS_CONFIRMED.into(),
            MEMBER_TYPE_OWNER.into(),
            MEMBER_TYPE_ADMIN.into(),
            policy_type.into(),
        ])?
        .first(Some("applies"))
        .await
        .map_err(|_| AppError::Database)?;
    Ok(applies.is_some())
}

pub(crate) async fn hide_send_email_is_disabled(
    db: &D1Database,
    user_id: &str,
) -> Result<bool, AppError> {
    let rows: Vec<Value> = db
        .prepare(
            "SELECT p.data FROM org_policies p
             JOIN users_organizations m ON m.organization_id = p.organization_id
             WHERE m.user_id = ?1 AND m.status IN (?2, ?3)
               AND m.type NOT IN (?4, ?5) AND p.type = 7 AND p.enabled = 1",
        )
        .bind(&[
            user_id.into(),
            MEMBER_STATUS_ACCEPTED.into(),
            MEMBER_STATUS_CONFIRMED.into(),
            MEMBER_TYPE_OWNER.into(),
            MEMBER_TYPE_ADMIN.into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    Ok(rows.into_iter().any(|row| {
        row.get("data")
            .and_then(Value::as_str)
            .and_then(|data| serde_json::from_str::<Value>(data).ok())
            .and_then(|data| {
                data.get("disableHideEmail")
                    .or_else(|| data.get("DisableHideEmail"))
                    .and_then(Value::as_bool)
            })
            .unwrap_or(false)
    }))
}

pub(crate) async fn delete_membership_preserving_owner(
    db: &D1Database,
    org_id: &str,
    member_id: &str,
) -> Result<(), AppError> {
    let result = db
        .prepare(
            "DELETE FROM users_organizations
             WHERE id = ?1 AND organization_id = ?2
               AND (type <> ?3 OR status <> ?4 OR
                    (SELECT COUNT(*) FROM users_organizations owners
                     WHERE owners.organization_id = ?2 AND owners.type = ?3
                       AND owners.status = ?4) > 1)",
        )
        .bind(&[
            member_id.into(),
            org_id.into(),
            MEMBER_TYPE_OWNER.into(),
            MEMBER_STATUS_CONFIRMED.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    if result.meta()?.and_then(|meta| meta.changes).unwrap_or(0) == 0 {
        return Err(AppError::BadRequest(
            "The last confirmed owner cannot be removed or revoked".to_string(),
        ));
    }
    Ok(())
}

pub(crate) async fn profile_organizations(
    db: &D1Database,
    env: &worker::Env,
    user_id: &str,
) -> Result<Vec<Value>, AppError> {
    if !organizations_enabled(env) {
        return Ok(Vec::new());
    }
    let rows: Vec<Value> = db
        .prepare(
            "SELECT m.*,
                    o.id AS org_id, o.name AS org_name, o.billing_email AS org_billing_email,
                    o.private_key AS org_private_key, o.public_key AS org_public_key,
                    o.created_at AS org_created_at, o.updated_at AS org_updated_at
             FROM users_organizations m JOIN organizations o ON o.id = m.organization_id
             WHERE m.user_id = ?1 AND m.status >= ?2 ORDER BY o.name COLLATE NOCASE",
        )
        .bind(&[user_id.into(), MEMBER_STATUS_INVITED.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let mut output = Vec::new();
    for row in rows {
        let membership: Membership =
            serde_json::from_value(row.clone()).map_err(|_| AppError::Internal)?;
        let org = Organization {
            id: row
                .get("org_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            name: row
                .get("org_name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            billing_email: row
                .get("org_billing_email")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            private_key: row
                .get("org_private_key")
                .and_then(Value::as_str)
                .map(str::to_string),
            public_key: row
                .get("org_public_key")
                .and_then(Value::as_str)
                .map(str::to_string),
            created_at: row
                .get("org_created_at")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            updated_at: row
                .get("org_updated_at")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        };
        output.push(membership.profile_json(
            &org,
            events_enabled(env),
            groups_enabled(env),
            notify::is_email_webhook_configured(env),
        ));
    }
    Ok(output)
}

pub(crate) async fn sync_collections(
    db: &D1Database,
    env: &worker::Env,
    user_id: &str,
) -> Result<Vec<Value>, AppError> {
    if !organizations_enabled(env) {
        return Ok(Vec::new());
    }
    let rows: Vec<Value> = db
        .prepare(
            "SELECT c.*,
                    CASE WHEN m.type IN (?3, ?4) OR m.access_all = 1 OR
                              EXISTS(SELECT 1 FROM groups_users gu JOIN groups g ON g.id = gu.group_id
                                     WHERE gu.membership_id = m.id AND g.access_all = 1)
                         THEN 0
                         ELSE COALESCE(
                            (SELECT uc.read_only FROM users_collections uc
                             WHERE uc.membership_id = m.id AND uc.collection_id = c.id),
                            (SELECT MIN(cg.read_only) FROM collections_groups cg
                             JOIN groups_users gu ON gu.group_id = cg.group_id
                             WHERE gu.membership_id = m.id AND cg.collection_id = c.id), 1)
                    END AS access_read_only,
                    CASE WHEN m.type IN (?3, ?4) OR m.access_all = 1 OR
                              EXISTS(SELECT 1 FROM groups_users gu JOIN groups g ON g.id = gu.group_id
                                     WHERE gu.membership_id = m.id AND g.access_all = 1)
                         THEN 0
                         ELSE COALESCE(
                            (SELECT uc.hide_passwords FROM users_collections uc
                             WHERE uc.membership_id = m.id AND uc.collection_id = c.id),
                            (SELECT MIN(cg.hide_passwords) FROM collections_groups cg
                             JOIN groups_users gu ON gu.group_id = cg.group_id
                             WHERE gu.membership_id = m.id AND cg.collection_id = c.id), 1)
                    END AS access_hide_passwords,
                    CASE WHEN m.type IN (?3, ?4) OR m.access_all = 1 THEN 1
                         WHEN EXISTS(SELECT 1 FROM groups_users gu JOIN groups g ON g.id = gu.group_id
                                     WHERE gu.membership_id = m.id AND g.access_all = 1)
                         THEN 0
                         ELSE COALESCE(
                            (SELECT uc.manage FROM users_collections uc
                             WHERE uc.membership_id = m.id AND uc.collection_id = c.id),
                            (SELECT MAX(cg.manage) FROM collections_groups cg
                             JOIN groups_users gu ON gu.group_id = cg.group_id
                             WHERE gu.membership_id = m.id AND cg.collection_id = c.id), 0)
                    END AS access_manage
             FROM collections c
             JOIN users_organizations m ON m.organization_id = c.organization_id
             WHERE m.user_id = ?1 AND m.status = ?2
               AND (m.type IN (?3, ?4) OR m.access_all = 1 OR
                    EXISTS(SELECT 1 FROM users_collections uc
                           WHERE uc.membership_id = m.id AND uc.collection_id = c.id) OR
                    EXISTS(SELECT 1 FROM groups_users gu JOIN groups g ON g.id = gu.group_id
                           WHERE gu.membership_id = m.id AND g.access_all = 1) OR
                    EXISTS(SELECT 1 FROM collections_groups cg
                           JOIN groups_users gu ON gu.group_id = cg.group_id
                           WHERE gu.membership_id = m.id AND cg.collection_id = c.id))",
        )
        .bind(&[
            user_id.into(),
            MEMBER_STATUS_CONFIRMED.into(),
            MEMBER_TYPE_OWNER.into(),
            MEMBER_TYPE_ADMIN.into(),
        ])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let mut output = Vec::new();
    for row in rows {
        let collection: Collection =
            serde_json::from_value(row.clone()).map_err(|_| AppError::Internal)?;
        output.push(collection.to_details_json(
            row.get("access_read_only").and_then(Value::as_i64) != Some(0),
            row.get("access_hide_passwords").and_then(Value::as_i64) != Some(0),
            row.get("access_manage").and_then(Value::as_i64) == Some(1),
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_vaultwarden_member_types() {
        assert_eq!(
            parse_member_type(&json!(0)).unwrap(),
            (MEMBER_TYPE_OWNER, false)
        );
        assert_eq!(
            parse_member_type(&json!("Admin")).unwrap(),
            (MEMBER_TYPE_ADMIN, false)
        );
        assert_eq!(
            parse_member_type(&json!(4)).unwrap(),
            (MEMBER_TYPE_MANAGER, true)
        );
        assert!(parse_member_type(&json!(99)).is_err());
    }

    #[test]
    fn list_response_uses_bitwarden_shape() {
        let value = list_response(vec![json!({"id": "one"})]);
        assert_eq!(value["object"], "list");
        assert_eq!(value["data"][0]["id"], "one");
        assert!(value["continuationToken"].is_null());
    }
}
