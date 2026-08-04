use std::{collections::HashSet, sync::Arc};

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, header},
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;
use worker::D1Database;

use crate::{
    api::{AppState, core::organizations},
    auth::OrgApiKeyClaims,
    db,
    db::models::{
        MEMBER_STATUS_CONFIRMED, MEMBER_STATUS_INVITED, MEMBER_TYPE_OWNER, MEMBER_TYPE_USER,
        Membership, OrganizationApiKey,
    },
    error::AppError,
};

const REVOKE_OFFSET: i32 = 128;
const DIRECTORY_IMPORT_MAX_ENTRIES: usize = 2_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportGroupData {
    name: String,
    external_id: String,
    #[serde(default)]
    member_external_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportUserData {
    email: String,
    external_id: String,
    #[serde(default)]
    deleted: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrgImportData {
    #[serde(default)]
    groups: Vec<OrgImportGroupData>,
    #[serde(default)]
    members: Vec<OrgImportUserData>,
    #[serde(default)]
    overwrite_existing: bool,
    #[serde(default, rename = "largeImport")]
    _large_import: bool,
}

async fn authenticate_public_token(
    state: &AppState,
    headers: &HeaderMap,
    database: &D1Database,
) -> Result<String, AppError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::Unauthorized("No access token provided".to_string()))?;
    let claims = decode::<OrgApiKeyClaims>(
        token,
        &DecodingKey::from_secret(state.jwt_keys.access_secret.as_ref()),
        &Validation::default(),
    )
    .map_err(|_| AppError::Unauthorized("Invalid claim".to_string()))?
    .claims;

    let expected_issuer = format!(
        "{}|api.organization",
        state.public_url("").trim_end_matches('/')
    );
    if claims.iss != expected_issuer
        || claims.scope.len() != 1
        || claims.scope[0] != "api.organization"
        || claims.client_sub.is_empty()
        || claims.client_id != format!("organization.{}", claims.client_sub)
    {
        return Err(AppError::Unauthorized(
            "Token not issued by this server".to_string(),
        ));
    }

    let api_key: Option<OrganizationApiKey> = database
        .prepare(
            "SELECT id, organization_id, type, api_key, revision_date FROM organization_api_key WHERE organization_id = ?1",
        )
        .bind(&[claims.client_sub.clone().into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)?;
    let api_key = api_key.ok_or_else(|| AppError::Unauthorized("Invalid client_id".to_string()))?;
    if api_key.id != claims.sub || api_key.organization_id != claims.client_sub {
        return Err(AppError::Unauthorized(
            "Token not issued for this organization".to_string(),
        ));
    }
    Ok(api_key.organization_id)
}

async fn membership_by_email(
    database: &D1Database,
    organization_id: &str,
    email: &str,
) -> Result<Option<Membership>, AppError> {
    database
        .prepare(
            "SELECT m.* FROM users_organizations m
             JOIN users u ON u.id = m.user_id
             WHERE m.organization_id = ?1 AND u.email = ?2",
        )
        .bind(&[organization_id.into(), email.into()])?
        .first(None)
        .await
        .map_err(|_| AppError::Database)
}

async fn import_existing_member(
    database: &D1Database,
    organization_id: &str,
    mut member: Membership,
    data: &OrgImportUserData,
) -> Result<(), AppError> {
    if data.deleted {
        let can_revoke = if member.member_type == MEMBER_TYPE_OWNER
            && member.status == MEMBER_STATUS_CONFIRMED
        {
            let owner_count: Option<i32> = database
                .prepare(
                    "SELECT COUNT(*) AS count FROM users_organizations
                     WHERE organization_id = ?1 AND type = ?2 AND status = ?3",
                )
                .bind(&[
                    organization_id.into(),
                    MEMBER_TYPE_OWNER.into(),
                    MEMBER_STATUS_CONFIRMED.into(),
                ])?
                .first(Some("count"))
                .await
                .map_err(|_| AppError::Database)?;
            owner_count.unwrap_or_default() > 1
        } else {
            true
        };
        if can_revoke && member.status >= MEMBER_STATUS_INVITED {
            member.status -= REVOKE_OFFSET;
        }
    } else if member.status < MEMBER_STATUS_INVITED {
        let mut restored = member.clone();
        restored.status += REVOKE_OFFSET;
        if organizations::validate_membership_policies(database, &restored)
            .await
            .is_ok()
        {
            member.status = restored.status;
        }
    }

    database
        .prepare(
            "UPDATE users_organizations SET status = ?1, external_id = ?2, updated_at = ?3
             WHERE id = ?4 AND organization_id = ?5",
        )
        .bind(&[
            member.status.into(),
            data.external_id.clone().into(),
            db::now_rfc3339_millis().into(),
            member.id.into(),
            organization_id.into(),
        ])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    Ok(())
}

async fn import_new_member(
    state: &AppState,
    database: &D1Database,
    organization_id: &str,
    email: &str,
    external_id: &str,
) -> Result<(), AppError> {
    let organization = organizations::load_organization(database, organization_id).await?;
    let existing: Option<Value> = database
        .prepare("SELECT id, master_password_hash FROM users WHERE email = ?1")
        .bind(&[email.into()])?
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
    let membership_id = Uuid::new_v4().to_string();
    let now = db::now_rfc3339_millis();
    let mut statements = Vec::new();
    if existing.is_none() {
        statements.push(
            database
                .prepare(
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
                    email.into(),
                    Uuid::new_v4().to_string().into(),
                    now.clone().into(),
                    now.clone().into(),
                ])?,
        );
    }
    statements.push(
        database
            .prepare(
                "INSERT INTO users_organizations
                 (id, user_id, organization_id, invited_by_email, access_all, key, status, type,
                  reset_password_key, external_id, permissions, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 0, '', ?5, ?6, NULL, ?7, '{}', ?8, ?9)",
            )
            .bind(&[
                membership_id.clone().into(),
                user_id.clone().into(),
                organization_id.into(),
                organization.billing_email.clone().into(),
                MEMBER_STATUS_INVITED.into(),
                MEMBER_TYPE_USER.into(),
                external_id.into(),
                now.clone().into(),
                now.clone().into(),
            ])?,
    );
    statements.push(
        database
            .prepare(
                "INSERT INTO invitations (email, created_at, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(email) DO UPDATE SET updated_at = excluded.updated_at",
            )
            .bind(&[email.into(), now.clone().into(), now.into()])?,
    );
    database
        .batch(statements)
        .await
        .map_err(|_| AppError::Database)?;
    organizations::send_invite_link(
        state,
        &organization,
        email,
        &user_id,
        &membership_id,
        Some(organization.billing_email.clone()),
        has_existing_user,
    )
    .await
}

async fn import_groups(
    database: &D1Database,
    organization_id: &str,
    groups: &[OrgImportGroupData],
) -> Result<(), AppError> {
    for group in groups {
        let group_id: Option<String> = database
            .prepare("SELECT id FROM groups WHERE organization_id = ?1 AND external_id = ?2")
            .bind(&[organization_id.into(), group.external_id.clone().into()])?
            .first(Some("id"))
            .await
            .map_err(|_| AppError::Database)?;
        let group_id = match group_id {
            Some(group_id) => group_id,
            None => {
                let group_id = Uuid::new_v4().to_string();
                let now = db::now_rfc3339_millis();
                database
                    .prepare(
                        "INSERT INTO groups
                         (id, organization_id, name, access_all, external_id, created_at, updated_at)
                         VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6)",
                    )
                    .bind(&[
                        group_id.clone().into(),
                        organization_id.into(),
                        group.name.clone().into(),
                        group.external_id.clone().into(),
                        now.clone().into(),
                        now.into(),
                    ])?
                    .run()
                    .await
                    .map_err(|_| AppError::Database)?;
                group_id
            }
        };
        database
            .prepare("DELETE FROM groups_users WHERE group_id = ?1")
            .bind(&[group_id.clone().into()])?
            .run()
            .await
            .map_err(|_| AppError::Database)?;
        for external_id in &group.member_external_ids {
            database
                .prepare(
                    "INSERT OR IGNORE INTO groups_users (group_id, membership_id)
                     SELECT ?1, id FROM users_organizations
                     WHERE organization_id = ?2 AND external_id = ?3",
                )
                .bind(&[
                    group_id.clone().into(),
                    organization_id.into(),
                    external_id.clone().into(),
                ])?
                .run()
                .await
                .map_err(|_| AppError::Database)?;
        }
    }
    Ok(())
}

#[worker::send]
pub async fn import_organization_directory(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(data): Json<OrgImportData>,
) -> Result<Json<Value>, AppError> {
    if !organizations::organizations_enabled(&state.env) {
        return Err(AppError::NotFound(
            "Organization support is disabled".to_string(),
        ));
    }
    if data.members.len() > DIRECTORY_IMPORT_MAX_ENTRIES
        || data.groups.len() > DIRECTORY_IMPORT_MAX_ENTRIES
    {
        return Err(AppError::BadRequest(format!(
            "A directory import supports at most {DIRECTORY_IMPORT_MAX_ENTRIES} members and groups"
        )));
    }
    let database = db::get_db(&state.env)?;
    let organization_id = authenticate_public_token(&state, &headers, &database).await?;

    let mut imported_external_ids = HashSet::new();
    for member_data in &data.members {
        let email = crate::auth::normalize_email(&member_data.email);
        if email.is_empty() || member_data.external_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "Directory members require email and externalId".to_string(),
            ));
        }
        if !imported_external_ids.insert(member_data.external_id.clone()) {
            return Err(AppError::BadRequest(
                "Directory member externalId values must be unique".to_string(),
            ));
        }
        match membership_by_email(&database, &organization_id, &email).await? {
            Some(member) => {
                import_existing_member(&database, &organization_id, member, member_data).await?
            }
            None if !member_data.deleted => {
                import_new_member(
                    &state,
                    &database,
                    &organization_id,
                    &email,
                    &member_data.external_id,
                )
                .await?
            }
            None => {}
        }
    }

    if organizations::groups_enabled(&state.env) {
        import_groups(&database, &organization_id, &data.groups).await?;
    } else if !data.groups.is_empty() {
        log::warn!("Organization groups are disabled; directory groups were not imported");
    }

    if data.overwrite_existing {
        let existing: Vec<Value> = database
            .prepare(
                "SELECT id, external_id FROM users_organizations
                 WHERE organization_id = ?1 AND external_id IS NOT NULL",
            )
            .bind(&[organization_id.clone().into()])?
            .all()
            .await
            .map_err(|_| AppError::Database)?
            .results()?;
        for member in existing {
            let external_id = member
                .get("external_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if imported_external_ids.contains(external_id) {
                continue;
            }
            let member_id = member.get("id").and_then(Value::as_str).unwrap_or_default();
            if !member_id.is_empty() {
                let _ = organizations::delete_membership_preserving_owner(
                    &database,
                    &organization_id,
                    member_id,
                )
                .await;
            }
        }
    }

    organizations::touch_organization_members(&database, &organization_id).await?;
    Ok(Json(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_import_accepts_vaultwarden_shape() {
        let data: OrgImportData = serde_json::from_value(json!({
            "groups": [{
                "name": "Engineering",
                "externalId": "group-1",
                "memberExternalIds": ["member-1"]
            }],
            "members": [{
                "email": "member@example.com",
                "externalId": "member-1",
                "deleted": false
            }],
            "overwriteExisting": true,
            "largeImport": false
        }))
        .expect("deserialize directory import");
        assert_eq!(data.members.len(), 1);
        assert_eq!(data.groups.len(), 1);
        assert!(data.overwrite_existing);
    }
}
