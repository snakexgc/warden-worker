use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;
use worker::D1Database;

use crate::{api::AppState, auth::Claims, db, db::models::Event, error::AppError};

const EVENT_PAGE_SIZE: usize = 30;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventCollection {
    pub r#type: i32,
    pub date: String,
    pub cipher_id: Option<String>,
    pub organization_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRange {
    start: String,
    end: String,
    continuation_token: Option<String>,
}

fn parse_date(value: &str) -> Result<String, AppError> {
    DateTime::parse_from_rfc3339(value)
        .map(|date| {
            date.with_timezone(&Utc)
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        })
        .map_err(|_| AppError::BadRequest("Invalid event date".to_string()))
}

fn event_json(event: Event) -> Value {
    json!({
        "type": event.event_type,
        "userId": event.user_id,
        "organizationId": event.organization_id,
        "cipherId": event.cipher_id,
        "collectionId": event.collection_id,
        "groupId": event.group_id,
        "organizationUserId": event.membership_id,
        "actingUserId": event.acting_user_id,
        "date": event.date,
        "deviceType": event.device_type,
        "ipAddress": event.ip_address,
        "policyId": null,
        "providerId": null,
        "providerUserId": null,
        "providerOrganizationId": null,
        "id": event.id
    })
}

#[allow(clippy::too_many_arguments)]
fn event_statement(
    db: &D1Database,
    event_type: i32,
    user_id: Option<&str>,
    organization_id: Option<&str>,
    cipher_id: Option<&str>,
    membership_id: Option<&str>,
    acting_user_id: &str,
    date: &str,
    ip_address: &str,
) -> Result<worker::D1PreparedStatement, AppError> {
    Ok(db
        .prepare(
            "INSERT INTO events
             (id, type, user_id, organization_id, cipher_id, collection_id, group_id,
              membership_id, device_type, ip_address, acting_user_id, date)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, NULL, ?7, ?8, ?9)",
        )
        .bind(&[
            Uuid::new_v4().to_string().into(),
            event_type.into(),
            user_id.map(str::to_string).into(),
            organization_id.map(str::to_string).into(),
            cipher_id.map(str::to_string).into(),
            membership_id.map(str::to_string).into(),
            ip_address.into(),
            acting_user_id.into(),
            date.into(),
        ])?)
}

/// 服务端审计事件写入（对齐 Vaultwarden `log_event`）。
/// 仅在事件记录启用时写入；device_type/ip 由客户端上报事件使用，服务端事件暂不采集。
#[allow(clippy::too_many_arguments)]
pub(crate) async fn log_event(
    db: &D1Database,
    env: &worker::Env,
    event_type: i32,
    user_id: Option<&str>,
    organization_id: Option<&str>,
    cipher_id: Option<&str>,
    acting_user_id: &str,
) -> Result<(), AppError> {
    if !super::organizations::events_enabled(env) {
        return Ok(());
    }
    let date = db::now_rfc3339_millis();
    db.prepare(
        "INSERT INTO events
         (id, type, user_id, organization_id, cipher_id, collection_id, group_id,
          membership_id, device_type, ip_address, acting_user_id, date)
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, NULL, NULL, NULL, ?6, ?7)",
    )
    .bind(&[
        Uuid::new_v4().to_string().into(),
        event_type.into(),
        user_id.map(str::to_string).into(),
        organization_id.map(str::to_string).into(),
        cipher_id.map(str::to_string).into(),
        acting_user_id.into(),
        date.into(),
    ])?
    .run()
    .await
    .map_err(|_| AppError::Database)?;
    Ok(())
}

/// 用户维度审计事件（对齐 Vaultwarden `log_user_event`），如登录、改密等。
pub(crate) async fn log_user_event(
    db: &D1Database,
    env: &worker::Env,
    event_type: i32,
    user_id: &str,
) -> Result<(), AppError> {
    log_event(db, env, event_type, Some(user_id), None, None, user_id).await
}

/// 对齐 Vaultwarden `event_cleanup_job`：删除早于保留期的审计事件（默认 7 天）。
pub async fn cleanup_old_events(env: &worker::Env) -> Result<u64, AppError> {
    let db = db::get_db(env)?;
    let retention_days: i64 = env
        .var("EVENT_CLEANUP_SCHEDULE_DAYS")
        .ok()
        .and_then(|value| value.to_string().trim().parse().ok())
        .unwrap_or(7)
        .max(1);
    let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days.max(1));
    let cutoff = cutoff
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
        .to_string();
    let result = db
        .prepare("DELETE FROM events WHERE date < ?1")
        .bind(&[cutoff.into()])?
        .run()
        .await
        .map_err(|_| AppError::Database)?;
    let changes = result
        .meta()
        .ok()
        .flatten()
        .and_then(|meta| meta.changes)
        .unwrap_or(0) as u64;
    Ok(changes)
}

/// Persist client audit events only after resolving their organization scope from server-side data.
#[worker::send]
pub async fn post_events_collect(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<Vec<EventCollection>>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    if !super::organizations::events_enabled(&state.env) {
        return Ok(Json(json!({})));
    }
    if payload.len() > 40 {
        return Err(AppError::BadRequest(
            "At most 40 events can be collected in one request".to_string(),
        ));
    }

    let memberships: Vec<Value> = db
        .prepare(
            "SELECT id, organization_id FROM users_organizations
             WHERE user_id = ?1 AND status = 2",
        )
        .bind(&[claims.sub.clone().into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let confirmed_orgs = memberships
        .iter()
        .filter_map(|row| {
            Some((
                row.get("organization_id")?.as_str()?.to_string(),
                row.get("id")?.as_str()?.to_string(),
            ))
        })
        .collect::<HashMap<_, _>>();
    let ip_address = crate::auth::client_ip_from_headers(&headers);
    let mut statements = Vec::new();
    for event in payload {
        let date = parse_date(&event.date)?;
        match event.r#type {
            1000..=1099 => {
                statements.push(event_statement(
                    &db,
                    event.r#type,
                    Some(&claims.sub),
                    None,
                    None,
                    None,
                    &claims.sub,
                    &date,
                    &ip_address,
                )?);
                for (org_id, membership_id) in &confirmed_orgs {
                    statements.push(event_statement(
                        &db,
                        event.r#type,
                        Some(&claims.sub),
                        Some(org_id),
                        None,
                        Some(membership_id),
                        &claims.sub,
                        &date,
                        &ip_address,
                    )?);
                }
            }
            1600..=1699 => {
                if let Some(org_id) = event.organization_id.as_deref()
                    && confirmed_orgs.contains_key(org_id)
                {
                    statements.push(event_statement(
                        &db,
                        event.r#type,
                        None,
                        Some(org_id),
                        None,
                        None,
                        &claims.sub,
                        &date,
                        &ip_address,
                    )?);
                }
            }
            _ => {
                if let Some(cipher_id) = event.cipher_id.as_deref()
                    && let Ok(cipher) = super::ciphers::get_cipher_dbmodel_with_access(
                        &db,
                        cipher_id,
                        &claims.sub,
                        true,
                    )
                    .await
                    && let Some(org_id) = cipher.organization_id.as_deref()
                {
                    statements.push(event_statement(
                        &db,
                        event.r#type,
                        None,
                        Some(org_id),
                        Some(cipher_id),
                        None,
                        &claims.sub,
                        &date,
                        &ip_address,
                    )?);
                }
            }
        }
        if statements.len() > 80 {
            return Err(AppError::BadRequest(
                "The event batch expands beyond the Workers safety limit".to_string(),
            ));
        }
    }
    if !statements.is_empty() {
        db.batch(statements).await.map_err(|_| AppError::Database)?;
    }
    Ok(Json(json!({})))
}

async fn query_events(
    db: &D1Database,
    where_clause: &str,
    first_id: &str,
    range: &EventRange,
) -> Result<Value, AppError> {
    let start = parse_date(&range.start)?;
    let end = parse_date(range.continuation_token.as_deref().unwrap_or(&range.end))?;
    let end_operator = if range.continuation_token.is_some() {
        "<"
    } else {
        "<="
    };
    let sql = format!(
        "SELECT * FROM events WHERE {where_clause} AND date >= ?2 AND date {end_operator} ?3
         ORDER BY date DESC LIMIT {}",
        EVENT_PAGE_SIZE
    );
    let rows: Vec<Event> = db
        .prepare(&sql)
        .bind(&[first_id.into(), start.into(), end.into()])?
        .all()
        .await
        .map_err(|_| AppError::Database)?
        .results()?;
    let continuation = (rows.len() == EVENT_PAGE_SIZE)
        .then(|| rows.last().map(|event| event.date.clone()))
        .flatten();
    Ok(json!({
        "data": rows.into_iter().map(event_json).collect::<Vec<_>>(),
        "object": "list",
        "continuationToken": continuation
    }))
}

#[worker::send]
pub async fn get_organization_events(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(org_id): Path<String>,
    Query(range): Query<EventRange>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = super::organizations::load_membership(&db, &claims.sub, &org_id).await?;
    super::organizations::require_admin(&member)?;
    if !super::organizations::events_enabled(&state.env) {
        return Ok(Json(
            json!({"data": [], "object": "list", "continuationToken": null}),
        ));
    }
    let events = query_events(&db, "organization_id = ?1", &org_id, &range).await?;
    Ok(Json(events))
}

#[worker::send]
pub async fn get_cipher_events(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path(cipher_id): Path<String>,
    Query(range): Query<EventRange>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    if !super::organizations::events_enabled(&state.env) {
        return Ok(Json(
            json!({"data": [], "object": "list", "continuationToken": null}),
        ));
    }
    let empty = || {
        Ok(Json(
            json!({"data": [], "object": "list", "continuationToken": null}),
        ))
    };
    // 对齐 Vaultwarden：无访问权限时返回空列表，而不是 404/403
    let Ok(cipher) =
        super::ciphers::get_cipher_dbmodel_with_access(&db, &cipher_id, &claims.sub, true).await
    else {
        return empty();
    };
    let Some(org_id) = cipher.organization_id else {
        return empty();
    };
    let Ok(member) = super::organizations::load_membership(&db, &claims.sub, &org_id).await else {
        return empty();
    };
    if super::organizations::require_admin(&member).is_err() {
        return empty();
    }
    let events = query_events(&db, "cipher_id = ?1", &cipher_id, &range).await?;
    Ok(Json(events))
}

#[worker::send]
pub async fn get_member_events(
    claims: Claims,
    State(state): State<Arc<AppState>>,
    Path((org_id, member_id)): Path<(String, String)>,
    Query(range): Query<EventRange>,
) -> Result<Json<Value>, AppError> {
    let db = db::get_db(&state.env)?;
    claims.verify_security_stamp(&db).await?;
    let member = super::organizations::load_membership(&db, &claims.sub, &org_id).await?;
    super::organizations::require_admin(&member)?;
    if !super::organizations::events_enabled(&state.env) {
        return Ok(Json(
            json!({"data": [], "object": "list", "continuationToken": null}),
        ));
    }
    let member_user: Option<String> = db
        .prepare(
            "SELECT user_id FROM users_organizations
             WHERE id = ?1 AND organization_id = ?2",
        )
        .bind(&[member_id.clone().into(), org_id.into()])?
        .first(Some("user_id"))
        .await
        .map_err(|_| AppError::Database)?;
    let Some(member_user) = member_user else {
        return Err(AppError::NotFound(
            "Organization member not found".to_string(),
        ));
    };
    // 对齐 Vaultwarden：成员事件按 user_uuid 或 act_user_uuid 匹配
    let events = query_events(
        &db,
        "(user_id = ?1 OR acting_user_id = ?1)",
        &member_user,
        &range,
    )
    .await?;
    Ok(Json(events))
}
