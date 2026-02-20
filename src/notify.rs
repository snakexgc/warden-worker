use axum::http::HeaderMap;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use worker::{wasm_bindgen::JsValue, Context, Env, Fetch, Method, Request, RequestInit};

use crate::db::get_db;
use crate::logging::targets;

const WEBHOOK_SECRET_NAME: &str = "WEWORK_WEBHOOK_URL";
const EVENTS_VAR_NAME: &str = "NOTIFY_EVENTS";
const MAX_UA_HISTORY: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyEvent {
    Login,
    LoginFailed,
    PasswordHint,
    PasswordChange,
    EmailChange,
    KdfChange,
    CipherCreate,
    CipherUpdate,
    CipherDelete,
    Import,
    SendCreate,
    SendDelete,
    TwoFactorEnable,
    TwoFactorDisable,
}

impl NotifyEvent {
    fn key(self) -> &'static str {
        match self {
            NotifyEvent::Login => "login",
            NotifyEvent::LoginFailed => "login_failed",
            NotifyEvent::PasswordHint => "password_hint",
            NotifyEvent::PasswordChange => "password",
            NotifyEvent::EmailChange => "email",
            NotifyEvent::KdfChange => "kdf",
            NotifyEvent::CipherCreate => "cipher_create",
            NotifyEvent::CipherUpdate => "cipher_update",
            NotifyEvent::CipherDelete => "cipher_delete",
            NotifyEvent::Import => "import",
            NotifyEvent::SendCreate => "send_create",
            NotifyEvent::SendDelete => "send_delete",
            NotifyEvent::TwoFactorEnable => "2fa_enable",
            NotifyEvent::TwoFactorDisable => "2fa_disable",
        }
    }

    fn title(self) -> &'static str {
        match self {
            NotifyEvent::Login => "登录成功",
            NotifyEvent::LoginFailed => "登录失败",
            NotifyEvent::PasswordHint => "密码提示",
            NotifyEvent::PasswordChange => "修改主密码",
            NotifyEvent::EmailChange => "修改邮箱",
            NotifyEvent::KdfChange => "修改 KDF 设置",
            NotifyEvent::CipherCreate => "新增密码项",
            NotifyEvent::CipherUpdate => "修改密码项",
            NotifyEvent::CipherDelete => "删除密码项",
            NotifyEvent::Import => "导入数据",
            NotifyEvent::SendCreate => "创建 Send",
            NotifyEvent::SendDelete => "删除 Send",
            NotifyEvent::TwoFactorEnable => "启用 2FA",
            NotifyEvent::TwoFactorDisable => "关闭 2FA",
        }
    }

    fn emoji(self) -> &'static str {
        match self {
            NotifyEvent::Login => "🔐",
            NotifyEvent::LoginFailed => "🚫",
            NotifyEvent::PasswordHint => "💡",
            NotifyEvent::PasswordChange => "🔑",
            NotifyEvent::EmailChange => "📧",
            NotifyEvent::KdfChange => "⚙️",
            NotifyEvent::CipherCreate => "📝",
            NotifyEvent::CipherUpdate => "📝",
            NotifyEvent::CipherDelete => "🗑️",
            NotifyEvent::Import => "📥",
            NotifyEvent::SendCreate => "📤",
            NotifyEvent::SendDelete => "🗑️",
            NotifyEvent::TwoFactorEnable => "🛡️",
            NotifyEvent::TwoFactorDisable => "🔓",
        }
    }

    fn color(self) -> &'static str {
        match self {
            NotifyEvent::Login => "info",
            NotifyEvent::LoginFailed => "warning",
            NotifyEvent::PasswordHint => "warning",
            NotifyEvent::PasswordChange => "warning",
            NotifyEvent::EmailChange => "warning",
            NotifyEvent::KdfChange => "warning",
            NotifyEvent::CipherDelete | NotifyEvent::SendDelete => "warning",
            _ => "comment",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Geo {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
}

impl Geo {
    fn to_string(&self) -> String {
        let mut parts = Vec::new();
        if let Some(c) = &self.country {
            parts.push(c.clone());
        }
        if let Some(r) = &self.region {
            parts.push(r.clone());
        }
        if let Some(c) = &self.city {
            parts.push(c.clone());
        }
        if parts.is_empty() {
            "Unknown".to_string()
        } else {
            parts.join(", ")
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RequestMeta {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub geo: Option<Geo>,
}

pub fn extract_request_meta(headers: &HeaderMap) -> RequestMeta {
    let get = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).map(|s| s.to_string());

    let ip = get("CF-Connecting-IP")
        .or_else(|| {
            get("X-Forwarded-For").and_then(|v| {
                v.split(',')
                    .next()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
            })
        })
        .or_else(|| get("X-Real-IP"));

    let user_agent = get("User-Agent");

    let geo = if get("X-CF-Country").is_some() {
        Some(Geo {
            country: get("X-CF-Country"),
            region: get("X-CF-Region"),
            city: get("X-CF-City"),
        })
    } else {
        None
    };

    RequestMeta { ip, user_agent, geo }
}

#[derive(Debug, Clone, Default)]
pub struct NotifyContext {
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub device_identifier: Option<String>,
    pub device_name: Option<String>,
    pub device_type: Option<i32>,
    pub cipher_id: Option<String>,
    pub send_id: Option<String>,
    pub detail: Option<String>,
    pub meta: RequestMeta,
    pub is_new_ua: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UaRecord {
    ua: String,
    last_seen_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UaHistory {
    records: Vec<UaRecord>,
}

impl Default for UaHistory {
    fn default() -> Self {
        Self { records: Vec::new() }
    }
}

impl UaHistory {
    fn is_new_ua(&self, ua: &str) -> bool {
        !self.records.iter().any(|r| r.ua == ua)
    }

    fn update_ua(&mut self, ua: &str) {
        let now = Utc::now()
            .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        if let Some(pos) = self.records.iter().position(|r| r.ua == ua) {
            self.records.remove(pos);
        }

        self.records.push(UaRecord {
            ua: ua.to_string(),
            last_seen_at: now,
        });

        if self.records.len() > MAX_UA_HISTORY {
            self.records.remove(0);
        }
    }

    fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{\"records\":[]}".to_string())
    }

    fn from_json(json_str: &str) -> Self {
        serde_json::from_str(json_str).unwrap_or_default()
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut out = s[..max].to_string();
    out.push_str("…");
    out
}

async fn get_user_ua_history(user_id: &str, env: &Env) -> Result<UaHistory, worker::Error> {
    let db = match get_db(env) {
        Ok(db) => db,
        Err(e) => return Err(worker::Error::RustError(e.to_string())),
    };
    let query = "SELECT ua_history FROM users WHERE id = ?";
    let result = db.prepare(query).bind(&[user_id.into()])?.first::<serde_json::Value>(None).await?;

    match result {
        Some(row) => {
            let history_json = row.get("ua_history").and_then(|v| v.as_str()).unwrap_or("{\"records\":[]}");
            Ok(UaHistory::from_json(history_json))
        }
        None => Ok(UaHistory::default()),
    }
}

async fn update_user_ua_history(user_id: &str, env: &Env, ua: &str) -> Result<(), worker::Error> {
    let db = match get_db(env) {
        Ok(db) => db,
        Err(e) => return Err(worker::Error::RustError(e.to_string())),
    };

    let query = "SELECT ua_history FROM users WHERE id = ?";
    let result = db.prepare(query).bind(&[user_id.into()])?.first::<serde_json::Value>(None).await?;

    let mut history = match result {
        Some(row) => {
            let history_json = row.get("ua_history").and_then(|v| v.as_str()).unwrap_or("{\"records\":[]}");
            UaHistory::from_json(history_json)
        }
        None => UaHistory::default(),
    };

    history.update_ua(ua);

    let update_query = "UPDATE users SET ua_history = ? WHERE id = ?";
    db.prepare(update_query)
        .bind(&[history.to_json().into(), user_id.into()])?
        .run()
        .await?;

    Ok(())
}

fn format_markdown(event: NotifyEvent, ctx: &NotifyContext) -> String {
    let now = Utc::now()
        .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    let mut lines = Vec::new();
    lines.push(format!("# {} Warden Worker 通知", event.emoji()));
    lines.push(format!("> <font color=\"comment\">🕒 时间：</font>{}", now));
    lines.push(format!("> <font color=\"comment\">🛠️ 操作：</font><font color=\"{}\">{}</font>", event.color(), event.title()));

    if let Some(email) = ctx.user_email.as_deref() {
        lines.push(format!("> <font color=\"comment\">👤 用户：</font>{}", truncate(email, 256)));
    } else if let Some(uid) = ctx.user_id.as_deref() {
        lines.push(format!("> <font color=\"comment\">🆔 ID：</font>{}", truncate(uid, 64)));
    }

    if ctx.device_identifier.is_some() || ctx.device_name.is_some() || ctx.device_type.is_some() {
        let name = ctx
            .device_name
            .as_deref()
            .map(|s| truncate(s, 128))
            .unwrap_or_else(|| "-".to_string());
        // let ident = ctx
        //     .device_identifier
        //     .as_deref()
        //     .map(|s| truncate(s, 128))
        //     .unwrap_or_else(|| "-".to_string());
        let dtype = ctx
            .device_type
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        lines.push(format!("> <font color=\"comment\">📱 设备：</font>{} (Type: {})", name, dtype));
    }

    if let Some(cipher_id) = ctx.cipher_id.as_deref() {
        lines.push(format!("> <font color=\"comment\">🔑 Cipher：</font>{}", truncate(cipher_id, 64)));
    }

    if let Some(send_id) = ctx.send_id.as_deref() {
        lines.push(format!("> <font color=\"comment\">📦 Send：</font>{}", truncate(send_id, 64)));
    }

    if let Some(detail) = ctx.detail.as_deref() {
        lines.push(format!("> <font color=\"comment\">📝 详情：</font>{}", truncate(detail, 512)));
    }

    if let Some(ip) = ctx.meta.ip.as_deref() {
        let geo_str = ctx.meta.geo.as_ref().map(|g| g.to_string()).unwrap_or_else(|| "".to_string());
        let loc_info = if geo_str.is_empty() {
            ip.to_string()
        } else {
            format!("{} ({})", ip, geo_str)
        };
        lines.push(format!("> <font color=\"comment\">🌐 网络：</font>{}", truncate(&loc_info, 128)));
    }

    if let Some(ua) = ctx.meta.user_agent.as_deref() {
        let new_ua_tag = if ctx.is_new_ua {
            "<font color=\"warning\">[新设备]</font> "
        } else {
            ""
        };
        lines.push(format!(
            "> <font color=\"comment\">💻 UA：</font>{}{}",
            new_ua_tag,
            truncate(ua, 512)
        ));
    }

    truncate(&lines.join("\n"), 3800)
}

fn parse_enabled_events(env: &Env) -> Vec<NotifyEvent> {
    let raw = env.var(EVENTS_VAR_NAME).ok().map(|v| v.to_string());
    let Some(raw) = raw else { return Vec::new() };
    let raw = raw.trim().to_lowercase();
    if raw.is_empty() || matches!(raw.as_str(), "none" | "off" | "0" | "false") {
        return Vec::new();
    }
    if matches!(raw.as_str(), "all" | "*") {
        return vec![
            NotifyEvent::Login,
            NotifyEvent::LoginFailed,
            NotifyEvent::PasswordHint,
            NotifyEvent::PasswordChange,
            NotifyEvent::EmailChange,
            NotifyEvent::KdfChange,
            NotifyEvent::CipherCreate,
            NotifyEvent::CipherUpdate,
            NotifyEvent::CipherDelete,
            NotifyEvent::Import,
            NotifyEvent::SendCreate,
            NotifyEvent::SendDelete,
            NotifyEvent::TwoFactorEnable,
            NotifyEvent::TwoFactorDisable,
        ];
    }

    let mut out = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part {
            "login" => out.push(NotifyEvent::Login),
            "login_failed" | "login_fail" => out.push(NotifyEvent::LoginFailed),
            "password_hint" | "password-hint" => out.push(NotifyEvent::PasswordHint),
            "password" | "password_change" => out.push(NotifyEvent::PasswordChange),
            "email" | "email_change" => out.push(NotifyEvent::EmailChange),
            "kdf" | "kdf_change" => out.push(NotifyEvent::KdfChange),
            "cipher_create" | "cipher.add" | "cipher_add" | "create_cipher" => {
                out.push(NotifyEvent::CipherCreate)
            }
            "cipher_update" | "cipher.update" | "cipher_edit" | "update_cipher" => {
                out.push(NotifyEvent::CipherUpdate)
            }
            "cipher_delete" | "cipher.del" | "delete_cipher" => {
                out.push(NotifyEvent::CipherDelete)
            }
            "import" => out.push(NotifyEvent::Import),
            "send_create" | "send.create" | "send_add" => out.push(NotifyEvent::SendCreate),
            "send_delete" | "send.del" | "send_remove" => out.push(NotifyEvent::SendDelete),
            "2fa_enable" | "two_factor_enable" | "twofactor_enable" => out.push(NotifyEvent::TwoFactorEnable),
            "2fa_disable" | "two_factor_disable" | "twofactor_disable" => out.push(NotifyEvent::TwoFactorDisable),
            _ => {}
        }
    }

    out.sort_by_key(|e| e.key());
    out.dedup();
    out
}

fn should_notify(env: &Env, event: NotifyEvent) -> bool {
    let enabled = parse_enabled_events(env);
    enabled.iter().any(|e| *e == event)
}

pub async fn notify_best_effort(env: &Env, event: NotifyEvent, mut ctx: NotifyContext) {
    if !should_notify(env, event) {
        log::debug!(target: targets::NOTIFY, "notify skipped event={}", event.key());
        return;
    }

    if let (Some(user_id), Some(ua)) = (ctx.user_id.as_deref(), ctx.meta.user_agent.as_deref()) {
        match get_user_ua_history(user_id, env).await {
            Ok(history) => {
                ctx.is_new_ua = history.is_new_ua(ua);
                if let Err(e) = update_user_ua_history(user_id, env, ua).await {
                    log::warn!(target: targets::NOTIFY, "update ua history failed user_id={} err={:?}", user_id, e);
                }
            }
            Err(e) => {
                log::warn!(target: targets::NOTIFY, "get ua history failed user_id={} err={:?}", user_id, e);
            }
        }
    }

    let webhook = match env.secret(WEBHOOK_SECRET_NAME) {
        Ok(s) => s.to_string(),
        Err(_) => {
            log::debug!(target: targets::NOTIFY, "notify skipped missing secret={}", WEBHOOK_SECRET_NAME);
            return;
        }
    };

    if let Err(e) = send_markdown(&webhook, event, &ctx).await {
        log::warn!(target: targets::NOTIFY, "notify send failed event={} err={:?}", event.key(), e);
    }
}

pub fn notify_background(context: &Context, env: Env, event: NotifyEvent, notify_ctx: NotifyContext) {
    context.wait_until(async move {
        notify_best_effort(&env, event, notify_ctx).await;
    });
}

pub fn is_webhook_configured(env: &Env) -> bool {
    env.secret(WEBHOOK_SECRET_NAME).is_ok()
}

pub async fn send_password_hint(env: &Env, ctx: NotifyContext) -> Result<(), worker::Error> {
    let webhook = env.secret(WEBHOOK_SECRET_NAME)?.to_string();
    send_markdown(&webhook, NotifyEvent::PasswordHint, &ctx).await
}

pub fn send_password_hint_background(context: &Context, env: Env, notify_ctx: NotifyContext) {
    context.wait_until(async move {
        if let Err(e) = send_password_hint(&env, notify_ctx).await {
            log::warn!(target: targets::NOTIFY, "send_password_hint failed err={:?}", e);
        }
    });
}

async fn send_markdown(webhook: &str, event: NotifyEvent, ctx: &NotifyContext) -> Result<(), worker::Error> {
    let content = format_markdown(event, ctx);
    let body = json!({
        "msgtype": "markdown",
        "markdown": { "content": content }
    })
    .to_string();

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(JsValue::from_str(&body)));
    let mut request = Request::new_with_init(webhook, &init)?;

    if let Ok(headers) = request.headers_mut() {
        let _ = headers.set("content-type", "application/json; charset=utf-8");
    }

    log::info!(
        target: targets::NOTIFY,
        "notify sending event={} user_id={:?} ip={:?}",
        event.key(),
        ctx.user_id.as_deref(),
        ctx.meta.ip.as_deref()
    );

    let r = Fetch::Request(request).send().await?;
    let status = r.status_code();
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(worker::Error::RustError(format!("notify failed status={}", status)))
    }
}
