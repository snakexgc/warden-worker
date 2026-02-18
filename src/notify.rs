use axum::http::HeaderMap;
use chrono::Utc;
use serde_json::json;
use worker::{wasm_bindgen::JsValue, Env, Fetch, Method, Request, RequestInit};

use crate::logging::targets;

const WEBHOOK_SECRET_NAME: &str = "WEWORK_WEBHOOK_URL";
const EVENTS_VAR_NAME: &str = "NOTIFY_EVENTS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyEvent {
    Login,
    LoginFailed,
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
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut out = s[..max].to_string();
    out.push_str("…");
    out
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

    /*
    if let Some(ua) = ctx.meta.user_agent.as_deref() {
        lines.push(format!("> <font color=\"comment\">💻 UA：</font>{}", truncate(ua, 512)));
    }
    */

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

pub async fn notify_best_effort(env: &Env, event: NotifyEvent, ctx: NotifyContext) {
    if !should_notify(env, event) {
        log::debug!(target: targets::NOTIFY, "notify skipped event={}", event.key());
        return;
    }
    let webhook = match env.secret(WEBHOOK_SECRET_NAME) {
        Ok(s) => s.to_string(),
        Err(_) => {
            log::debug!(target: targets::NOTIFY, "notify skipped missing secret={}", WEBHOOK_SECRET_NAME);
            return;
        }
    };

    let content = format_markdown(event, &ctx);
    let body = json!({
        "msgtype": "markdown",
        "markdown": { "content": content }
    })
    .to_string();

    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_body(Some(JsValue::from_str(&body)));
    let mut request = match Request::new_with_init(&webhook, &init) {
        Ok(r) => r,
        Err(e) => {
            log::warn!(target: targets::NOTIFY, "notify request init failed: {:?}", e);
            return;
        }
    };

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

    let res = Fetch::Request(request).send().await;
    match res {
        Ok(r) => {
            let status = r.status_code();
            if (200..300).contains(&status) {
                log::info!(target: targets::NOTIFY, "notify sent event={} status={}", event.key(), status);
            } else {
                log::warn!(target: targets::NOTIFY, "notify failed event={} status={}", event.key(), status);
            }
        }
        Err(e) => {
            log::warn!(target: targets::NOTIFY, "notify send failed event={} err={:?}", event.key(), e);
        }
    }
}
