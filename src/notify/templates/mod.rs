mod code;
mod event;

use chrono::Utc;

pub fn format_timestamp() -> String {
    Utc::now()
        .with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut out = s[..max].to_string();
    out.push_str("…");
    out
}

pub fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

use super::types::Notification;

pub fn format_for_wework(notification: &Notification) -> String {
    match notification.kind {
        super::types::NotificationKind::Event => event::format_markdown(notification),
        super::types::NotificationKind::VerificationCode => code::format_markdown(notification),
    }
}

pub fn format_for_telegram(notification: &Notification) -> String {
    match notification.kind {
        super::types::NotificationKind::Event => event::format_html(notification),
        super::types::NotificationKind::VerificationCode => code::format_html(notification),
    }
}
