use super::{escape_html, format_timestamp};
use crate::extensions::notify::types::{ActionLinkType, Notification};

fn title(kind: ActionLinkType) -> &'static str {
    match kind {
        ActionLinkType::Registration => "用户注册验证",
        ActionLinkType::OrganizationInvite => "组织邀请",
        ActionLinkType::EmergencyAccessInvite => "紧急访问邀请",
        ActionLinkType::DeleteAccount => "删除账户恢复",
    }
}

pub fn format_markdown(notification: &Notification) -> String {
    let Some(data) = notification.action_link.as_ref() else {
        return String::new();
    };
    let organization = data
        .organization_name
        .as_deref()
        .map(|name| format!("\n> 组织：{}", escape_html(name)))
        .unwrap_or_default();
    format!(
        "# 🔐 Warden Worker {}\n> 时间：{}\n> 目标邮箱：{}{}\n\n请管理员核对邮箱后，将以下一次性链接私下转发给目标用户：\n\n{}",
        title(data.link_type),
        format_timestamp(),
        escape_html(&data.email),
        organization,
        escape_html(&data.url)
    )
}

pub fn format_html(notification: &Notification) -> String {
    let Some(data) = notification.action_link.as_ref() else {
        return String::new();
    };
    let organization = data
        .organization_name
        .as_deref()
        .map(|name| format!("\n组织：{}", escape_html(name)))
        .unwrap_or_default();
    format!(
        "<b>🔐 Warden Worker {}</b>\n时间：{}\n目标邮箱：{}{}\n\n请管理员核对邮箱后，将以下一次性链接私下转发给目标用户：\n\n<code>{}</code>",
        title(data.link_type),
        escape_html(&format_timestamp()),
        escape_html(&data.email),
        organization,
        escape_html(&data.url)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extensions::notify::types::Notification;

    #[test]
    fn action_link_escapes_untrusted_values() {
        let notification = Notification::action_link(
            "user@example.com",
            "https://example.test/?a=<tag>&b=1",
            ActionLinkType::Registration,
            None,
        );
        let rendered = format_html(&notification);
        assert!(rendered.contains("&lt;tag&gt;&amp;b=1"));
        assert!(!rendered.contains("<tag>"));
    }
}
