use super::{escape_html, format_timestamp};

pub fn format_markdown(notification: &super::super::types::Notification) -> String {
    let code_data = match &notification.verification_code {
        Some(data) => data,
        None => return String::new(),
    };

    let now = format_timestamp();
    format!(
        "# {} Warden Worker 验证码\n> <font color=\"comment\">🕒 时间：</font>{}\n> <font color=\"comment\">📧 邮箱：</font>{}\n\n您的验证码是：<font color=\"warning\">**{}**</font>\n\n验证码有效期为10分钟，请尽快完成验证。",
        code_data.code_type.emoji(),
        now,
        escape_html(&code_data.email),
        escape_html(&code_data.code)
    )
}

pub fn format_html(notification: &super::super::types::Notification) -> String {
    let code_data = match &notification.verification_code {
        Some(data) => data,
        None => return String::new(),
    };

    let now = format_timestamp();
    format!(
        "<b>{} Warden Worker 验证码</b>\n🕒 时间：{}\n📧 邮箱：{}\n\n您的验证码是：<b>{}</b>\n\n验证码有效期为10分钟，请尽快完成验证。",
        code_data.code_type.emoji(),
        escape_html(&now),
        escape_html(&code_data.email),
        escape_html(&code_data.code)
    )
}
