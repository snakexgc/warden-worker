use super::{escape_html, format_timestamp, truncate};

pub fn format_markdown(notification: &super::super::types::Notification) -> String {
    let event = match notification.event {
        Some(e) => e,
        None => return String::new(),
    };
    let ctx = match &notification.context {
        Some(ctx) => ctx,
        None => return format!("# {} Warden Worker 通知\n> 操作：{}", event.emoji(), event.title()),
    };

    let now = format_timestamp();
    let mut lines = Vec::new();
    lines.push(format!("# {} Warden Worker 通知", event.emoji()));
    lines.push(format!("> <font color=\"comment\">🕒 时间：</font>{}", now));
    lines.push(format!(
        "> <font color=\"comment\">🛠️ 操作：</font><font color=\"{}\">{}</font>",
        event.color(),
        event.title()
    ));

    if let Some(email) = ctx.user_email.as_deref() {
        lines.push(format!(
            "> <font color=\"comment\">👤 用户：</font>{}",
            truncate(email, 256)
        ));
    } else if let Some(uid) = ctx.user_id.as_deref() {
        lines.push(format!(
            "> <font color=\"comment\">🆔 ID：</font>{}",
            truncate(uid, 64)
        ));
    }

    if ctx.device_identifier.is_some() || ctx.device_name.is_some() || ctx.device_type.is_some() {
        let name = ctx
            .device_name
            .as_deref()
            .map(|s| truncate(s, 128))
            .unwrap_or_else(|| "-".to_string());
        let dtype = ctx
            .device_type
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        lines.push(format!(
            "> <font color=\"comment\">📱 设备：</font>{} (Type: {})",
            name, dtype
        ));
    }

    if let Some(cipher_id) = ctx.cipher_id.as_deref() {
        lines.push(format!(
            "> <font color=\"comment\">🔑 Cipher：</font>{}",
            truncate(cipher_id, 64)
        ));
    }

    if let Some(send_id) = ctx.send_id.as_deref() {
        lines.push(format!(
            "> <font color=\"comment\">📦 Send：</font>{}",
            truncate(send_id, 64)
        ));
    }

    if let Some(detail) = ctx.detail.as_deref() {
        lines.push(format!(
            "> <font color=\"comment\">📝 详情：</font>{}",
            truncate(detail, 512)
        ));
    }

    if let Some(ip) = ctx.meta.ip.as_deref() {
        let geo_str = ctx
            .meta
            .geo
            .as_ref()
            .map(|g| g.to_string())
            .unwrap_or_else(|| "".to_string());
        let loc_info = if geo_str.is_empty() {
            ip.to_string()
        } else {
            format!("{} ({})", ip, geo_str)
        };
        lines.push(format!(
            "> <font color=\"comment\">🌐 网络：</font>{}",
            truncate(&loc_info, 128)
        ));
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

pub fn format_html(notification: &super::super::types::Notification) -> String {
    let event = match notification.event {
        Some(e) => e,
        None => return String::new(),
    };
    let ctx = match &notification.context {
        Some(ctx) => ctx,
        None => return format!("<b>{} Warden Worker 通知</b>\n操作：{}", event.emoji(), escape_html(event.title())),
    };

    let now = format_timestamp();
    let mut lines = Vec::new();
    lines.push(format!("<b>{} Warden Worker 通知</b>", event.emoji()));
    lines.push(format!("🕒 时间：{}", escape_html(&now)));
    lines.push(format!("🛠️ 操作：{}", escape_html(event.title())));

    if let Some(email) = ctx.user_email.as_deref() {
        lines.push(format!("👤 用户：{}", escape_html(&truncate(email, 256))));
    } else if let Some(uid) = ctx.user_id.as_deref() {
        lines.push(format!("🆔 ID：{}", escape_html(&truncate(uid, 64))));
    }

    if ctx.device_identifier.is_some() || ctx.device_name.is_some() || ctx.device_type.is_some() {
        let name = ctx
            .device_name
            .as_deref()
            .map(|s| truncate(s, 128))
            .unwrap_or_else(|| "-".to_string());
        let dtype = ctx
            .device_type
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        lines.push(format!("📱 设备：{} (Type: {})", escape_html(&name), escape_html(&dtype)));
    }

    if let Some(cipher_id) = ctx.cipher_id.as_deref() {
        lines.push(format!("🔑 Cipher：{}", escape_html(&truncate(cipher_id, 64))));
    }

    if let Some(send_id) = ctx.send_id.as_deref() {
        lines.push(format!("📦 Send：{}", escape_html(&truncate(send_id, 64))));
    }

    if let Some(detail) = ctx.detail.as_deref() {
        lines.push(format!("📝 详情：{}", escape_html(&truncate(detail, 512))));
    }

    if let Some(ip) = ctx.meta.ip.as_deref() {
        let geo_str = ctx
            .meta
            .geo
            .as_ref()
            .map(|g| g.to_string())
            .unwrap_or_else(|| "".to_string());
        let loc_info = if geo_str.is_empty() {
            ip.to_string()
        } else {
            format!("{} ({})", ip, geo_str)
        };
        lines.push(format!("🌐 网络：{}", escape_html(&truncate(&loc_info, 128))));
    }

    if let Some(ua) = ctx.meta.user_agent.as_deref() {
        let new_ua_tag = if ctx.is_new_ua {
            "<b>[新设备]</b> "
        } else {
            ""
        };
        lines.push(format!(
            "💻 UA：{}{}",
            new_ua_tag,
            escape_html(&truncate(ua, 512))
        ));
    }

    truncate(&lines.join("\n"), 4000)
}
