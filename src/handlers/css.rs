use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::Response,
};
use std::sync::Arc;

use crate::router::AppState;

const DEFAULT_BASE_CSS: &str = r#"/* ============================================
     Vaultwarden 自定义登录界面样式
     功能：只显示邮箱、记住邮箱、登录、注册
     ============================================ */

/* --------------------------------------------
     1. 隐藏所有额外的登录方式按钮
     -------------------------------------------- */

/* 隐藏 \"Use single sign-on\" 按钮 */
.vw-sso-login {
    display: none !important;
}

/* 隐藏 \"Other\" 登录方式按钮 */
.vw-other-login {
    display: none !important;
}

/* 隐藏 \"or\" 分隔文本 */
.vw-or-text {
    display: none !important;
}

/* --------------------------------------------
     2. 隐藏其他可能的干扰元素
     -------------------------------------------- */

/* 隐藏 SSO 专用邮箱输入（如果存在） */
.vw-email-sso {
    display: none !important;
}

/* 隐藏水平分隔线 */
app-login form hr,
app-login form .tw-border-t {
    display: none !important;
}

/* --------------------------------------------
     3. 确保主要登录表单元素正常显示
     -------------------------------------------- */

/* 确保邮箱输入框显示 */
app-login form input[type=\"email\"],
app-login form input[name=\"email\"],
app-login form input[formcontrolname=\"email\"],
app-login form input[inputmode=\"email\"] {
    display: block !important;
}

/* 确保密码输入框显示 */
app-login form input[type=\"password\"],
app-login form input[name=\"masterPassword\"],
app-login form input[formcontrolname=\"masterPassword\"] {
    display: block !important;
}

/* 确保 \"Remember email\" 复选框显示 */
app-login form input[type=\"checkbox\"][name=\"rememberEmail\"],
app-login form input[type=\"checkbox\"][formcontrolname=\"rememberEmail\"] {
    display: inline-block !important;
}

/* 确保登录按钮显示 */
app-login form button[type=\"submit\"][buttontype=\"primary\"] {
    display: inline-flex !important;
}

/* 确保注册链接显示 */
app-login form a[routerlink=\"/signup\"],
app-login form a[href*=\"/signup\"] {
    display: inline-flex !important;
}

/* --------------------------------------------
     4. 登录表单布局优化
     -------------------------------------------- */

/* 简化登录表单容器 */
app-login form {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

/* 确保表单分组正确显示 */
app-login form .form-group,
app-login form bit-form-field {
    display: block !important;
}

/* --------------------------------------------
     5. 与 Vaultwarden 静态模板对齐的固定隐藏项
     -------------------------------------------- */

/* 隐藏订阅页入口 */
bit-nav-item[route="settings/subscription"] {
    display: none !important;
}

/* 隐藏 Sponsored Families 链接 */
a[href$="/settings/sponsored-families"] {
    display: none !important;
}

/* 隐藏组织设置中的 Two-Factor 菜单 */
bit-nav-item[route="settings/two-factor"],
a[href$="/settings/two-factor"] {
    display: none !important;
}

/* 隐藏组织套餐区域 */
app-organization-plans > form > bit-section:nth-child(2) {
    display: none !important;
}

/* 隐藏 Collection Management Form */
app-org-account form.ng-untouched:nth-child(5) {
    display: none !important;
}

/* 隐藏组织报表中的 Member Access 卡片 */
app-org-reports-home > app-report-list > div.tw-inline-grid > div:nth-child(6) {
    display: none !important;
}

/* 隐藏两步登录页中的 Device Verification 表单 */
app-security > app-two-factor-setup > form {
    display: none !important;
}

/* 隐藏不支持的 Custom Role 选项 */
bit-dialog div.tw-ml-4:has(bit-form-control input),
bit-dialog div.tw-col-span-4:has(input[formcontrolname*="access"], input[formcontrolname*="manage"]) {
    display: none !important;
}

/* 隐藏用户设置页中的 Device Login Protection 按钮 */
app-user-layout app-danger-zone button:nth-child(1) {
    display: none !important;
}

/* 隐藏用户设置中的 Log in with passkey 设置 */
app-user-layout app-password-settings app-webauthn-login-settings {
    display: none !important;
}

/* 侧边栏折叠图标改为 Vaultwarden 图标 */
bit-nav-logo bit-nav-item a:before {
    content: "";
    background-image: url("../images/icon-white.svg");
    background-repeat: no-repeat;
    background-position: center center;
    height: 32px;
    display: block;
}

/* 隐藏默认 shield 图标 */
bit-nav-logo bit-nav-item .bwi-shield {
    display: none !important;
}
"#;

fn parse_bool(input: &str, default: bool) -> bool {
    match input.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default,
    }
}

fn env_bool(env: &worker::Env, key: &str, default: bool) -> bool {
    env.var(key)
        .ok()
        .map(|v| parse_bool(&v.to_string(), default))
        .unwrap_or(default)
}

fn env_text(env: &worker::Env, key: &str) -> Option<String> {
    if let Ok(secret) = env.secret(key) {
        let value = secret.to_string();
        if !value.trim().is_empty() {
            return Some(value);
        }
    }

    env.var(key).ok().map(|v| v.to_string()).filter(|v| !v.trim().is_empty())
}

fn add_hide_rule(css: &mut String, comment: &str, selectors: &str) {
    css.push_str("\n/* ");
    css.push_str(comment);
    css.push_str(" */\n");
    css.push_str(selectors);
    css.push_str(" {\n  display: none !important;\n}\n");
}

#[worker::send]
pub async fn vaultwarden_css(State(state): State<Arc<AppState>>) -> Response {
    let env = &state.env;

    let signup_disabled = env_bool(env, "VW_CSS_SIGNUP_DISABLED", false);
    let sends_allowed = env_bool(env, "VW_CSS_SENDS_ALLOWED", true);
    let password_hints_allowed = env_bool(env, "VW_CSS_PASSWORD_HINTS_ALLOWED", true);
    let sso_enabled = env_bool(env, "VW_CSS_SSO_ENABLED", false);
    let sso_only = env_bool(env, "VW_CSS_SSO_ONLY", false);
    let passkey_2fa_supported = env_bool(env, "VW_CSS_PASSKEY_2FA_SUPPORTED", false);
    let remember_2fa_disabled = env_bool(env, "VW_CSS_REMEMBER_2FA_DISABLED", false);
    let mail_2fa_enabled = env_bool(env, "VW_CSS_MAIL_2FA_ENABLED", true);
    let mail_enabled = env_bool(env, "VW_CSS_MAIL_ENABLED", true);
    let yubico_enabled = env_bool(env, "VW_CSS_YUBICO_ENABLED", false);
    let emergency_access_allowed = env_bool(env, "VW_CSS_EMERGENCY_ACCESS_ALLOWED", true);
    let load_user_css = env_bool(env, "VW_CSS_LOAD_USER_CSS", true);

    let mut css = String::from(DEFAULT_BASE_CSS);

    css.push_str("\n/* ==== Dynamic rules generated by worker ==== */\n");

    if !sso_enabled {
        add_hide_rule(&mut css, "Hide SSO login when disabled", ".vw-sso-login, .vw-email-sso");
    } else {
        add_hide_rule(
            &mut css,
            "Hide default email/continue flow when SSO enabled",
            ".vw-email-continue, .vw-continue-login",
        );
    }

    if !sso_enabled || sso_only {
        add_hide_rule(
            &mut css,
            "Hide alternative login options when SSO-only",
            ".vw-or-text, .vw-other-login",
        );
    }

    if signup_disabled {
        add_hide_rule(
            &mut css,
            "Hide signup entry when signup is disabled",
            "a[routerlink=\"/signup\"], a[href*=\"/signup\"]",
        );
    }

    if !sends_allowed {
        add_hide_rule(
            &mut css,
            "Hide Sends menu when sends are disabled",
            "bit-nav-item[route=\"sends\"]",
        );
    }

    if !password_hints_allowed {
        add_hide_rule(
            &mut css,
            "Hide password hint entries when disabled",
            "a[routerlink=\"/hint\"], .vw-password-hint",
        );
    }

    if !passkey_2fa_supported {
        add_hide_rule(
            &mut css,
            "Hide passkey 2FA entries when unsupported",
            ".providers-2fa-7, .vw-passkey-login",
        );
    }

    if remember_2fa_disabled {
        add_hide_rule(
            &mut css,
            "Hide remember 2FA checkbox",
            "app-two-factor-auth > form > bit-form-control",
        );
    }

    if !mail_enabled || !mail_2fa_enabled {
        add_hide_rule(
            &mut css,
            "Hide Email 2FA entries when mail is disabled",
            ".providers-2fa-1",
        );
    }

    if !yubico_enabled {
        add_hide_rule(
            &mut css,
            "Hide YubiKey OTP 2FA entries when disabled",
            ".providers-2fa-3",
        );
    }

    if !emergency_access_allowed {
        add_hide_rule(
            &mut css,
            "Hide emergency access menu when disabled",
            "bit-nav-item[route=\"settings/emergency-access\"]",
        );
    }

    if load_user_css {
        if let Some(user_css) = env_text(env, "VW_CSS_USER") {
            css.push_str("\n/* ==== User custom CSS (VW_CSS_USER) ==== */\n");
            css.push_str(&user_css);
            css.push('\n');
        }
    }

    let mut response = Response::new(axum::body::Body::from(css));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/css; charset=utf-8"));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=300"));

    response
}
