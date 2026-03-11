#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord)]
pub enum NotifyLevel {
    #[default]
    Info = 0,
    Warning = 1,
    Error = 2,
}

impl NotifyLevel {
    #[allow(dead_code)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(NotifyLevel::Info),
            "warning" | "warn" => Some(NotifyLevel::Warning),
            "error" => Some(NotifyLevel::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelType {
    WeWork,
    Telegram,
}

impl ChannelType {
    pub fn as_str(self) -> &'static str {
        match self {
            ChannelType::WeWork => "wework",
            ChannelType::Telegram => "telegram",
        }
    }
}

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
    TwoFactorRecoveryCodeView,
    TwoFactorRecover,
    TokenRefresh,
    Sync,
    AuthRequest,
    AuthResponse,
    WebAuthnCredentialCreate,
    WebAuthnCredentialDelete,
    WebAuthnCredentialUpdate,
    WebAuthnLogin,
}

impl NotifyEvent {
    pub fn key(self) -> &'static str {
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
            NotifyEvent::TwoFactorRecoveryCodeView => "2fa_recovery_code_view",
            NotifyEvent::TwoFactorRecover => "2fa_recover",
            NotifyEvent::TokenRefresh => "token_refresh",
            NotifyEvent::Sync => "sync",
            NotifyEvent::AuthRequest => "auth_request",
            NotifyEvent::AuthResponse => "auth_response",
            NotifyEvent::WebAuthnCredentialCreate => "webauthn_credential_create",
            NotifyEvent::WebAuthnCredentialDelete => "webauthn_credential_delete",
            NotifyEvent::WebAuthnCredentialUpdate => "webauthn_credential_update",
            NotifyEvent::WebAuthnLogin => "webauthn_login",
        }
    }

    pub fn from_key(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "login" => Some(NotifyEvent::Login),
            "login_failed" | "login_fail" | "loginfailed" => Some(NotifyEvent::LoginFailed),
            "password_hint" | "password-hint" => Some(NotifyEvent::PasswordHint),
            "password" | "password_change" | "passwordchange" => Some(NotifyEvent::PasswordChange),
            "email" | "email_change" | "emailchange" => Some(NotifyEvent::EmailChange),
            "kdf" | "kdf_change" | "kdfchange" => Some(NotifyEvent::KdfChange),
            "cipher_create" | "cipher.add" | "cipher_add" | "create_cipher" => Some(NotifyEvent::CipherCreate),
            "cipher_update" | "cipher.update" | "cipher_edit" | "update_cipher" => Some(NotifyEvent::CipherUpdate),
            "cipher_delete" | "cipher.del" | "delete_cipher" => Some(NotifyEvent::CipherDelete),
            "import" => Some(NotifyEvent::Import),
            "send_create" | "send.create" | "send_add" => Some(NotifyEvent::SendCreate),
            "send_delete" | "send.del" | "send_remove" => Some(NotifyEvent::SendDelete),
            "2fa_enable" | "two_factor_enable" | "twofactor_enable" => Some(NotifyEvent::TwoFactorEnable),
            "2fa_disable" | "two_factor_disable" | "twofactor_disable" => Some(NotifyEvent::TwoFactorDisable),
            "2fa_recovery_code_view" | "two_factor_recovery_code_view" => Some(NotifyEvent::TwoFactorRecoveryCodeView),
            "2fa_recover" | "two_factor_recover" | "twofactor_recover" => Some(NotifyEvent::TwoFactorRecover),
            "token_refresh" | "unlock" => Some(NotifyEvent::TokenRefresh),
            "sync" => Some(NotifyEvent::Sync),
            "auth_request" | "authrequest" => Some(NotifyEvent::AuthRequest),
            "auth_response" | "authresponse" => Some(NotifyEvent::AuthResponse),
            "webauthn_credential_create" | "webauthn_create" | "passkey_create" => Some(NotifyEvent::WebAuthnCredentialCreate),
            "webauthn_credential_delete" | "webauthn_delete" | "passkey_delete" => Some(NotifyEvent::WebAuthnCredentialDelete),
            "webauthn_credential_update" | "webauthn_update" | "passkey_update" => Some(NotifyEvent::WebAuthnCredentialUpdate),
            "webauthn_login" | "passkey_login" => Some(NotifyEvent::WebAuthnLogin),
            _ => None,
        }
    }

    pub fn title(self) -> &'static str {
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
            NotifyEvent::TwoFactorRecoveryCodeView => "查看恢复码",
            NotifyEvent::TwoFactorRecover => "恢复账户",
            NotifyEvent::TokenRefresh => "刷新令牌",
            NotifyEvent::Sync => "同步数据",
            NotifyEvent::AuthRequest => "设备登录请求",
            NotifyEvent::AuthResponse => "设备登录响应",
            NotifyEvent::WebAuthnCredentialCreate => "创建 Passkey 凭证",
            NotifyEvent::WebAuthnCredentialDelete => "删除 Passkey 凭证",
            NotifyEvent::WebAuthnCredentialUpdate => "更新 Passkey 凭证",
            NotifyEvent::WebAuthnLogin => "Passkey 登录",
        }
    }

    pub fn emoji(self) -> &'static str {
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
            NotifyEvent::TwoFactorRecoveryCodeView => "👀",
            NotifyEvent::TwoFactorRecover => "🔓",
            NotifyEvent::TokenRefresh => "🔄",
            NotifyEvent::Sync => "🔄",
            NotifyEvent::AuthRequest => "📱",
            NotifyEvent::AuthResponse => "✅",
            NotifyEvent::WebAuthnCredentialCreate => "🔑",
            NotifyEvent::WebAuthnCredentialDelete => "🗑️",
            NotifyEvent::WebAuthnCredentialUpdate => "📝",
            NotifyEvent::WebAuthnLogin => "🔐",
        }
    }

    pub fn level(self) -> NotifyLevel {
        match self {
            NotifyEvent::TwoFactorRecover => NotifyLevel::Error,

            NotifyEvent::LoginFailed => NotifyLevel::Warning,
            NotifyEvent::PasswordHint => NotifyLevel::Warning,
            NotifyEvent::PasswordChange => NotifyLevel::Warning,
            NotifyEvent::EmailChange => NotifyLevel::Warning,
            NotifyEvent::KdfChange => NotifyLevel::Warning,
            NotifyEvent::CipherDelete => NotifyLevel::Warning,
            NotifyEvent::SendDelete => NotifyLevel::Warning,
            NotifyEvent::TwoFactorDisable => NotifyLevel::Warning,
            NotifyEvent::TwoFactorRecoveryCodeView => NotifyLevel::Warning,
            NotifyEvent::WebAuthnCredentialDelete => NotifyLevel::Warning,

            NotifyEvent::Login => NotifyLevel::Info,
            NotifyEvent::CipherCreate => NotifyLevel::Info,
            NotifyEvent::CipherUpdate => NotifyLevel::Info,
            NotifyEvent::Import => NotifyLevel::Info,
            NotifyEvent::SendCreate => NotifyLevel::Info,
            NotifyEvent::TwoFactorEnable => NotifyLevel::Info,
            NotifyEvent::TokenRefresh => NotifyLevel::Info,
            NotifyEvent::Sync => NotifyLevel::Info,
            NotifyEvent::AuthRequest => NotifyLevel::Info,
            NotifyEvent::AuthResponse => NotifyLevel::Info,
            NotifyEvent::WebAuthnCredentialCreate => NotifyLevel::Info,
            NotifyEvent::WebAuthnCredentialUpdate => NotifyLevel::Info,
            NotifyEvent::WebAuthnLogin => NotifyLevel::Info,
        }
    }

    pub fn color(self) -> &'static str {
        match self.level() {
            NotifyLevel::Error => "error",
            NotifyLevel::Warning => "warning",
            NotifyLevel::Info => "info",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeType {
    TwoFactorEmail,
    TwoFactorLogin,
}

impl CodeType {
    pub fn emoji(self) -> &'static str {
        match self {
            CodeType::TwoFactorEmail => "📧",
            CodeType::TwoFactorLogin => "🔐",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationKind {
    Event,
    VerificationCode,
}

#[derive(Debug, Clone)]
pub struct VerificationCodeData {
    pub email: String,
    pub code: String,
    pub code_type: CodeType,
}

#[derive(Debug, Clone, Default)]
pub struct Geo {
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
}

impl std::fmt::Display for Geo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if let Some(c) = &self.country {
            parts.push(c.as_str());
        }
        if let Some(r) = &self.region {
            parts.push(r.as_str());
        }
        if let Some(c) = &self.city {
            parts.push(c.as_str());
        }
        if parts.is_empty() {
            write!(f, "Unknown")
        } else {
            write!(f, "{}", parts.join(", "))
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RequestMeta {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub geo: Option<Geo>,
}

#[derive(Debug, Clone)]
pub struct Notification {
    pub kind: NotificationKind,
    pub event: Option<NotifyEvent>,
    pub context: Option<super::context::NotifyContext>,
    pub verification_code: Option<VerificationCodeData>,
}

impl Notification {
    pub fn event(event: NotifyEvent, context: super::context::NotifyContext) -> Self {
        Self {
            kind: NotificationKind::Event,
            event: Some(event),
            context: Some(context),
            verification_code: None,
        }
    }

    pub fn code(email: &str, code: &str, code_type: CodeType) -> Self {
        Self {
            kind: NotificationKind::VerificationCode,
            event: None,
            context: None,
            verification_code: Some(VerificationCodeData {
                email: email.to_string(),
                code: code.to_string(),
                code_type,
            }),
        }
    }
}
