use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, header, request::Parts},
};
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::api::AppState;
use crate::error::AppError;
use serde_json::Value;
use worker::D1Database;

pub(crate) fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteClaims {
    pub nbf: usize,
    pub exp: usize,
    pub iss: String,
    pub sub: String,
    pub email: String,
    pub org_id: String,
    pub member_id: String,
    pub invited_by_email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterVerifyClaims {
    pub sub: String,
    pub name: Option<String>,
    pub exp: usize,
    pub nbf: usize,
    pub iss: String,
    pub jti: String,
    pub verified: bool,
}

/// Access-token contract used by Vaultwarden's organization Public API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgApiKeyClaims {
    pub nbf: usize,
    pub exp: usize,
    pub iss: String,
    pub sub: String,
    pub client_id: String,
    pub client_sub: String,
    pub scope: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyAccessInviteClaims {
    pub nbf: usize,
    pub exp: usize,
    pub iss: String,
    pub sub: String,
    pub email: String,
    pub emer_id: String,
    pub grantor_name: String,
    pub grantor_email: String,
}

/// Returns the edge-authenticated client address used for security decisions.
///
/// Cloudflare Workers do not expose a peer socket address, so production
/// requests use the `CF-Connecting-IP` value injected by Cloudflare. The
/// forwarded-header fallback keeps local Worker development usable.
pub(crate) fn client_ip_from_headers(headers: &HeaderMap) -> String {
    let parse_ip = |value: &str| {
        value
            .trim()
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| ip.to_canonical().to_string())
    };

    if let Some(value) = headers
        .get("cf-connecting-ip")
        .and_then(|value| value.to_str().ok())
    {
        return parse_ip(value).unwrap_or_else(|| "0.0.0.0".to_string());
    }

    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(parse_ip)
        .unwrap_or_else(|| "0.0.0.0".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub nbf: usize,
    pub iss: String,

    pub premium: bool,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub amr: Vec<String>,

    // 对齐 Vaultwarden LoginJwtClaims：security stamp 字段名为 sstamp
    pub sstamp: String,
    pub device: Option<String>,
    pub devicetype: Option<String>,
    pub client_id: Option<String>,
    pub scope: Option<Vec<String>>,
    // 设备级 refresh token（Vaultwarden RefreshJwtClaims.token）：设备删除/登出后刷新立即失效
    pub token: Option<String>,
}

impl FromRequestParts<Arc<AppState>> for Claims {
    type Rejection = AppError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|auth_header| auth_header.to_str().ok())
            .and_then(|auth_value| auth_value.strip_prefix("Bearer ").map(str::to_owned))
            .or_else(|| {
                let raw = parts.headers.get(header::COOKIE)?.to_str().ok()?;
                for part in raw.split(';') {
                    let part = part.trim();
                    if let Some((k, v)) = part.split_once('=')
                        && k.trim() == "bw_access_token"
                    {
                        return Some(v.trim().to_string());
                    }
                }
                None
            });

        let result = match token {
            Some(token) => {
                let decoding_key = DecodingKey::from_secret(state.jwt_keys.access_secret.as_ref());
                decode::<Claims>(&token, &decoding_key, &Validation::default())
                    .map(|td| td.claims)
                    .map_err(|_| AppError::Unauthorized("Invalid token".to_string()))
            }
            None => Err(AppError::Unauthorized(
                "Missing or invalid token".to_string(),
            )),
        };

        std::future::ready(result)
    }
}

impl Claims {
    pub async fn verify_security_stamp(&self, db: &D1Database) -> Result<(), AppError> {
        let token_stamp = &self.sstamp;

        let user_val: Option<Value> = db
            .prepare("SELECT security_stamp FROM users WHERE id = ?1")
            .bind(&[self.sub.clone().into()])
            .map_err(|_| AppError::Database)?
            .first(None)
            .await
            .map_err(|_| AppError::Database)?;

        let Some(user_val) = user_val else {
            return Err(AppError::Unauthorized("User not found".to_string()));
        };

        let db_stamp = user_val
            .get("security_stamp")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        if db_stamp != token_stamp {
            return Err(AppError::Unauthorized("Invalid security stamp".to_string()));
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BasicJwtClaims {
    pub nbf: usize,
    pub exp: usize,
    pub iss: String,
    pub sub: String,
}

pub fn decode_delete(token: &str, jwt_secret: &str) -> Result<BasicJwtClaims, AppError> {
    let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());
    decode::<BasicJwtClaims>(token, &decoding_key, &Validation::default())
        .map(|d| d.claims)
        .map_err(|_| AppError::Unauthorized("Invalid delete token".to_string()))
}

#[cfg(test)]
mod tests {
    use super::{client_ip_from_headers, normalize_email};
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn email_normalization_trims_and_lowercases() {
        assert_eq!(
            normalize_email("  User.Name+Tag@Example.COM \r\n"),
            "user.name+tag@example.com"
        );
    }

    #[test]
    fn cloudflare_client_ip_takes_precedence_and_is_validated() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.10"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.20"));
        assert_eq!(client_ip_from_headers(&headers), "203.0.113.10");

        headers.insert("cf-connecting-ip", HeaderValue::from_static("not-an-ip"));
        assert_eq!(client_ip_from_headers(&headers), "0.0.0.0");
    }
}
