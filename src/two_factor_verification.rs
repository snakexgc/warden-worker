//! Short-lived `userVerificationToken` JWTs used to authorize 2FA
//! enable/disable/send-email requests after a password or OTP check.
//!
//! Mirrors upstream vaultwarden `src/auth/two_factor.rs` (commit `acbf4901`):
//! the get-* endpoints mint a 5-minute token carrying provider-specific
//! claims plus the enabled state, and the mutating endpoints validate it
//! instead of re-sending the master password hash. Provider claim structs use
//! `deny_unknown_fields` so a token minted for one provider can never be
//! replayed against another provider's endpoint.

use chrono::{Duration, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::jwt;

/// Issuer for every 2FA user-verification token.
pub const TWO_FACTOR_VERIFY_ISSUER: &str = "warden-worker|2fa-verify";

/// Tokens are valid for five minutes, matching upstream.
const TWO_FACTOR_VERIFY_VALIDITY_SECS: i64 = 300;

#[derive(Debug, Serialize, Deserialize)]
pub struct TwoFactorVerificationClaims<T> {
    /// Not before.
    pub nbf: i64,
    /// Expiration time.
    pub exp: i64,
    /// Issuer.
    pub iss: String,
    /// Subject (user id).
    pub sub: String,
    /// Whether the provider was enabled when the token was minted.
    pub enabled: bool,
    /// Provider-specific claims.
    pub claims: T,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatorClaims {
    #[serde(rename = "authenticator_key")]
    pub key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailClaims {
    pub email: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebauthnClaims {
    #[serde(rename = "webauthn_keys")]
    pub keys: Vec<i32>,
}

fn mint<T: Serialize>(
    secret: &str,
    user_id: &str,
    enabled: bool,
    claims: T,
) -> Result<String, AppError> {
    let now = Utc::now();
    let verification_claims = TwoFactorVerificationClaims {
        nbf: now.timestamp(),
        exp: (now + Duration::seconds(TWO_FACTOR_VERIFY_VALIDITY_SECS)).timestamp(),
        iss: TWO_FACTOR_VERIFY_ISSUER.to_string(),
        sub: user_id.to_string(),
        enabled,
        claims,
    };
    jwt::encode_hs256(&verification_claims, secret)
}

fn validate<T: DeserializeOwned>(
    secret: &str,
    token: &str,
    user_id: &str,
    enabled: bool,
) -> Result<T, AppError> {
    let claims: TwoFactorVerificationClaims<T> = jwt::decode_hs256(token, secret)
        .map_err(|_| AppError::Unauthorized("Failed to decode verification token".to_string()))?;
    if claims.iss != TWO_FACTOR_VERIFY_ISSUER {
        return Err(AppError::Unauthorized(
            "Invalid verification token: Invalid issuer".to_string(),
        ));
    }
    if claims.sub != user_id {
        return Err(AppError::Unauthorized(
            "Invalid verification token: Invalid user".to_string(),
        ));
    }
    if claims.enabled != enabled {
        return Err(AppError::Unauthorized(
            "Invalid verification token: Invalid state".to_string(),
        ));
    }
    Ok(claims.claims)
}

pub fn mint_authenticator_token(
    secret: &str,
    user_id: &str,
    key: String,
    enabled: bool,
) -> Result<String, AppError> {
    mint(secret, user_id, enabled, AuthenticatorClaims { key })
}

pub fn validate_authenticator_token(
    secret: &str,
    token: &str,
    user_id: &str,
    expected_key: &str,
    expected_enabled: bool,
) -> Result<(), AppError> {
    let claims: AuthenticatorClaims = validate(secret, token, user_id, expected_enabled)?;
    if claims.key != expected_key {
        return Err(AppError::Unauthorized(
            "Invalid verification token: Invalid key".to_string(),
        ));
    }
    Ok(())
}

pub fn mint_email_token(
    secret: &str,
    user_id: &str,
    email: Option<String>,
    enabled: bool,
) -> Result<String, AppError> {
    mint(secret, user_id, enabled, EmailClaims { email })
}

/// When `expected_enabled` is true the token email must match the expected
/// address; while setting the provider up (enabled=false) the address is not
/// compared, matching upstream `validate_email`.
pub fn validate_email_token(
    secret: &str,
    token: &str,
    user_id: &str,
    expected_email: Option<&str>,
    expected_enabled: bool,
) -> Result<(), AppError> {
    let claims: EmailClaims = validate(secret, token, user_id, expected_enabled)?;
    if expected_enabled && claims.email.as_deref() != expected_email {
        return Err(AppError::Unauthorized(
            "Invalid verification token: Invalid email".to_string(),
        ));
    }
    Ok(())
}

pub fn mint_webauthn_token(
    secret: &str,
    user_id: &str,
    keys: Vec<i32>,
    enabled: bool,
) -> Result<String, AppError> {
    mint(secret, user_id, enabled, WebauthnClaims { keys })
}

pub fn validate_webauthn_token(
    secret: &str,
    token: &str,
    user_id: &str,
    expected_keys: &[i32],
    expected_enabled: bool,
) -> Result<(), AppError> {
    let claims: WebauthnClaims = validate(secret, token, user_id, expected_enabled)?;
    if claims.keys != expected_keys {
        return Err(AppError::Unauthorized(
            "Invalid verification token: Invalid keys".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, from_value, to_value};

    const SECRET: &str = "test-access-secret";
    const USER_ID: &str = "4ff0f0a4-0aa4-4c1d-9d43-1f2bd4d5e8b1";

    #[test]
    fn claims_only_parse_as_their_own_provider() {
        fn token<T: Serialize>(claims: T) -> Value {
            to_value(TwoFactorVerificationClaims {
                nbf: 0,
                exp: 0,
                iss: String::new(),
                sub: USER_ID.to_string(),
                enabled: false,
                claims,
            })
            .unwrap()
        }

        let tokens = [
            token(AuthenticatorClaims {
                key: "JBSWY3DPEHPK3PXP".to_string(),
            }),
            token(EmailClaims { email: None }),
            token(WebauthnClaims { keys: vec![1] }),
        ];
        for (issued, token) in tokens.iter().enumerate() {
            let parsed = [
                from_value::<TwoFactorVerificationClaims<AuthenticatorClaims>>(token.clone())
                    .is_ok(),
                from_value::<TwoFactorVerificationClaims<EmailClaims>>(token.clone()).is_ok(),
                from_value::<TwoFactorVerificationClaims<WebauthnClaims>>(token.clone()).is_ok(),
            ];
            for (checked, ok) in parsed.into_iter().enumerate() {
                assert_eq!(ok, issued == checked, "token {issued} parsed as {checked}");
            }
        }
    }

    #[test]
    fn authenticator_token_roundtrip_and_rejections() {
        let token =
            mint_authenticator_token(SECRET, USER_ID, "JBSWY3DPEHPK3PXP".to_string(), false)
                .unwrap();
        assert!(
            validate_authenticator_token(SECRET, &token, USER_ID, "JBSWY3DPEHPK3PXP", false)
                .is_ok()
        );
        // Wrong key, wrong enabled state and wrong user are all rejected.
        assert!(validate_authenticator_token(SECRET, &token, USER_ID, "OTHERKEY", false).is_err());
        assert!(
            validate_authenticator_token(SECRET, &token, USER_ID, "JBSWY3DPEHPK3PXP", true)
                .is_err()
        );
        assert!(
            validate_authenticator_token(SECRET, &token, "another-user", "JBSWY3DPEHPK3PXP", false)
                .is_err()
        );
        // A different signing secret fails to decode.
        assert!(
            validate_authenticator_token(
                "other-secret",
                &token,
                USER_ID,
                "JBSWY3DPEHPK3PXP",
                false
            )
            .is_err()
        );
    }

    #[test]
    fn cross_provider_tokens_are_rejected() {
        let authenticator =
            mint_authenticator_token(SECRET, USER_ID, "JBSWY3DPEHPK3PXP".to_string(), false)
                .unwrap();
        // deny_unknown_fields makes the authenticator token fail to parse as
        // email or webauthn claims.
        assert!(validate_email_token(SECRET, &authenticator, USER_ID, None, false).is_err());
        assert!(validate_webauthn_token(SECRET, &authenticator, USER_ID, &[], false).is_err());

        let email =
            mint_email_token(SECRET, USER_ID, Some("a@example.com".to_string()), false).unwrap();
        assert!(
            validate_authenticator_token(SECRET, &email, USER_ID, "a@example.com", false).is_err()
        );
        assert!(validate_webauthn_token(SECRET, &email, USER_ID, &[], false).is_err());

        let webauthn = mint_webauthn_token(SECRET, USER_ID, vec![1, 2], true).unwrap();
        assert!(validate_authenticator_token(SECRET, &webauthn, USER_ID, "1", true).is_err());
        assert!(validate_email_token(SECRET, &webauthn, USER_ID, None, true).is_err());
    }

    #[test]
    fn email_token_only_compares_address_when_enabled() {
        let token =
            mint_email_token(SECRET, USER_ID, Some("a@example.com".to_string()), true).unwrap();
        assert!(validate_email_token(SECRET, &token, USER_ID, Some("a@example.com"), true).is_ok());
        assert!(
            validate_email_token(SECRET, &token, USER_ID, Some("b@example.com"), true).is_err()
        );
        // While setting the provider up the address is not compared.
        let pending =
            mint_email_token(SECRET, USER_ID, Some("a@example.com".to_string()), false).unwrap();
        assert!(
            validate_email_token(SECRET, &pending, USER_ID, Some("b@example.com"), false).is_ok()
        );
    }

    #[test]
    fn webauthn_token_validates_against_current_key_list() {
        let token = mint_webauthn_token(SECRET, USER_ID, vec![1, 2], true).unwrap();
        assert!(validate_webauthn_token(SECRET, &token, USER_ID, &[1, 2], true).is_ok());
        assert!(validate_webauthn_token(SECRET, &token, USER_ID, &[1], true).is_err());
        assert!(validate_webauthn_token(SECRET, &token, USER_ID, &[2, 1], true).is_err());
    }

    #[test]
    fn expired_token_is_rejected() {
        // exp is now + 300s; craft an already-expired token manually.
        let now = Utc::now();
        let claims = TwoFactorVerificationClaims {
            nbf: now.timestamp() - 600,
            exp: now.timestamp() - 300,
            iss: TWO_FACTOR_VERIFY_ISSUER.to_string(),
            sub: USER_ID.to_string(),
            enabled: false,
            claims: AuthenticatorClaims {
                key: "JBSWY3DPEHPK3PXP".to_string(),
            },
        };
        let token = jwt::encode_hs256(&claims, SECRET).unwrap();
        assert!(
            validate_authenticator_token(SECRET, &token, USER_ID, "JBSWY3DPEHPK3PXP", false)
                .is_err()
        );
    }
}
