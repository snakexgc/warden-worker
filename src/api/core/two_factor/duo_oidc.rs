use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha512_256};
use url::Url;
use uuid::Uuid;
use worker::{D1Database, Env, Fetch, Method, Request, RequestInit, wasm_bindgen::JsValue};

use crate::{db::models::two_factor_duo_context::TwoFactorDuoContext, error::AppError};

use super::duo;

const DUO_REDIRECT_LOCATION: &str = "duo-redirect-connector.html";
const JWT_VALIDITY_SECONDS: i64 = 300;
const CONTEXT_VALIDITY_SECONDS: i64 = 300;
const DUO_RESPONSE_SIGNATURE_ALGORITHM: Algorithm = Algorithm::HS512;
const JWT_SIGNATURE_ALGORITHM: Algorithm = Algorithm::HS512;

#[derive(Debug, Serialize)]
struct ClientAssertion {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    jti: String,
    iat: i64,
}

#[derive(Debug, Serialize)]
struct AuthorizationRequest {
    response_type: &'static str,
    scope: &'static str,
    exp: i64,
    client_id: String,
    redirect_uri: String,
    state: String,
    duo_uname: String,
    iss: String,
    aud: String,
    nonce: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum HealthCheckResponse {
    Ok {
        stat: String,
    },
    Failed {
        message: String,
        message_detail: String,
    },
}

#[derive(Debug, Deserialize)]
struct IdTokenResponse {
    id_token: String,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    preferred_username: String,
    nonce: String,
}

struct DuoClient {
    client_id: String,
    client_secret: String,
    api_host: String,
    redirect_uri: String,
}

impl DuoClient {
    fn new(
        client_id: String,
        client_secret: String,
        api_host: String,
        redirect_uri: String,
    ) -> Result<Self, AppError> {
        if api_host.is_empty()
            || api_host.contains('/')
            || api_host.contains(':')
            || !api_host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        {
            return Err(AppError::BadRequest("Invalid Duo API hostname".to_string()));
        }
        Ok(Self {
            client_id,
            client_secret,
            api_host,
            redirect_uri,
        })
    }

    fn new_client_assertion(&self, url: &str) -> ClientAssertion {
        let now = Utc::now().timestamp();
        ClientAssertion {
            iss: self.client_id.clone(),
            sub: self.client_id.clone(),
            aud: url.to_string(),
            exp: now + JWT_VALIDITY_SECONDS,
            jti: random_state(),
            iat: now,
        }
    }

    fn encode_jwt<T: Serialize>(&self, claims: &T) -> Result<String, AppError> {
        jsonwebtoken::encode(
            &Header::new(JWT_SIGNATURE_ALGORITHM),
            claims,
            &EncodingKey::from_secret(self.client_secret.as_bytes()),
        )
        .map_err(AppError::JsonWebToken)
    }

    async fn health_check(&self) -> Result<(), AppError> {
        let url = format!("https://{}/oauth/v1/health_check", self.api_host);
        let assertion = self.encode_jwt(&self.new_client_assertion(&url))?;
        let response: HealthCheckResponse = post_form(
            &url,
            &[
                ("client_assertion", assertion.as_str()),
                ("client_id", self.client_id.as_str()),
            ],
        )
        .await?;
        match response {
            HealthCheckResponse::Ok { stat } if stat == "OK" => Ok(()),
            HealthCheckResponse::Ok { stat } => Err(AppError::BadRequest(format!(
                "Duo health check returned status {stat}"
            ))),
            HealthCheckResponse::Failed {
                message,
                message_detail,
            } => Err(AppError::BadRequest(format!(
                "Duo health check failed: {message}: {message_detail}"
            ))),
        }
    }

    fn authorization_url(
        &self,
        username: &str,
        state: String,
        nonce: String,
    ) -> Result<String, AppError> {
        let now = Utc::now().timestamp();
        let request = AuthorizationRequest {
            response_type: "code",
            scope: "openid",
            exp: now + JWT_VALIDITY_SECONDS,
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            state,
            duo_uname: username.to_string(),
            iss: self.client_id.clone(),
            aud: format!("https://{}", self.api_host),
            nonce,
        };
        let request_jwt = self.encode_jwt(&request)?;
        let mut url = Url::parse(&format!("https://{}/oauth/v1/authorize", self.api_host))
            .map_err(|_| AppError::BadRequest("Invalid Duo API hostname".to_string()))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("request", &request_jwt);
        Ok(url.to_string())
    }

    async fn exchange_code(&self, code: &str, username: &str, nonce: &str) -> Result<(), AppError> {
        if code.is_empty() {
            return Err(AppError::BadRequest(
                "Empty Duo authorization code".to_string(),
            ));
        }
        let token_url = format!("https://{}/oauth/v1/token", self.api_host);
        let assertion = self.encode_jwt(&self.new_client_assertion(&token_url))?;
        let response: IdTokenResponse = post_form(
            &token_url,
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &self.redirect_uri),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", &assertion),
            ],
        )
        .await?;

        let mut validation = Validation::new(DUO_RESPONSE_SIGNATURE_ALGORITHM);
        validation.set_required_spec_claims(&["exp", "aud", "iss"]);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&[token_url.as_str()]);
        let claims = jsonwebtoken::decode::<IdTokenClaims>(
            &response.id_token,
            &DecodingKey::from_secret(self.client_secret.as_bytes()),
            &validation,
        )?
        .claims;
        if !constant_time_eq::constant_time_eq(nonce.as_bytes(), claims.nonce.as_bytes())
            || !constant_time_eq::constant_time_eq(
                username.as_bytes(),
                claims.preferred_username.as_bytes(),
            )
        {
            return Err(AppError::BadRequest(
                "Error validating Duo authorization".to_string(),
            ));
        }
        Ok(())
    }
}

async fn post_form<T: DeserializeOwned>(url: &str, fields: &[(&str, &str)]) -> Result<T, AppError> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().copied())
        .finish();
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(JsValue::from_str(&body)));
    let mut request = Request::new_with_init(url, &init)?;
    request
        .headers_mut()?
        .set("content-type", "application/x-www-form-urlencoded")?;
    let mut response = Fetch::Request(request).send().await?;
    if !(200..300).contains(&response.status_code()) {
        return Err(AppError::BadRequest(format!(
            "Duo request failed with status {}",
            response.status_code()
        )));
    }
    response.json().await.map_err(AppError::Worker)
}

fn random_state() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

fn callback_url(env: &Env, client_name: &str) -> Result<String, AppError> {
    let domain = env
        .secret("DOMAIN")
        .ok()
        .map(|value| value.to_string())
        .or_else(|| env.var("DOMAIN").ok().map(|value| value.to_string()))
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| AppError::BadRequest("DOMAIN is required for Duo OIDC".to_string()))?;
    let mut callback = Url::parse(&format!("{}/", domain.trim_end_matches('/')))
        .and_then(|base| base.join(DUO_REDIRECT_LOCATION))
        .map_err(|_| AppError::BadRequest("Invalid DOMAIN for Duo OIDC".to_string()))?;
    callback
        .query_pairs_mut()
        .append_pair("client", client_name);
    Ok(callback.to_string())
}

pub fn is_configured(env: &Env) -> bool {
    callback_url(env, "web").is_ok()
}

fn bound_nonce(nonce: &str, device_identifier: &str) -> String {
    hex::encode(Sha512_256::digest(
        format!("{nonce}{device_identifier}").as_bytes(),
    ))
}

pub async fn get_duo_auth_url(
    email: &str,
    user_id: &str,
    client_id: &str,
    device_identifier: &str,
    db: &D1Database,
    env: &Env,
) -> Result<String, AppError> {
    let data = duo::configured_duo_data(db, env, user_id).await?;
    let callback = callback_url(env, client_id)?;
    let client = DuoClient::new(data.ik, data.sk, data.host, callback)?;
    client.health_check().await?;

    let state = random_state();
    let nonce = random_state();
    let nonce_hash = bound_nonce(&nonce, device_identifier);
    TwoFactorDuoContext::save(db, &state, email, &nonce, CONTEXT_VALIDITY_SECONDS).await?;
    client.authorization_url(email, state, nonce_hash)
}

pub async fn validate_duo_login(
    email: &str,
    user_id: &str,
    token: &str,
    client_id: &str,
    device_identifier: &str,
    db: &D1Database,
    env: &Env,
) -> Result<(), AppError> {
    let (code, state) = token
        .split_once('|')
        .ok_or_else(|| AppError::BadRequest("Invalid Duo response".to_string()))?;
    if code.is_empty() || state.is_empty() || state.contains('|') {
        return Err(AppError::BadRequest("Invalid Duo response".to_string()));
    }
    let context = TwoFactorDuoContext::take(db, state)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired Duo state".to_string()))?;
    if !constant_time_eq::constant_time_eq(email.as_bytes(), context.user_email.as_bytes())
        || !constant_time_eq::constant_time_eq(state.as_bytes(), context.state.as_bytes())
        || context.exp <= Utc::now().timestamp()
    {
        return Err(AppError::BadRequest(
            "Error validating Duo authentication".to_string(),
        ));
    }

    let data = duo::configured_duo_data(db, env, user_id).await?;
    let callback = callback_url(env, client_id)?;
    let client = DuoClient::new(data.ik, data.sk, data.host, callback)?;
    client.health_check().await?;
    client
        .exchange_code(code, email, &bound_nonce(&context.nonce, device_identifier))
        .await
}

pub async fn purge_duo_contexts(env: &Env) -> Result<(), AppError> {
    let db = crate::db::get_db(env)?;
    TwoFactorDuoContext::purge_expired(&db).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_has_upstream_compatible_length() {
        assert_eq!(random_state().len(), 64);
    }

    #[test]
    fn nonce_is_bound_to_device() {
        assert_ne!(
            bound_nonce("nonce", "device-a"),
            bound_nonce("nonce", "device-b")
        );
        assert_eq!(bound_nonce("nonce", "device-a").len(), 64);
    }
}
