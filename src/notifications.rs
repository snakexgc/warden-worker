use constant_time_eq::constant_time_eq;
use jsonwebtoken::{DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use worker::{
    DurableObject, Env, Error, Headers, Method, Request, RequestInit, Response, Result, State,
    WebSocket, WebSocketIncomingMessage, WebSocketPair, durable_object, wasm_bindgen::JsValue,
};

use crate::auth::Claims;
use crate::background::BackgroundExecutor;

const DO_BINDING: &str = "NOTIFICATIONS_HUB";
const DO_INSTANCE_NAME: &str = "global";
const INTERNAL_AUTH_HEADER: &str = "x-internal-notify";

const RECORD_SEPARATOR: u8 = 0x1e;
const INITIAL_RESPONSE: [u8; 3] = [0x7b, 0x7d, RECORD_SEPARATOR];
const SIGNALR_MESSAGEPACK_PING: [u8; 3] = [0x02, 0x91, 0x06];
const KEEPALIVE_INTERVAL_MS: i64 = 15_000;
const MAX_ANONYMOUS_CONNECTIONS_PER_IP: usize = 25;

const UPDATE_TYPE_AUTH_REQUEST: i32 = 15;
const UPDATE_TYPE_AUTH_REQUEST_RESPONSE: i32 = 16;

const HUB_PATH: &str = "/hub";
const ANONYMOUS_HUB_PATH: &str = "/anonymous-hub";
const HUB_PATH_WITH_PREFIX: &str = "/notifications/hub";
const ANONYMOUS_HUB_PATH_WITH_PREFIX: &str = "/notifications/anonymous-hub";

const INTERNAL_AUTH_REQUEST_PATH: &str = "/internal/auth-request";
const INTERNAL_AUTH_RESPONSE_PATH: &str = "/internal/auth-response";
const INTERNAL_VAULT_UPDATE_PATH: &str = "/internal/vault-update";
const INTERNAL_CLOSE_ANONYMOUS_PATH: &str = "/internal/close-anonymous";

const TARGET_RECEIVE_MESSAGE: &str = "ReceiveMessage";
const TARGET_ANONYMOUS_AUTH_RESPONSE: &str = "AuthRequestResponseRecieved";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InitialHandshake {
    protocol: String,
    version: i32,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthEventPayload {
    user_id: String,
    auth_request_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloseAnonymousPayload {
    token: String,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum VaultPayloadKind {
    Cipher,
    Folder,
    Send,
    User,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultEventPayload {
    user_id: String,
    item_id: Option<String>,
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    collection_ids: Option<Vec<String>>,
    revision_date: String,
    update_type: i32,
    acting_device_id: Option<String>,
    kind: VaultPayloadKind,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[repr(i32)]
pub enum UpdateType {
    SyncCipherUpdate = 0,
    SyncCipherCreate = 1,
    SyncLoginDelete = 2,
    SyncFolderDelete = 3,
    SyncCiphers = 4,
    SyncVault = 5,
    SyncFolderCreate = 7,
    SyncFolderUpdate = 8,
    SyncSettings = 10,
    LogOut = 11,
    SyncSendCreate = 12,
    SyncSendUpdate = 13,
    SyncSendDelete = 14,
}

#[durable_object]
pub struct NotificationsHub {
    state: State,
    env: Env,
}

impl DurableObject for NotificationsHub {
    fn new(state: State, env: Env) -> Self {
        Self { state, env }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path_owned = req.path();
        let path = normalize_path(&path_owned);

        if req.method() == Method::Get && (path == HUB_PATH || path == HUB_PATH_WITH_PREFIX) {
            return self.handle_user_hub(&req).await;
        }

        if req.method() == Method::Get
            && (path == ANONYMOUS_HUB_PATH || path == ANONYMOUS_HUB_PATH_WITH_PREFIX)
        {
            return self.handle_anonymous_hub(&req).await;
        }

        if req.method() == Method::Post && path == INTERNAL_AUTH_REQUEST_PATH {
            if !self.is_internal_request(&req).await {
                return Response::error("Forbidden", 403);
            }
            return self.handle_internal_auth_request(&mut req).await;
        }

        if req.method() == Method::Post && path == INTERNAL_AUTH_RESPONSE_PATH {
            if !self.is_internal_request(&req).await {
                return Response::error("Forbidden", 403);
            }
            return self.handle_internal_auth_response(&mut req).await;
        }

        if req.method() == Method::Post && path == INTERNAL_VAULT_UPDATE_PATH {
            if !self.is_internal_request(&req).await {
                return Response::error("Forbidden", 403);
            }
            return self.handle_internal_vault_update(&mut req).await;
        }

        if req.method() == Method::Post && path == INTERNAL_CLOSE_ANONYMOUS_PATH {
            if !self.is_internal_request(&req).await {
                return Response::error("Forbidden", 403);
            }
            return self.handle_internal_close_anonymous(&mut req).await;
        }

        Response::error("Not found", 404)
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        match message {
            WebSocketIncomingMessage::String(text) if is_signalr_messagepack_handshake(&text) => {
                ws.send_with_bytes(INITIAL_RESPONSE)?;
            }
            WebSocketIncomingMessage::Binary(bytes) => ws.send_with_bytes(bytes)?,
            WebSocketIncomingMessage::String(_) => {}
        }
        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        if self.state.get_websockets().is_empty() {
            self.state.storage().delete_alarm().await?;
        }
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, err: Error) -> Result<()> {
        log::warn!("notifications websocket error: {err}");
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        let sockets = self.state.get_websockets();
        if sockets.is_empty() {
            self.state.storage().delete_alarm().await?;
        } else {
            for socket in sockets {
                if let Err(err) = socket.send_with_bytes(SIGNALR_MESSAGEPACK_PING) {
                    log::warn!("notifications keepalive failed: {err}");
                }
            }
            self.state
                .storage()
                .set_alarm(KEEPALIVE_INTERVAL_MS)
                .await?;
        }
        Response::empty().map(|response| response.with_status(204))
    }
}

impl NotificationsHub {
    async fn get_jwt_secret(&self) -> std::result::Result<String, Error> {
        let db = self
            .env
            .d1("vaultsql")
            .map_err(|e| Error::RustError(format!("Failed to get database: {}", e)))?;

        let result: Option<serde_json::Value> = db
            .prepare("SELECT access_secret FROM jwt_keys WHERE id = ?1")
            .bind(&["global".into()])
            .map_err(|e| Error::RustError(format!("Failed to prepare statement: {}", e)))?
            .first(None)
            .await
            .map_err(|e| Error::RustError(format!("Failed to query database: {}", e)))?;

        result
            .and_then(|row| {
                row.get("access_secret")
                    .and_then(|v| v.as_str().map(String::from))
            })
            .ok_or_else(|| Error::RustError("JWT keys not found".to_string()))
    }

    async fn handle_user_hub(&self, req: &Request) -> Result<Response> {
        let access_token = extract_access_token(req)
            .ok_or_else(|| Error::RustError("Missing access token".to_string()))?;

        let jwt_secret = self
            .get_jwt_secret()
            .await
            .map_err(|e| Error::RustError(format!("Failed to get JWT secret: {}", e)))?;

        let decoding_key = DecodingKey::from_secret(jwt_secret.as_ref());
        let token_data = decode::<Claims>(&access_token, &decoding_key, &Validation::default())
            .map_err(|_| Error::RustError("Invalid token".to_string()))?;

        let token_stamp = token_data.claims.security_stamp.as_deref().unwrap_or("");
        let db = self
            .env
            .d1("vaultsql")
            .map_err(|e| Error::RustError(format!("Failed to get database: {e}")))?;
        let stored_stamp: Option<String> = db
            .prepare("SELECT security_stamp FROM users WHERE id = ?1")
            .bind(&[token_data.claims.sub.clone().into()])
            .map_err(|e| Error::RustError(format!("Failed to bind database query: {e}")))?
            .first(Some("security_stamp"))
            .await
            .map_err(|e| Error::RustError(format!("Failed to query database: {e}")))?;
        if token_stamp.is_empty() || stored_stamp.as_deref() != Some(token_stamp) {
            return Response::error("Invalid security stamp", 401);
        }

        let tag = user_tag(&token_data.claims.sub);
        let tags = [tag.as_str()];
        self.accept_with_tags(&tags).await
    }

    async fn handle_anonymous_hub(&self, req: &Request) -> Result<Response> {
        let token = query_param(req, "token")
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| Error::RustError("Missing token".to_string()))?;

        let token_tag = anon_tag(&token);
        let ip_tag = anon_ip_tag(&client_ip(req));
        if self.state.get_websockets_with_tag(&ip_tag).len() >= MAX_ANONYMOUS_CONNECTIONS_PER_IP {
            return Response::error("Too many connections", 429);
        }

        let tags = [token_tag.as_str(), ip_tag.as_str()];
        self.accept_with_tags(&tags).await
    }

    async fn accept_with_tags(&self, tags: &[&str]) -> Result<Response> {
        let pair = WebSocketPair::new()?;
        self.state.accept_websocket_with_tags(&pair.server, tags);
        if self.state.storage().get_alarm().await?.is_none() {
            self.state
                .storage()
                .set_alarm(KEEPALIVE_INTERVAL_MS)
                .await?;
        }
        Response::from_websocket(pair.client)
    }

    async fn handle_internal_auth_request(&self, req: &mut Request) -> Result<Response> {
        let payload: AuthEventPayload = match req.json().await {
            Ok(v) => v,
            Err(_) => return Response::error("Bad request", 400),
        };

        let user_event = encode_user_update(
            UPDATE_TYPE_AUTH_REQUEST,
            &payload.auth_request_id,
            &payload.user_id,
        );
        self.broadcast_to_tag(&user_tag(&payload.user_id), &user_event);
        Response::empty().map(|resp| resp.with_status(204))
    }

    async fn handle_internal_auth_response(&self, req: &mut Request) -> Result<Response> {
        let payload: AuthEventPayload = match req.json().await {
            Ok(v) => v,
            Err(_) => return Response::error("Bad request", 400),
        };

        let user_event = encode_user_update(
            UPDATE_TYPE_AUTH_REQUEST_RESPONSE,
            &payload.auth_request_id,
            &payload.user_id,
        );
        self.broadcast_to_tag(&user_tag(&payload.user_id), &user_event);

        let anonymous_event =
            encode_anonymous_auth_response(&payload.auth_request_id, &payload.user_id);
        self.broadcast_to_tag(&anon_tag(&payload.auth_request_id), &anonymous_event);

        Response::empty().map(|resp| resp.with_status(204))
    }

    async fn handle_internal_vault_update(&self, req: &mut Request) -> Result<Response> {
        let payload: VaultEventPayload = match req.json().await {
            Ok(v) => v,
            Err(_) => return Response::error("Bad request", 400),
        };

        let event = encode_vault_update(&payload);
        self.broadcast_to_tag(&user_tag(&payload.user_id), &event);
        Response::empty().map(|resp| resp.with_status(204))
    }

    async fn handle_internal_close_anonymous(&self, req: &mut Request) -> Result<Response> {
        let payload: CloseAnonymousPayload = match req.json().await {
            Ok(v) => v,
            Err(_) => return Response::error("Bad request", 400),
        };

        self.close_tagged_websockets(&anon_tag(&payload.token), "auth-complete");
        Response::empty().map(|resp| resp.with_status(204))
    }

    fn broadcast_to_tag(&self, tag: &str, payload: &[u8]) {
        for ws in self.state.get_websockets_with_tag(tag) {
            if let Err(err) = ws.send_with_bytes(payload) {
                log::warn!("notifications send failed ({tag}): {err}");
            }
        }
    }

    fn close_tagged_websockets(&self, tag: &str, reason: &str) {
        for ws in self.state.get_websockets_with_tag(tag) {
            if let Err(err) = ws.close(Some(1000), Some(reason)) {
                log::warn!("notifications close failed ({tag}): {err}");
            }
        }
    }

    async fn is_internal_request(&self, req: &Request) -> bool {
        let provided = req
            .headers()
            .get(INTERNAL_AUTH_HEADER)
            .ok()
            .flatten()
            .unwrap_or_default();
        if provided.is_empty() {
            return false;
        }

        let expected = match self.get_jwt_secret().await {
            Ok(secret) => secret,
            Err(_) => return false,
        };
        constant_time_eq(provided.as_bytes(), expected.as_bytes())
    }
}

pub fn is_notifications_path(path: &str) -> bool {
    path == "/notifications" || path.starts_with("/notifications/")
}

pub async fn proxy_notifications_request(env: &Env, req: Request) -> Result<Response> {
    let namespace = env.durable_object(DO_BINDING)?;
    let stub = namespace.id_from_name(DO_INSTANCE_NAME)?.get_stub()?;
    stub.fetch_with_request(req).await
}

pub async fn publish_auth_request(env: &Env, user_id: &str, auth_request_id: &str) -> Result<()> {
    dispatch_internal(
        env,
        INTERNAL_AUTH_REQUEST_PATH,
        &AuthEventPayload {
            user_id: user_id.to_string(),
            auth_request_id: auth_request_id.to_string(),
        },
    )
    .await
}

pub async fn publish_auth_response(env: &Env, user_id: &str, auth_request_id: &str) -> Result<()> {
    dispatch_internal(
        env,
        INTERNAL_AUTH_RESPONSE_PATH,
        &AuthEventPayload {
            user_id: user_id.to_string(),
            auth_request_id: auth_request_id.to_string(),
        },
    )
    .await
}

pub async fn publish_cipher_update(
    env: &Env,
    update_type: UpdateType,
    user_id: &str,
    cipher_id: &str,
    revision_date: &str,
    acting_device_id: Option<&str>,
) -> Result<()> {
    publish_vault_update(
        env,
        update_type,
        user_id,
        Some(cipher_id),
        revision_date,
        acting_device_id,
        VaultPayloadKind::Cipher,
        None,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn publish_organization_cipher_update(
    env: &Env,
    update_type: UpdateType,
    user_id: &str,
    cipher_id: &str,
    organization_id: &str,
    collection_ids: Option<Vec<String>>,
    revision_date: &str,
    acting_device_id: Option<&str>,
) -> Result<()> {
    publish_vault_update(
        env,
        update_type,
        user_id,
        Some(cipher_id),
        revision_date,
        acting_device_id,
        VaultPayloadKind::Cipher,
        Some(organization_id),
        collection_ids,
    )
    .await
}

pub async fn publish_folder_update(
    env: &Env,
    update_type: UpdateType,
    user_id: &str,
    folder_id: &str,
    revision_date: &str,
    acting_device_id: Option<&str>,
) -> Result<()> {
    publish_vault_update(
        env,
        update_type,
        user_id,
        Some(folder_id),
        revision_date,
        acting_device_id,
        VaultPayloadKind::Folder,
        None,
        None,
    )
    .await
}

pub async fn publish_send_update(
    env: &Env,
    update_type: UpdateType,
    user_id: &str,
    send_id: &str,
    revision_date: &str,
) -> Result<()> {
    publish_vault_update(
        env,
        update_type,
        user_id,
        Some(send_id),
        revision_date,
        None,
        VaultPayloadKind::Send,
        None,
        None,
    )
    .await
}

pub async fn publish_user_update(
    env: &Env,
    update_type: UpdateType,
    user_id: &str,
    revision_date: &str,
    acting_device_id: Option<&str>,
) -> Result<()> {
    publish_vault_update(
        env,
        update_type,
        user_id,
        None,
        revision_date,
        acting_device_id,
        VaultPayloadKind::User,
        None,
        None,
    )
    .await
}

pub fn publish_cipher_update_background(
    context: &BackgroundExecutor,
    env: Env,
    update_type: UpdateType,
    user_id: String,
    cipher_id: String,
    revision_date: String,
    acting_device_id: Option<String>,
) {
    context.wait_until(async move {
        if let Err(err) = publish_cipher_update(
            &env,
            update_type,
            &user_id,
            &cipher_id,
            &revision_date,
            acting_device_id.as_deref(),
        )
        .await
        {
            log::warn!("failed to publish cipher update: {err}");
        }
    });
}

#[allow(clippy::too_many_arguments)]
pub fn publish_organization_cipher_update_background(
    context: &BackgroundExecutor,
    env: Env,
    update_type: UpdateType,
    user_id: String,
    cipher_id: String,
    organization_id: String,
    collection_ids: Option<Vec<String>>,
    revision_date: String,
    acting_device_id: Option<String>,
) {
    context.wait_until(async move {
        if let Err(err) = publish_organization_cipher_update(
            &env,
            update_type,
            &user_id,
            &cipher_id,
            &organization_id,
            collection_ids,
            &revision_date,
            acting_device_id.as_deref(),
        )
        .await
        {
            log::warn!("failed to publish organization cipher update: {err}");
        }
    });
}

pub fn publish_folder_update_background(
    context: &BackgroundExecutor,
    env: Env,
    update_type: UpdateType,
    user_id: String,
    folder_id: String,
    revision_date: String,
    acting_device_id: Option<String>,
) {
    context.wait_until(async move {
        if let Err(err) = publish_folder_update(
            &env,
            update_type,
            &user_id,
            &folder_id,
            &revision_date,
            acting_device_id.as_deref(),
        )
        .await
        {
            log::warn!("failed to publish folder update: {err}");
        }
    });
}

pub fn publish_send_update_background(
    context: &BackgroundExecutor,
    env: Env,
    update_type: UpdateType,
    user_id: String,
    send_id: String,
    revision_date: String,
) {
    context.wait_until(async move {
        if let Err(err) =
            publish_send_update(&env, update_type, &user_id, &send_id, &revision_date).await
        {
            log::warn!("failed to publish send update: {err}");
        }
    });
}

pub fn publish_user_update_background(
    context: &BackgroundExecutor,
    env: Env,
    update_type: UpdateType,
    user_id: String,
    revision_date: String,
    acting_device_id: Option<String>,
) {
    context.wait_until(async move {
        if let Err(err) = publish_user_update(
            &env,
            update_type,
            &user_id,
            &revision_date,
            acting_device_id.as_deref(),
        )
        .await
        {
            log::warn!("failed to publish user update: {err}");
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn publish_vault_update(
    env: &Env,
    update_type: UpdateType,
    user_id: &str,
    item_id: Option<&str>,
    revision_date: &str,
    acting_device_id: Option<&str>,
    kind: VaultPayloadKind,
    organization_id: Option<&str>,
    collection_ids: Option<Vec<String>>,
) -> Result<()> {
    dispatch_internal(
        env,
        INTERNAL_VAULT_UPDATE_PATH,
        &VaultEventPayload {
            user_id: user_id.to_string(),
            item_id: item_id.map(str::to_string),
            organization_id: organization_id.map(str::to_string),
            collection_ids,
            revision_date: revision_date.to_string(),
            update_type: update_type as i32,
            acting_device_id: acting_device_id.map(str::to_string),
            kind,
        },
    )
    .await
}

async fn dispatch_internal(env: &Env, path: &str, payload: &impl Serialize) -> Result<()> {
    let namespace = env.durable_object(DO_BINDING)?;
    let stub = namespace.id_from_name(DO_INSTANCE_NAME)?.get_stub()?;
    let req = build_internal_request(env, path, payload).await?;

    let mut resp = stub.fetch_with_request(req).await?;
    if resp.status_code() >= 400 {
        let detail = resp.text().await.unwrap_or_else(|_| String::new());
        return Err(Error::RustError(format!(
            "notifications internal call failed (status={}): {detail}",
            resp.status_code()
        )));
    }
    Ok(())
}

async fn build_internal_request(
    env: &Env,
    path: &str,
    payload: &impl Serialize,
) -> Result<Request> {
    let payload_json = serde_json::to_string(payload)?;

    let db = env
        .d1("vaultsql")
        .map_err(|e| Error::RustError(format!("Failed to get database: {}", e)))?;

    let result: Option<serde_json::Value> = db
        .prepare("SELECT access_secret FROM jwt_keys WHERE id = ?1")
        .bind(&["global".into()])
        .map_err(|e| Error::RustError(format!("Failed to prepare statement: {}", e)))?
        .first(None)
        .await
        .map_err(|e| Error::RustError(format!("Failed to query database: {}", e)))?;

    let jwt_secret = result
        .and_then(|row| {
            row.get("access_secret")
                .and_then(|v| v.as_str().map(String::from))
        })
        .ok_or_else(|| Error::RustError("JWT keys not found".to_string()))?;

    let headers = Headers::new();
    headers.set("content-type", "application/json")?;
    headers.set(INTERNAL_AUTH_HEADER, &jwt_secret)?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&payload_json)));

    Request::new_with_init(&format!("https://notifications.internal{path}"), &init)
}

fn normalize_path(path: &str) -> &str {
    if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    }
}

fn extract_access_token(req: &Request) -> Option<String> {
    if let Some(token) = query_param(req, "access_token") {
        return Some(token);
    }

    let auth_header = req.headers().get("authorization").ok().flatten()?;
    auth_header
        .strip_prefix("Bearer ")
        .or_else(|| auth_header.strip_prefix("bearer "))
        .map(str::to_string)
}

fn query_param(req: &Request, key: &str) -> Option<String> {
    let url = req.url().ok()?;
    url.query_pairs().find_map(|(k, v)| {
        if k.eq_ignore_ascii_case(key) {
            Some(v.into_owned())
        } else {
            None
        }
    })
}

fn user_tag(user_id: &str) -> String {
    format!("user:{user_id}")
}

fn anon_tag(token: &str) -> String {
    format!("anon:{token}")
}

fn anon_ip_tag(ip: &str) -> String {
    format!("anon-ip:{ip}")
}

fn client_ip(req: &Request) -> String {
    req.headers()
        .get("cf-connecting-ip")
        .ok()
        .flatten()
        .and_then(|value| value.trim().parse::<std::net::IpAddr>().ok())
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "0.0.0.0".to_string())
}

fn is_signalr_messagepack_handshake(text: &str) -> bool {
    let trimmed = text.trim_end_matches(RECORD_SEPARATOR as char).trim();
    if trimmed.is_empty() {
        return false;
    }

    let Ok(msg) = serde_json::from_str::<InitialHandshake>(trimmed) else {
        return false;
    };
    msg.protocol == "messagepack" && msg.version == 1
}

fn encode_user_update(update_type: i32, auth_request_id: &str, user_id: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(192);

    write_array_len(&mut payload, 5);
    write_i32(&mut payload, 1);
    write_map_len(&mut payload, 0);
    write_nil(&mut payload);
    write_str(&mut payload, TARGET_RECEIVE_MESSAGE);
    write_array_len(&mut payload, 1);

    write_map_len(&mut payload, 3);
    write_str(&mut payload, "ContextId");
    write_nil(&mut payload);
    write_str(&mut payload, "Type");
    write_i32(&mut payload, update_type);
    write_str(&mut payload, "Payload");
    write_auth_payload_map(&mut payload, auth_request_id, user_id);

    add_signalr_length_prefix(payload)
}

fn encode_anonymous_auth_response(auth_request_id: &str, user_id: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(192);

    write_array_len(&mut payload, 5);
    write_i32(&mut payload, 1);
    write_map_len(&mut payload, 0);
    write_nil(&mut payload);
    write_str(&mut payload, TARGET_ANONYMOUS_AUTH_RESPONSE);
    write_array_len(&mut payload, 1);

    write_map_len(&mut payload, 3);
    write_str(&mut payload, "Type");
    write_i32(&mut payload, UPDATE_TYPE_AUTH_REQUEST_RESPONSE);
    write_str(&mut payload, "Payload");
    write_auth_payload_map(&mut payload, auth_request_id, user_id);
    write_str(&mut payload, "UserId");
    write_str(&mut payload, user_id);

    add_signalr_length_prefix(payload)
}

fn encode_vault_update(event: &VaultEventPayload) -> Vec<u8> {
    let mut payload = Vec::with_capacity(256);

    write_array_len(&mut payload, 5);
    write_i32(&mut payload, 1);
    write_map_len(&mut payload, 0);
    write_nil(&mut payload);
    write_str(&mut payload, TARGET_RECEIVE_MESSAGE);
    write_array_len(&mut payload, 1);

    write_map_len(&mut payload, 3);
    write_str(&mut payload, "ContextId");
    write_optional_str(&mut payload, event.acting_device_id.as_deref());
    write_str(&mut payload, "Type");
    write_i32(&mut payload, event.update_type);
    write_str(&mut payload, "Payload");

    match event.kind {
        VaultPayloadKind::Cipher => {
            write_map_len(&mut payload, 5);
            write_str(&mut payload, "Id");
            write_optional_str(&mut payload, event.item_id.as_deref());
            write_str(&mut payload, "UserId");
            if event.organization_id.is_some() {
                write_nil(&mut payload);
            } else {
                write_str(&mut payload, &event.user_id);
            }
            write_str(&mut payload, "OrganizationId");
            write_optional_str(&mut payload, event.organization_id.as_deref());
            write_str(&mut payload, "CollectionIds");
            if let Some(collection_ids) = &event.collection_ids {
                write_array_len(&mut payload, collection_ids.len());
                for collection_id in collection_ids {
                    write_str(&mut payload, collection_id);
                }
            } else {
                write_nil(&mut payload);
            }
            write_str(&mut payload, "RevisionDate");
            write_timestamp(&mut payload, &event.revision_date);
        }
        VaultPayloadKind::Folder | VaultPayloadKind::Send => {
            write_map_len(&mut payload, 3);
            write_str(&mut payload, "Id");
            write_optional_str(&mut payload, event.item_id.as_deref());
            write_str(&mut payload, "UserId");
            write_str(&mut payload, &event.user_id);
            write_str(&mut payload, "RevisionDate");
            write_timestamp(&mut payload, &event.revision_date);
        }
        VaultPayloadKind::User => {
            write_map_len(&mut payload, 2);
            write_str(&mut payload, "UserId");
            write_str(&mut payload, &event.user_id);
            write_str(&mut payload, "Date");
            write_timestamp(&mut payload, &event.revision_date);
        }
    }

    add_signalr_length_prefix(payload)
}

fn write_auth_payload_map(out: &mut Vec<u8>, auth_request_id: &str, user_id: &str) {
    write_map_len(out, 2);
    write_str(out, "Id");
    write_str(out, auth_request_id);
    write_str(out, "UserId");
    write_str(out, user_id);
}

fn add_signalr_length_prefix(mut body: Vec<u8>) -> Vec<u8> {
    let mut len = body.len();
    let mut prefixed = Vec::with_capacity(body.len() + 5);

    loop {
        let mut part = (len & 0x7f) as u8;
        len >>= 7;
        if len > 0 {
            part |= 0x80;
        }
        prefixed.push(part);
        if len == 0 {
            break;
        }
    }

    prefixed.append(&mut body);
    prefixed
}

fn write_nil(out: &mut Vec<u8>) {
    out.push(0xc0);
}

fn write_optional_str(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => write_str(out, value),
        None => write_nil(out),
    }
}

fn write_timestamp(out: &mut Vec<u8>, value: &str) {
    let Ok(date) = chrono::DateTime::parse_from_rfc3339(value) else {
        write_str(out, value);
        return;
    };
    let seconds = date.timestamp();
    let nanos = u64::from(date.timestamp_subsec_nanos());
    if (0..(1_i64 << 34)).contains(&seconds) {
        let packed = (nanos << 34) | seconds as u64;
        out.push(0xd7); // fixext 8
        out.push(0xff); // MessagePack timestamp extension type -1
        out.extend_from_slice(&packed.to_be_bytes());
    } else {
        write_str(out, value);
    }
}

fn write_i32(out: &mut Vec<u8>, value: i32) {
    if (0..=127).contains(&value) {
        out.push(value as u8);
        return;
    }

    if (-32..=-1).contains(&value) {
        out.push((value as i8) as u8);
        return;
    }

    if (i8::MIN as i32..=i8::MAX as i32).contains(&value) {
        out.push(0xd0);
        out.push(value as i8 as u8);
        return;
    }

    if (i16::MIN as i32..=i16::MAX as i32).contains(&value) {
        out.push(0xd1);
        out.extend_from_slice(&(value as i16).to_be_bytes());
        return;
    }

    out.push(0xd2);
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_array_len(out: &mut Vec<u8>, len: usize) {
    if len <= 15 {
        out.push(0x90 | (len as u8));
    } else if len <= u16::MAX as usize {
        out.push(0xdc);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0xdd);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn write_map_len(out: &mut Vec<u8>, len: usize) {
    if len <= 15 {
        out.push(0x80 | (len as u8));
    } else if len <= u16::MAX as usize {
        out.push(0xde);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0xdf);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
}

fn write_str(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = bytes.len();

    if len <= 31 {
        out.push(0xa0 | (len as u8));
    } else if len <= u8::MAX as usize {
        out.push(0xd9);
        out.push(len as u8);
    } else if len <= u16::MAX as usize {
        out.push(0xda);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0xdb);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    }
    out.extend_from_slice(bytes);
}
