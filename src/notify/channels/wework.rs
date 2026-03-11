use serde_json::json;
use worker::{wasm_bindgen::JsValue, Env, Fetch, Method, Request, RequestInit};

use crate::notify::types::{ChannelType, Notification};

use super::r#trait::ChannelError;

const WEBHOOK_SECRET_NAME: &str = "WEWORK_WEBHOOK_URL";

pub struct WeWorkChannel {
    webhook_url: String,
}

impl WeWorkChannel {
    pub fn from_env(env: &Env) -> Option<Self> {
        let webhook_url = env.secret(WEBHOOK_SECRET_NAME).ok()?.to_string();
        if webhook_url.trim().is_empty() {
            return None;
        }
        Some(Self { webhook_url })
    }

    pub fn channel_type(&self) -> ChannelType {
        ChannelType::WeWork
    }

    pub async fn send(&self, notification: &Notification) -> Result<(), ChannelError> {
        let content = crate::notify::templates::format_for_wework(notification);

        if content.is_empty() {
            return Err(ChannelError {
                message: "Empty content".to_string(),
            });
        }

        let body = json!({
            "msgtype": "markdown",
            "markdown": { "content": content }
        })
        .to_string();

        let mut init = RequestInit::new();
        init.with_method(Method::Post);
        init.with_body(Some(JsValue::from_str(&body)));
        let mut request = Request::new_with_init(&self.webhook_url, &init)
            .map_err(|e| ChannelError { message: e.to_string() })?;

        if let Ok(headers) = request.headers_mut() {
            let _ = headers.set("content-type", "application/json; charset=utf-8");
        }

        let r = Fetch::Request(request)
            .send()
            .await
            .map_err(|e| ChannelError { message: e.to_string() })?;
        let status = r.status_code();

        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(ChannelError {
                message: format!("WeWork webhook failed with status {}", status),
            })
        }
    }
}
