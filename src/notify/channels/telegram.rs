use serde_json::json;
use worker::{wasm_bindgen::JsValue, Env, Fetch, Method, Request, RequestInit};

use crate::notify::types::{ChannelType, Notification};

use super::r#trait::ChannelError;

const TELEGRAM_BOT_TOKEN: &str = "TELEGRAM_BOT_TOKEN";
const TELEGRAM_CHAT_ID: &str = "TELEGRAM_CHAT_ID";

pub struct TelegramChannel {
    bot_token: String,
    chat_id: String,
}

impl TelegramChannel {
    pub fn from_env(env: &Env) -> Option<Self> {
        let bot_token = env.secret(TELEGRAM_BOT_TOKEN).ok()?.to_string();
        let chat_id = env.secret(TELEGRAM_CHAT_ID).ok()?.to_string();
        if bot_token.trim().is_empty() || chat_id.trim().is_empty() {
            return None;
        }
        Some(Self { bot_token, chat_id })
    }

    pub fn channel_type(&self) -> ChannelType {
        ChannelType::Telegram
    }

    pub async fn send(&self, notification: &Notification) -> Result<(), ChannelError> {
        let text = crate::notify::templates::format_for_telegram(notification);

        if text.is_empty() {
            return Err(ChannelError {
                message: "Empty content".to_string(),
            });
        }

        let url = format!(
            "https://api.telegram.org/bot{}/sendMessage",
            self.bot_token
        );

        let body = json!({
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "HTML"
        })
        .to_string();

        let mut init = RequestInit::new();
        init.with_method(Method::Post);
        init.with_body(Some(JsValue::from_str(&body)));
        let mut request = Request::new_with_init(&url, &init)
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
                message: format!("Telegram API failed with status {}", status),
            })
        }
    }
}
