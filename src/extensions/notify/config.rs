use std::collections::HashSet;

use super::types::{NotifyEvent, NotifyLevel};

const NOTIFY_LEVEL_VAR: &str = "NOTIFY_LEVEL";
const NOTIFY_EVENTS_VAR: &str = "NOTIFY_EVENTS";

#[derive(Debug, Clone, Default)]
pub struct NotifyConfig {
    pub min_level: NotifyLevel,
    pub enabled_events: HashSet<String>,
}

impl NotifyConfig {
    pub fn from_env(env: &worker::Env) -> Self {
        let min_level = parse_notify_level(env);
        let enabled_events = parse_enabled_events(env);

        Self {
            min_level,
            enabled_events,
        }
    }

    pub fn is_event_enabled(&self, event: NotifyEvent) -> bool {
        if self.enabled_events.is_empty() {
            return false;
        }
        if self.enabled_events.contains("*") {
            return true;
        }
        self.enabled_events.contains(event.key())
    }
}

fn parse_notify_level(env: &worker::Env) -> NotifyLevel {
    let raw = env.var(NOTIFY_LEVEL_VAR).ok().map(|v| v.to_string());
    let Some(raw) = raw else {
        return NotifyLevel::Info;
    };

    NotifyLevel::from_str(raw.trim()).unwrap_or(NotifyLevel::Info)
}

fn parse_enabled_events(env: &worker::Env) -> HashSet<String> {
    let raw = env.var(NOTIFY_EVENTS_VAR).ok().map(|v| v.to_string());
    let Some(raw) = raw else {
        return HashSet::new();
    };

    let raw = raw.trim().to_lowercase();
    if raw.is_empty() || matches!(raw.as_str(), "none" | "off" | "0" | "false") {
        return HashSet::new();
    }

    if matches!(raw.as_str(), "all" | "*") {
        let mut set = HashSet::new();
        set.insert("*".to_string());
        return set;
    }

    let mut set = HashSet::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(event) = NotifyEvent::from_key(part) {
            set.insert(event.key().to_string());
        } else {
            set.insert(part.to_string());
        }
    }
    set
}

pub fn is_webhook_configured(env: &worker::Env) -> bool {
    env.secret("WEWORK_WEBHOOK_URL").is_ok()
        || (env.secret("TELEGRAM_BOT_TOKEN").is_ok() && env.secret("TELEGRAM_CHAT_ID").is_ok())
}
