use crate::background::BackgroundExecutor;
use crate::logging::targets;

use super::channels::{TelegramChannel, WeWorkChannel};
use super::config::NotifyConfig;
use super::context::check_and_update_ua;
use super::types::{ChannelType, Notification, NotificationKind};

enum Channel {
    WeWork(WeWorkChannel),
    Telegram(TelegramChannel),
}

impl Channel {
    fn channel_type(&self) -> ChannelType {
        match self {
            Channel::WeWork(_) => ChannelType::WeWork,
            Channel::Telegram(_) => ChannelType::Telegram,
        }
    }

    async fn send(&self, notification: &Notification) -> Result<(), String> {
        match self {
            Channel::WeWork(ch) => ch.send(notification).await.map_err(|e| e.message),
            Channel::Telegram(ch) => ch.send(notification).await.map_err(|e| e.message),
        }
    }
}

pub struct Dispatcher {
    config: NotifyConfig,
    channels: Vec<Channel>,
}

impl Dispatcher {
    pub fn new(env: &worker::Env) -> Self {
        let config = NotifyConfig::from_env(env);
        let mut channels = Vec::new();

        if let Some(ch) = WeWorkChannel::from_env(env) {
            channels.push(Channel::WeWork(ch));
        }

        if let Some(ch) = TelegramChannel::from_env(env) {
            channels.push(Channel::Telegram(ch));
        }

        Self { config, channels }
    }

    pub fn should_dispatch(&self, notification: &Notification) -> bool {
        if self.channels.is_empty() {
            return false;
        }

        match notification.kind {
            NotificationKind::Event => {
                if let Some(event) = notification.event {
                    if !self.config.is_event_enabled(event) {
                        return false;
                    }
                    if event.level() < self.config.min_level {
                        return false;
                    }
                }
            }
            NotificationKind::VerificationCode => {
                return true;
            }
        }

        true
    }

    pub async fn dispatch(&self, env: &worker::Env, mut notification: Notification) -> Result<(), worker::Error> {
        if !self.should_dispatch(&notification) {
            log::debug!(
                target: targets::NOTIFY,
                "notification skipped: kind={:?}",
                notification.kind
            );
            return Ok(());
        }

        if notification.kind == NotificationKind::Event {
            if let Some(ref mut ctx) = notification.context {
                check_and_update_ua(ctx, env).await;
            }
        }

        log::info!(
            target: targets::NOTIFY,
            "dispatching notification kind={:?} channels={}",
            notification.kind,
            self.channels.len()
        );

        let mut has_success = false;
        for channel in &self.channels {
            match channel.send(&notification).await {
                Ok(()) => {
                    log::debug!(
                        target: targets::NOTIFY,
                        "notification sent via {}",
                        channel.channel_type().as_str()
                    );
                    has_success = true;
                }
                Err(e) => {
                    log::warn!(
                        target: targets::NOTIFY,
                        "notification failed via {}: {}",
                        channel.channel_type().as_str(),
                        e
                    );
                }
            }
        }

        if self.channels.is_empty() {
            log::warn!(target: targets::NOTIFY, "no notification channels configured");
        }

        if !has_success && !self.channels.is_empty() {
            return Err(worker::Error::RustError("All notification channels failed".to_string()));
        }

        Ok(())
    }
}

pub async fn dispatch(env: &worker::Env, notification: Notification) -> Result<(), worker::Error> {
    let dispatcher = Dispatcher::new(env);
    dispatcher.dispatch(env, notification).await
}

pub fn dispatch_background(
    context: &BackgroundExecutor,
    env: worker::Env,
    notification: Notification,
) {
    context.wait_until(async move {
        let dispatcher = Dispatcher::new(&env);
        if let Err(e) = dispatcher.dispatch(&env, notification).await {
            log::warn!(target: targets::NOTIFY, "background notification failed: {:?}", e);
        }
    });
}

pub fn is_webhook_configured(env: &worker::Env) -> bool {
    super::config::is_webhook_configured(env)
}
