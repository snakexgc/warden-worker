use crate::notify::types::{ChannelType, Notification};

#[derive(Debug)]
pub struct ChannelError {
    pub message: String,
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ChannelError {}

pub trait Channel {
    fn name(&self) -> &str;
    fn send(&self, notification: &Notification) -> Result<(), ChannelError>;
    fn channel_type(&self) -> ChannelType;
}
