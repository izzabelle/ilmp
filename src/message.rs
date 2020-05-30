use crate::{Packet, Result};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// a standard message from a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub timestamp: i64,
    pub message_id: u128,
    pub username: String,
    pub contents: String,
}

impl Message {
    /// create a new message
    pub fn new(username: String, contents: String) -> Message {
        let timestamp = Utc::now().timestamp();
        let message_id = Uuid::new_v4().as_u128();

        Message {
            username,
            message_id,
            timestamp,
            contents,
        }
    }
}

impl crate::Sendable for Message {
    fn to_packet(&self, encrypt_flag: crate::EncryptFlag) -> Result<Packet> {
        let contents: Vec<u8> = serde_json::to_string(&self)?.into_bytes();
        let kind = 0x00;
        Ok(Packet::new(kind, contents, encrypt_flag))
    }

    fn from_packet(packet: Packet) -> Result<Self> {
        let contents = &String::from_utf8(packet.contents)?;
        let message: Message = serde_json::from_str(contents)?;
        Ok(message)
    }

    fn packet_kind(&self) -> u8 {
        0x00
    }
}
