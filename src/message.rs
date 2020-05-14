use crate::{Packet, PacketKind, Result};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub timestamp: i64,
    pub message_id: u128,
    pub username: String,
    pub contents: String,
}

impl Message {
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
    fn to_packet(self) -> Result<Packet> {
        let contents: Vec<u8> = serde_json::to_string(&self)?.into_bytes();
        let kind = PacketKind::Message;

        Ok(Packet { kind, contents })
    }
    fn from_packet(packet: Packet) -> Result<Self> {
        let contents = &String::from_utf8(packet.contents)?;
        let message: Message = serde_json::from_str(contents)?;
        Ok(message)
    }
}
