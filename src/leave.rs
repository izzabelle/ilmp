use crate::{Packet, Result};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// packet for when a user connects to the server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Leave {
    pub timestamp: i64,
    pub message_id: u128,
    pub username: String,
}

impl Leave {
    pub fn new(username: String) -> Leave {
        let timestamp = Utc::now().timestamp();
        let message_id = Uuid::new_v4().as_u128();

        Leave { timestamp, message_id, username }
    }
}

impl crate::Sendable for Leave {
    fn to_packet(&self, encrypt_flag: crate::EncryptFlag) -> Result<Packet> {
        let contents: Vec<u8> = serde_json::to_string(&self)?.into_bytes();
        let kind = 0xfd;
        Ok(Packet::new(kind, contents, encrypt_flag))
    }

    fn from_packet(packet: Packet) -> Result<Self> {
        let contents = &String::from_utf8(packet.contents)?;
        let leave: Leave = serde_json::from_str(contents)?;
        Ok(leave)
    }

    fn packet_kind(&self) -> u8 {
        0xfd
    }
}
