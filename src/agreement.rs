// namespacing
use crate::{Packet, PacketKind, Result};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// packet to be used when server/client are coming to an agreement on
/// encryption key material
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agreement {
    pub timestamp: i64,
    pub message_id: u128,
    pub public_key: Vec<u8>,
}

impl Agreement {
    /// creates a new agreement packet from a public key
    pub fn new(public_key: Vec<u8>) -> Agreement {
        let timestamp = Utc::now().timestamp();
        let message_id = Uuid::new_v4().as_u128();
        Agreement {
            timestamp,
            message_id,
            public_key,
        }
    }
}

impl crate::Sendable for Agreement {
    fn to_packet(&self, encrypt_kind: crate::EncryptKind) -> Result<Packet> {
        let contents: Vec<u8> = serde_json::to_string(&self)?.into_bytes();
        let kind = PacketKind::Agreement;
        Ok(Packet::new(kind, contents, encrypt_kind))
    }

    fn from_packet(packet: Packet) -> Result<Self> {
        let contents = &String::from_utf8(packet.contents)?;
        let agreement: Agreement = serde_json::from_str(contents)?;
        Ok(agreement)
    }
}
