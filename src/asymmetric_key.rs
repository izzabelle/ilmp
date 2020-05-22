use crate::{Packet, PacketKind, Result};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsymmetricKey {
    pub timestamp: i64,
    pub public_key: Vec<u8>,
}

impl AsymmetricKey {
    pub fn new(public_key: Vec<u8>) -> AsymmetricKey {
        let timestamp = Utc::now().timestamp();
        AsymmetricKey { public_key, timestamp }
    }
}

impl crate::Sendable for AsymmetricKey {
    fn to_packet(&self, encrypt_kind: crate::EncryptKind) -> Result<Packet> {
        let contents: Vec<u8> = serde_json::to_string(&self)?.into_bytes();
        let kind = PacketKind::AsymmetricKey;
        Ok(Packet::new(kind, contents, encrypt_kind))
    }

    fn from_packet(packet: Packet) -> Result<AsymmetricKey> {
        let contents = &String::from_utf8(packet.contents)?;
        let asymmetric_key: AsymmetricKey = serde_json::from_str(contents)?;
        Ok(asymmetric_key)
    }
}
