use crate::Packet;
use orion::aead::SecretKey;

/// trait that allows for me to be lazy
pub trait Encryption {
    fn kind(&self) -> EncryptKind;
    fn key(&self) -> Option<&SecretKey>;
    fn encrypt(&self, packet: Packet) -> Packet;
    fn decrypt(&self, packet: Packet) -> Packet;
}

/// uses ring's aead module
pub struct SymmetricEncrypt(SecretKey);

impl Encryption for SymmetricEncrypt {
    fn kind(&self) -> EncryptKind {
        EncryptKind::Symmetric
    }

    fn key(&self) -> Option<&SecretKey> {
        Some(&self.0)
    }

    fn encrypt(&self, _packet: Packet) -> Packet {
        todo!()
    }

    fn decrypt(&self, _packet: Packet) -> Packet {
        todo!()
    }
}

impl SymmetricEncrypt {
    pub fn new(key: SecretKey) -> SymmetricEncrypt {
        SymmetricEncrypt(key)
    }
}

/// literally not encryption whatsoever
pub struct NoEncrypt;

impl Encryption for NoEncrypt {
    fn kind(&self) -> EncryptKind {
        EncryptKind::None
    }

    // lol
    fn key(&self) -> Option<&SecretKey> {
        None
    }

    // lol
    fn encrypt(&self, packet: Packet) -> Packet {
        packet
    }

    // lol
    fn decrypt(&self, packet: Packet) -> Packet {
        packet
    }
}

impl NoEncrypt {
    pub fn new() -> NoEncrypt {
        NoEncrypt
    }
}

/// encryption kind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EncryptKind {
    None = 0x00,
    Symmetric = 0xff,
}

impl EncryptKind {
    /// returns `EncryptKind` from u8 if returned value is valid
    pub fn from_u8(kind: u8) -> Option<EncryptKind> {
        match kind {
            0x00 => Some(EncryptKind::None),
            0xff => Some(EncryptKind::Symmetric),
            _ => None,
        }
    }
}
