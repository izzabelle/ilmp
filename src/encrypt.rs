// namespacing
use crate::Packet;
use crate::Result;
use orion::aead::{self, SecretKey};
use ring::digest;

/// trait that allows for me to be lazy
pub trait Encryption {
    /// return the encryption kind
    fn kind(&self) -> EncryptKind;
    /// returns Option<SecretKey>
    fn key(&self) -> Option<&SecretKey>;
    /// encrypts the packet contents and updates the integrity hash
    fn encrypt(&self, packet: &mut Packet) -> Result<()>;
    /// decrypts the packet contents, should only be used after integrity is
    /// validated
    fn decrypt(&self, packet: &mut Packet) -> Result<()>;
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

    fn encrypt(&self, packet: &mut Packet) -> Result<()> {
        packet.contents = aead::seal(self.key().unwrap(), &packet.contents)?;
        packet.integrity_hash = digest::digest(&digest::SHA256, &packet.contents)
            .as_ref()
            .to_vec();
        Ok(())
    }

    fn decrypt(&self, packet: &mut Packet) -> Result<()> {
        packet.contents = aead::open(self.key().unwrap(), &packet.contents)?;
        Ok(())
    }
}

impl SymmetricEncrypt {
    /// creates a new symmetric encryption key wrapper struct
    pub fn new(key: SecretKey) -> SymmetricEncrypt {
        SymmetricEncrypt(key)
    }

    #[doc(hidden)]
    /// dear future izzy, this is a really bad idea
    pub fn clone(&self) -> Result<SymmetricEncrypt> {
        Ok(SymmetricEncrypt::new(aead::SecretKey::from_slice(
            self.0.unprotected_as_bytes(),
        )?))
    }
}

/// literally not encryption whatsoever
pub struct NoEncrypt;

impl NoEncrypt {
    /// why
    pub fn new() -> NoEncrypt {
        NoEncrypt
    }
}

impl Encryption for NoEncrypt {
    fn kind(&self) -> EncryptKind {
        EncryptKind::None
    }

    // lol
    fn key(&self) -> Option<&SecretKey> {
        None
    }

    // lol
    fn encrypt(&self, _packet: &mut Packet) -> Result<()> {
        Ok(())
    }

    // lol
    fn decrypt(&self, _packet: &mut Packet) -> Result<()> {
        Ok(())
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
