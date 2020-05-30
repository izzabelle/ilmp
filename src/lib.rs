//! # Isabelle's Lazy Message Protocol
//!
//! ### network packet protocol
//!
//! I don't know whether or not this is a super practical way of doing things
//! but i'm lazy and it seems to work so gonna roll with it lol
//!
//! | segment size | usage                                      |
//! |--------------|--------------------------------------------|
//! | 1 byte       | u8 packet kind                             |
//! | 1 byte       | u8 encrypt flag                            |
//! | 8 byte       | u64 length of the packet contents          |
//! | 4 byte       | CRC32 packet contents checksum             |
//! | 32 byte      | SHA256 packet contents integrity check     |
//! | `u64::MAX`   | packet contents                            |
//!

// modules
mod message;
pub use message::Message;
mod agreement;
pub use agreement::Agreement;
mod join;
pub use join::Join;
mod leave;
pub use leave::Leave;
/// encryption types and functions
pub mod encrypt;

// namespacing
use encrypt::{EncryptFlag, Encryption};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use orion::aead;
use ring::{agreement as agree, digest, rand};
use std::convert::TryInto;
use std::marker::Unpin;
use thiserror::Error;

/// simple result
pub type Result<T> = std::result::Result<T, IlmpError>;

// packet that should be streamable
struct NetworkPacket(Vec<u8>);

/// a type of data that can be sent
pub trait Sendable: Sized {
    /// create a packet from the struct
    fn to_packet(&self, encrypt_flag: EncryptFlag) -> Result<Packet>;
    /// create the struct from a packet
    fn from_packet(packet: Packet) -> Result<Self>;
    /// returns the sendable's packet kind
    fn packet_kind(&self) -> u8;
}

/// data to be sent
#[derive(Debug, Clone)]
pub struct Packet {
    pub kind: u8,
    pub encrypt_flag: EncryptFlag,
    pub integrity_hash: Vec<u8>,
    pub contents: Vec<u8>,
}

impl Packet {
    /// create a new `Packet`
    pub fn new(kind: u8, contents: Vec<u8>, encrypt_flag: EncryptFlag) -> Packet {
        let integrity_hash = digest::digest(&digest::SHA256, &contents).as_ref().to_vec();
        Packet { kind, integrity_hash, contents, encrypt_flag }
    }

    // generate a checksum from the packet
    fn generate_checksum(&self) -> u32 {
        // combine integrity hash and contents
        let mut hash_and_contents = self.integrity_hash.clone();
        hash_and_contents.extend_from_slice(&self.contents);

        // generate checksum
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(hash_and_contents.as_ref());
        hasher.finalize()
    }

    // converts a to a network packet to be streamed
    fn to_network_packet(&self) -> NetworkPacket {
        let mut contents: Vec<u8> = Vec::new();

        // write packet kind byte
        contents.push(self.kind as u8);

        // write encrypt kind byte
        contents.push(self.encrypt_flag as u8);

        // write the packet length
        let contents_length = self.contents.len() as u64;
        contents.extend_from_slice(&contents_length.to_le_bytes());

        // write checksum
        let checksum = self.generate_checksum();
        contents.extend_from_slice(&checksum.to_le_bytes());

        // write hash and contents
        contents.extend_from_slice(&self.integrity_hash);
        contents.extend_from_slice(&self.contents);

        NetworkPacket(contents)
    }

    /// verifies SHA256 integrity
    pub fn verify_integrity(&self) -> Result<()> {
        let expected = digest::digest(&digest::SHA256, &self.contents).as_ref().to_vec();

        if expected == self.integrity_hash {
            Ok(())
        } else {
            Err(IlmpError::BadHashIntegrity { found: self.integrity_hash.clone(), expected }.into())
        }
    }

    /// verifies CRC32 checksum
    pub fn verify_checksum(&self, expected: u32) -> Result<()> {
        let found = self.generate_checksum();

        if found == expected {
            Ok(())
        } else {
            Err(IlmpError::BadChecksumIntegrity { expected, found })
        }
    }
}

/// ilmp's error type
#[derive(Error, Debug)]
pub enum IlmpError {
    #[error("checksum integrity check failed: (expected {expected:?} found {found:?})")]
    BadChecksumIntegrity { expected: u32, found: u32 },
    #[error("hash integrity check failed: (expected {expected:?} found {found:?})")]
    BadHashIntegrity { expected: Vec<u8>, found: Vec<u8> },
    // external error conversions
    #[error("std::io error")]
    StdIo(#[from] std::io::Error),
    #[error("serde_json error")]
    SerdeJson(#[from] serde_json::error::Error),
    #[error("string parsing error")]
    StringParse(#[from] std::string::FromUtf8Error),
    #[error("orion error")]
    Orion(#[from] orion::errors::UnknownCryptoError),
    #[error("ring fucking broke")]
    Ring(#[from] ring::error::Unspecified),
}

/// reads a `Packet` from a stream
///
/// if `Ok(None)` is returned the stream has been disconnected.
pub async fn read<S, E>(stream: &mut S, encryption: &E) -> Result<Option<Packet>>
where
    S: AsyncReadExt + Unpin,
    E: Encryption,
{
    let mut info_buf = [0u8; 14];
    let check = stream.read(&mut info_buf).await?;
    if check == 0 {
        return Ok(None);
    }

    let kind = info_buf[0];
    let encrypt_flag = EncryptFlag::from_u8(info_buf[1]).unwrap();
    let length = u64::from_le_bytes(info_buf[2..10].try_into().unwrap()) as usize;
    let checksum = u32::from_le_bytes(info_buf[10..14].try_into().unwrap());

    let mut integrity_hash: Vec<u8> = vec![0; 32];
    stream.read(&mut integrity_hash).await?;

    let mut contents: Vec<u8> = vec![0; length];
    stream.read(&mut contents).await?;

    let mut packet = Packet { kind, contents, integrity_hash, encrypt_flag };

    packet.verify_checksum(checksum)?;
    packet.verify_integrity()?;

    if packet.encrypt_flag == EncryptFlag::Symmetric {
        encryption.decrypt(&mut packet)?;
    }
    Ok(Some(packet))
}

/// writes a `Sendable` packet to a stream
pub async fn write<S, P, E>(stream: &mut S, packet: P, encryption: &E) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
    P: Sendable,
    E: Encryption,
{
    match encryption.kind() {
        EncryptFlag::None => {
            let network_packet = packet.to_packet(encryption.kind())?.to_network_packet();
            stream.write(&network_packet.0).await?;
            Ok(())
        }
        EncryptFlag::Symmetric => {
            let mut packet = packet.to_packet(encryption.kind())?;
            encryption.encrypt(&mut packet)?;
            let network_packet = packet.to_network_packet();
            stream.write(&network_packet.0).await?;
            Ok(())
        }
    }
}

/// writes a packet directly without conversion
pub async fn write_packet<S, E>(stream: &mut S, packet: Packet, encryption: &E) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
    E: Encryption,
{
    match encryption.kind() {
        EncryptFlag::None => {
            let network_packet = packet.to_network_packet();
            stream.write(&network_packet.0).await?;
            Ok(())
        }
        EncryptFlag::Symmetric => {
            let mut packet = packet;
            encryption.encrypt(&mut packet)?;
            let network_packet = packet.to_network_packet();
            stream.write(&network_packet.0).await?;
            Ok(())
        }
    }
}

/// uses ring's agree to generate key material and key
pub async fn initialize_connection<R, W>(read: &mut R, write: &mut W) -> Result<aead::SecretKey>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    // create / send agree key
    let rng = rand::SystemRandom::new();
    let my_priv_key = agree::EphemeralPrivateKey::generate(&agree::X25519, &rng)?;
    let my_pub_key = my_priv_key.compute_public_key()?;
    let agree_packet = Agreement::new(my_pub_key.as_ref().into());
    crate::write(write, agree_packet, &encrypt::NoEncrypt::new()).await?;

    // receive peer's pub key
    let packet = crate::read(read, &encrypt::NoEncrypt::new()).await?.unwrap();
    let agree_packet = Agreement::from_packet(packet)?;
    let peer_pub_key = agree::UnparsedPublicKey::new(&agree::X25519, agree_packet.public_key);

    // generate aead key
    agree::agree_ephemeral(
        my_priv_key,
        &peer_pub_key,
        IlmpError::Ring(ring::error::Unspecified),
        |key_material| {
            let key_material =
                digest::digest(&digest::SHA256, key_material.as_ref().into()).as_ref().to_vec();
            Ok(aead::SecretKey::from_slice(&key_material)?)
        },
    )
}
