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
//! | 1 byte       | u8 encrypt kind                            |
//! | 8 byte       | u64 length of the packet contents          |
//! | 4 byte       | CRC32 packet contents checksum             |
//! | 32 byte      | SHA256 packet contents integrity check     |
//! | `u64::MAX`   | packet contents                            |
//!

mod message;
pub use message::Message;
mod agreement;
pub use agreement::Agreement;
/// encryption types and functions
pub mod encrypt;

use encrypt::{EncryptKind, Encryption};
use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use orion::aead;
use ring::digest;
use std::convert::TryInto;
use std::marker::Unpin;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, IlmpError>;

struct NetworkPacket(Vec<u8>);

/// a type of data that can be sent
pub trait Sendable: Sized {
    fn to_packet(&self, encrypt_kind: EncryptKind) -> Result<Packet>;
    fn from_packet(packet: Packet) -> Result<Self>;
}

/// data to be sent
#[derive(Debug)]
pub struct Packet {
    pub kind: PacketKind,
    pub encrypt_kind: EncryptKind,
    pub integrity_hash: Vec<u8>,
    pub contents: Vec<u8>,
}

impl Packet {
    /// create a new `Packet`
    pub fn new(kind: PacketKind, contents: Vec<u8>, encrypt_kind: EncryptKind) -> Packet {
        let integrity_hash = digest::digest(&digest::SHA256, &contents).as_ref().to_vec();
        Packet {
            kind,
            integrity_hash,
            contents,
            encrypt_kind,
        }
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

    fn to_network_packet(&self) -> NetworkPacket {
        let mut contents: Vec<u8> = Vec::new();

        // write packet kind byte
        contents.push(self.kind as u8);

        // write encrypt kind byte
        contents.push(self.encrypt_kind as u8);

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
        let expected = digest::digest(&digest::SHA256, &self.contents)
            .as_ref()
            .to_vec();

        if expected == self.integrity_hash {
            Ok(())
        } else {
            println!("bad integrity");
            Err(IlmpError::BadHashIntegrity {
                found: self.integrity_hash.clone(),
                expected,
            }
            .into())
        }
    }

    /// verifies CRC32 checksum
    pub fn verify_checksum(&self, expected: u32) -> Result<()> {
        let found = self.generate_checksum();

        if found == expected {
            Ok(())
        } else {
            println!("bad checksum");
            Err(IlmpError::BadChecksumIntegrity { expected, found })
        }
    }
}

/// kinds of packets that can be sent
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketKind {
    Message = 0x00,
    Agreement = 0xff,
}

impl PacketKind {
    /// returns `Option<PacketKind> given valid matching variant
    pub fn from_u8(kind: u8) -> Option<PacketKind> {
        match kind {
            0x00 => Some(PacketKind::Message),
            0xff => Some(PacketKind::Agreement),
            _ => None,
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
}

/// reads a `Packet` from a stream
///
/// if `Ok(None)` is returned the stream has been disconnected.
pub async fn read<S>(stream: &mut S) -> Result<Option<Packet>>
where
    S: AsyncReadExt + Unpin,
{
    let mut info_buf = [0u8; 14];
    let check = stream.read(&mut info_buf).await?;
    if check == 0 {
        return Ok(None);
    }

    let kind = PacketKind::from_u8(info_buf[0]).unwrap();
    let encrypt_kind = EncryptKind::from_u8(info_buf[1]).unwrap();
    let length = u64::from_le_bytes(info_buf[2..10].try_into().unwrap()) as usize;
    let checksum = u32::from_le_bytes(info_buf[10..14].try_into().unwrap());

    let mut integrity_hash: Vec<u8> = vec![0; 32];
    stream.read(&mut integrity_hash).await?;

    let mut contents: Vec<u8> = vec![0; length];
    stream.read(&mut contents).await?;

    let packet = Packet {
        kind,
        contents,
        integrity_hash,
        encrypt_kind,
    };

    packet.verify_checksum(checksum)?;
    packet.verify_integrity()?;

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
        EncryptKind::None => {
            let network_packet = packet.to_packet(encryption.kind())?.to_network_packet();
            stream.write(&network_packet.0).await?;
            Ok(())
        }
        EncryptKind::Symmetric => {
            let mut packet = packet.to_packet(encryption.kind())?;
            packet.contents = aead::seal(encryption.key().unwrap(), &packet.contents)?;
            packet.integrity_hash = digest::digest(&digest::SHA256, &packet.contents)
                .as_ref()
                .to_vec();
            let network_packet = packet.to_network_packet();
            stream.write(&network_packet.0).await?;
            Ok(())
        }
    }
}
