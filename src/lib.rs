//! # Isabelle's Lazy Message Protocol
//!
//! ### network packet protocol
//!
//! I don't know whether or not this is a super practical way of doing things
//! but i'm lazy and it seems to work so gonna roll with it lol
//!
//! | segment size | usage                               |
//! |--------------|-------------------------------------|
//! | 1 byte       | u8 signifies the type of packet     |
//! | 8 byte       | u64 length of the packet contents   |
//! | 32 byte      | SHA256 packet contents checksum     |
//! | `u64::MAX`   | packet contents                     |
//!

use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use ring::digest;
use std::convert::TryInto;
use std::marker::Unpin;
use thiserror::Error;

mod message;
pub use message::Message;

pub type Result<T> = std::result::Result<T, IlmpError>;

struct NetworkPacket(Vec<u8>);

/// a type of data that can be sent
pub trait Sendable: Sized {
    fn to_packet(&self) -> Result<Packet>;
    fn from_packet(packet: Packet) -> Result<Self>;
}

/// data to be sent
pub struct Packet {
    kind: PacketKind,
    checksum: Vec<u8>,
    contents: Vec<u8>,
}

impl Packet {
    /// create a new `Packet`
    pub fn new(kind: PacketKind, contents: Vec<u8>) -> Packet {
        let checksum = digest::digest(&digest::SHA256, &contents).as_ref().to_vec();
        Packet {
            kind,
            checksum,
            contents,
        }
    }

    fn to_network_packet(&self) -> NetworkPacket {
        let mut contents: Vec<u8> = Vec::new();

        // write packet kind byte
        contents.push(self.kind as u8);

        // write the packet length
        let contents_length = self.contents.len() as u64;
        contents.extend_from_slice(&contents_length.to_le_bytes());

        // write checksum
        contents.extend_from_slice(&self.checksum.as_ref());

        // write contents
        contents.extend_from_slice(&self.contents);

        NetworkPacket(contents)
    }

    /// verifies SHA256 checksum
    pub fn verify_integrity(&self) -> Result<()> {
        let found = digest::digest(&digest::SHA256, &self.contents)
            .as_ref()
            .to_vec();
        if found == self.checksum {
            Ok(())
        } else {
            Err(IlmpError::BadChecksumIntegrity {
                expected: self.checksum.clone(),
                found,
            }
            .into())
        }
    }
}

/// kinds of packets that can be sent
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PacketKind {
    Message = 0,
    PublicKey = 1,
}

impl PacketKind {
    /// returns `Option<PacketKind> given valid matching variant
    pub fn from_u8(kind: u8) -> Option<PacketKind> {
        match kind {
            0 => Some(PacketKind::Message),
            _ => None,
        }
    }
}

/// ilmp's error type
#[derive(Error, Debug)]
pub enum IlmpError {
    #[error("checksum integrity check failed: (expected {expected:?} found {found:?})")]
    BadChecksumIntegrity { expected: Vec<u8>, found: Vec<u8> },
    #[error("std::io error")]
    // external error conversions
    StdIo(#[from] std::io::Error),
    #[error("serde_json error")]
    SerdeJson(#[from] serde_json::error::Error),
    #[error("string parsing error")]
    StringParse(#[from] std::string::FromUtf8Error),
}

/// reads a `Packet` from a stream
///
/// if `Ok(None)` is returned the stream has been disconnected.
pub async fn read<S>(stream: &mut S) -> Result<Option<Packet>>
where
    S: AsyncReadExt + Unpin,
{
    let mut info_buf = [0u8; 9];
    let check = stream.read(&mut info_buf).await?;
    if check == 0 {
        return Ok(None);
    }

    let kind = PacketKind::from_u8(info_buf[0]).unwrap();
    let length = u32::from_le_bytes(info_buf[1..9].try_into().unwrap()) as usize;

    let mut checksum: Vec<u8> = vec![0; 32];
    stream.read(&mut checksum).await?;

    let mut contents: Vec<u8> = vec![0; length];
    stream.read(&mut contents).await?;

    let packet = Packet {
        kind,
        contents,
        checksum,
    };
    packet.verify_integrity()?;

    Ok(Some(packet))
}

/// writes a `Sendable` packet to a stream
pub async fn write<S, P>(stream: &mut S, packet: P) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
    P: Sendable,
{
    let network_packet = packet.to_packet()?.to_network_packet();
    stream.write(&network_packet.0).await?;
    Ok(())
}
