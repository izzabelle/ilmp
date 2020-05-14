//! # Isabelle's Lazy Message Protocol
#![allow(dead_code)]

use futures_util::io::{AsyncReadExt, AsyncWriteExt};
use orion::aead;
use std::convert::TryInto;
use std::marker::Unpin;

mod message;
pub use message::Message;

/// lazy error
pub type Error = Box<dyn std::error::Error>;
/// lazy result
pub type Result<T> = std::result::Result<T, Error>;

struct NetworkPacket(Vec<u8>);

/// A type of data that can be sent
pub trait Sendable: Sized {
    fn to_packet(self) -> Result<Packet>;
    fn from_packet(packet: Packet) -> Result<Self>;
}

/// Data to be sent
pub struct Packet {
    kind: PacketKind,
    contents: Vec<u8>,
}

impl Packet {
    /// Create a new `Packet`
    pub fn new(kind: PacketKind, contents: Vec<u8>) -> Packet {
        Packet { kind, contents }
    }

    fn to_network_packet(self) -> NetworkPacket {
        let mut contents: Vec<u8> = Vec::new();

        // write packet kind byte
        contents.push(self.kind as u8);
        // write the packet length
        let contents_length = self.contents.len() as u32;
        contents.extend_from_slice(&contents_length.to_le_bytes());
        // write contents
        contents.extend_from_slice(&self.contents);

        NetworkPacket(contents)
    }
}

/// reads a `Packet` from a stream
///
/// if `Ok(None)` is returned the stream has been disconnected.
pub async fn read<S>(stream: &mut S) -> Result<Option<Packet>>
where
    S: AsyncReadExt + Unpin,
{
    let mut info_buf = [0u8; 5];
    let check = stream.read(&mut info_buf).await?;
    if check == 0 {
        return Ok(None);
    }

    let packet_kind = PacketKind::from_u8(info_buf[0]).unwrap();
    let length = u32::from_le_bytes(info_buf[1..5].try_into().unwrap()) as usize;

    let mut contents: Vec<u8> = vec![0; length];
    stream.read(&mut contents).await?;

    let packet = Packet::new(packet_kind, contents);

    Ok(Some(packet))
}

/// reads a `Packet` from a stream and decrypts
///
/// if `Ok(None)` is returned the stream has been disconnected.
pub async fn read_encrypted<S>(stream: &mut S, key: &aead::SecretKey) -> Result<Option<Packet>>
where
    S: AsyncReadExt + Unpin,
{
    let packet = read(stream).await?;
    match packet {
        None => Ok(packet),
        Some(mut packet) => {
            packet.contents = aead::open(&key, &packet.contents)?;
            Ok(Some(packet))
        }
    }
}

/// Writes a `Sendable` packet to a stream
pub async fn write<S, P>(stream: &mut S, packet: P) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
    P: Sendable,
{
    let network_packet = packet.to_packet()?.to_network_packet();
    stream.write(&network_packet.0).await?;
    Ok(())
}

/// Writes an encrypted `Sendable` packet to a stream
pub async fn write_encrypted<S, P>(stream: &mut S, packet: P, key: &aead::SecretKey) -> Result<()>
where
    S: AsyncWriteExt + Unpin,
    P: Sendable,
{
    let mut packet = packet.to_packet()?;
    packet.contents = aead::seal(&key, &packet.contents)?;
    let network_packet = packet.to_network_packet();
    stream.write(&network_packet.0).await?;
    Ok(())
}

/// Kinds of packets that can be sent
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
