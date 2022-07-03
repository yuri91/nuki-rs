use anyhow::Result;
use byteorder::WriteBytesExt;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;
use std::io::Read;
use std::io::Write;

use crate::command;
use crate::crc;
use crate::crypto;

pub trait Message: std::fmt::Debug {
    const CMD: command::CommandId;

    fn encode(&self, buf: &mut Vec<u8>);
    fn decode(cur: &mut Cursor<&[u8]>) -> Result<Self>
    where
        Self: Sized;
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ErrorReport {
    pub error_code: i8,
    pub command: command::CommandId,
}

impl Message for ErrorReport {
    const CMD: command::CommandId = command::ERROR_REPORT;

    fn encode(&self, _buf: &mut Vec<u8>) {
        unreachable!();
    }
    fn decode(cur: &mut Cursor<&[u8]>) -> Result<Self> {
        let error_code = cur.read_i8()?;
        let command = cur.read_u16::<LittleEndian>()?;
        let command = command::parse(command)?;
        Ok(ErrorReport {
            error_code,
            command,
        })
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PublicKey {
    pub key: crypto::PublicKey,
}
impl PublicKey {
    pub fn new(key: crypto::PublicKey) -> PublicKey {
        PublicKey { key }
    }
}
impl Message for PublicKey {
    const CMD: command::CommandId = command::PUBLIC_KEY;

    fn encode(&self, buf: &mut Vec<u8>) {
        buf.write(&self.key).unwrap();
    }
    fn decode(cur: &mut Cursor<&[u8]>) -> Result<Self> {
        let mut key = [0u8; 32];
        cur.read_exact(&mut key)?;
        Ok(PublicKey { key })
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Challenge {
    pub nonce: [u8; 32],
}
impl Message for Challenge {
    const CMD: command::CommandId = command::CHALLENGE;

    fn encode(&self, _buf: &mut Vec<u8>) {
        unreachable!();
    }
    fn decode(cur: &mut Cursor<&[u8]>) -> Result<Self> {
        let mut nonce = [0u8; 32];
        cur.read_exact(&mut nonce)?;
        Ok(Challenge { nonce })
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct AuthorizationAuthenticator {
    pub authenticator: [u8; 32],
}
impl AuthorizationAuthenticator {
    pub fn new(
        authenticator: &[u8; 32],
    ) -> AuthorizationAuthenticator {
        AuthorizationAuthenticator {
            authenticator: *authenticator,
        }
    }
}
impl Message for AuthorizationAuthenticator {
    const CMD: command::CommandId = command::AUTHORIZATION_AUTHENTICATOR;

    fn encode(&self, buf: &mut Vec<u8>) {
        buf.write_all(&self.authenticator).unwrap();
    }
    fn decode(_cur: &mut Cursor<&[u8]>) -> Result<Self> {
        unreachable!();
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct AuthorizationData {
    pub authenticator: [u8; 32],
    pub id_type: u8,
    pub app_id: u32,
    pub name: [u8; 32],
    pub nonce: [u8; 32],
}
impl AuthorizationData {
    pub fn new(
        authenticator: &[u8; 32],
        id_type: u8,
        app_id: u32,
        name: &[u8; 32],
        nonce: &[u8; 32],
    ) -> AuthorizationData {
        AuthorizationData {
            authenticator: *authenticator,
            id_type,
            app_id,
            name: *name,
            nonce: *nonce,
        }
    }
}
impl Message for AuthorizationData {
    const CMD: command::CommandId = command::AUTHORIZATION_DATA;

    fn encode(&self, buf: &mut Vec<u8>) {
        buf.write_all(&self.authenticator).unwrap();
        buf.write_u8(self.id_type).unwrap();
        buf.write_u32::<LittleEndian>(self.app_id).unwrap();
        buf.write_all(&self.name).unwrap();
        buf.write_all(&self.nonce).unwrap();
    }
    fn decode(_cur: &mut Cursor<&[u8]>) -> Result<Self> {
        unreachable!();
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct AuthorizationId {
    pub authenticator: [u8; 32],
    pub auth_id: u32,
    pub uuid: [u8; 16],
    pub nonce: [u8; 32],
}
impl Message for AuthorizationId {
    const CMD: command::CommandId = command::AUTHORIZATION_ID;

    fn encode(&self, _buf: &mut Vec<u8>) {
        unreachable!();
    }
    fn decode(cur: &mut Cursor<&[u8]>) -> Result<Self> {
        let mut authenticator = [0; 32];
        let mut uuid = [0; 16];
        let mut nonce = [0; 32];
        cur.read_exact(&mut authenticator)?;
        let auth_id = cur.read_u32::<LittleEndian>()?;
        cur.read_exact(&mut uuid)?;
        cur.read_exact(&mut nonce)?;
        Ok(AuthorizationId {
            authenticator,
            auth_id,
            uuid,
            nonce,
        })
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct AuthorizationIdComfirmation {
    pub authenticator: [u8; 32],
    pub auth_id: u32,
}
impl AuthorizationIdComfirmation {
    pub fn new(
        authenticator: &[u8; 32],
        auth_id: u32,
    ) -> AuthorizationIdComfirmation {
        AuthorizationIdComfirmation {
            authenticator: *authenticator,
            auth_id,
        }
    }
}
impl Message for AuthorizationIdComfirmation {
    const CMD: command::CommandId = command::AUTHORIZATION_ID_CONFIRMATION;

    fn encode(&self, buf: &mut Vec<u8>) {
        buf.write_all(&self.authenticator).unwrap();
        buf.write_u32::<LittleEndian>(self.auth_id).unwrap();
    }
    fn decode(_cur: &mut Cursor<&[u8]>) -> Result<Self> {
        unreachable!();
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Status {
    pub status: StatusKind,
}
#[derive(PartialEq, Eq, Clone, Debug)]
#[repr(u8)]
pub enum StatusKind {
    Complete = 0x00,
    Accepted = 0x01,
}

impl Message for Status {
    const CMD: command::CommandId = command::STATUS;

    fn encode(&self, _buf: &mut Vec<u8>) {
        unreachable!();
    }
    fn decode(cur: &mut Cursor<&[u8]>) -> Result<Self> {
        let status = cur.read_u8()?;
        let status = match status {
            0 => {
                StatusKind::Complete
            }
            1 => {
                StatusKind::Accepted
            }
            _ => {
                return Err(anyhow::anyhow!("Invalid status value: {}", status));
            }
        };
        Ok(Status {
            status
        })
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct RequestData {
    pub command: command::CommandId,
}
impl RequestData {
    pub fn new(cmd: command::CommandId) -> RequestData {
        RequestData { command: cmd }
    }
}
impl Message for RequestData {
    const CMD: command::CommandId = command::REQUEST_DATA;

    fn encode(&self, buf: &mut Vec<u8>) {
        buf.write_u16::<LittleEndian>(self.command.value()).unwrap();
    }
    fn decode(_cur: &mut Cursor<&[u8]>) -> Result<Self> {
        unreachable!();
    }
}

fn decode_inner<M: Message>(data: &[u8]) -> Result<M> {
    let mut cur = Cursor::new(data);
    let cmd = cur.read_u16::<LittleEndian>()?;
    let cmd = command::parse(cmd)?;
    let msg = if cmd == M::CMD {
        M::decode(&mut cur)?
    } else if cmd == ErrorReport::CMD {
        let err = ErrorReport::decode(&mut cur)?;
        return Err(anyhow::anyhow!(
            "Error report! code: 0x{:x?}, cmd: {}",
            err.error_code,
            err.command
        ));
    } else {
        return Err(anyhow::anyhow!("Unexpected command: {}", cmd));
    };
    if cur.position() as usize != data.len() {
        return Err(anyhow::anyhow!("Unexpected extra bytes"));
    }
    Ok(msg)
}

pub fn decode<M: Message>(payload: &[u8]) -> Result<M> {
    let data = crc::unwrap(payload)?;
    decode_inner(data)
}

fn encode_inner<M: Message>(m: &M, buf: &mut Vec<u8>) {
    buf.write_u16::<LittleEndian>(M::CMD.value()).unwrap();
    m.encode(buf);
}

pub fn encode<M: Message>(m: &M) -> Vec<u8> {
    let mut buf = Vec::new();
    encode_inner(m, &mut buf);
    crc::wrap(&mut buf);
    buf
}

pub fn encrypt<M: Message>(msg: &M, auth_id: u32, key: &crypto::Key) -> Vec<u8> {
    let mut plain = Vec::new();
    plain.write_u32::<LittleEndian>(auth_id).unwrap();
    encode_inner(msg, &mut plain);
    crc::wrap(&mut plain);
    let nonce = crypto::gen_nonce();
    let mut payload = Vec::new();
    payload.write(&nonce).unwrap();
    payload.write_u32::<LittleEndian>(auth_id).unwrap();
    payload
        .write_u16::<LittleEndian>(plain.len() as u16)
        .unwrap();
    crypto::encrypt(&mut payload, &plain, &nonce, &key).unwrap();
    payload
}

pub fn decrypt<M: Message>(payload: &[u8], key: &crypto::Key) -> Result<M> {
    let mut cur = Cursor::new(payload);
    let mut nonce: crypto::Nonce = [0; 24];
    cur.read_exact(&mut nonce)?;
    let auth_id = cur.read_u32::<LittleEndian>()?;
    let len = cur.read_u16::<LittleEndian>()? as usize;
    let plain = crypto::decrypt(remaining_slice(&cur), &nonce, key)?;
    if len != plain.len() {
        return Err(anyhow::anyhow!(
            "Inconsistent length! outer: {}, inner: {}",
            len,
            plain.len()
        ));
    }
    let data = crc::unwrap(&plain)?;
    let mut cur = Cursor::new(data);
    let auth_id_inner = cur.read_u32::<LittleEndian>()?;
    if auth_id_inner != auth_id {
        return Err(anyhow::anyhow!(
            "Inconsistent auth_id! outer: {}, inner: {}",
            auth_id,
            auth_id_inner
        ));
    }
    let m = decode_inner(remaining_slice(&cur))?;
    Ok(m)
}

fn remaining_slice<'a>(cur: &Cursor<&'a [u8]>) -> &'a [u8] {
    let len = cur.position().min(cur.get_ref().len() as u64);
    &cur.get_ref()[(len as usize)..]
}
