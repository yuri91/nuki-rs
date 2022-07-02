use anyhow::Result;
use byteorder::WriteBytesExt;
use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt};

use crate::command;
use crate::crc;

pub trait Request {
    const CMD: command::CommandId;

    fn encode(&self, buf: &mut Vec<u8>);
}
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Reply {
    ErrorReport(ErrorReport),
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct ErrorReport {
    pub error_code: i8,
    pub command: command::CommandId,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct RequestData {
    pub command: command::CommandId
}
impl RequestData {
    pub fn new(cmd: command::CommandId) -> RequestData {
        RequestData { command: cmd }
    }
}
impl Request for RequestData {
    const CMD: command::CommandId = command::REQUEST_DATA;

    fn encode(&self, buf: &mut Vec<u8>) {
        buf.write_u16::<LittleEndian>(self.command.value()).unwrap();
    }
}

pub fn decode(payload: &[u8]) -> Result<Reply> {
    let data = crc::unwrap(payload)?;
    let mut cur = Cursor::new(data);
    let cmd = cur.read_u16::<LittleEndian>()?;
    let msg = match command::parse(cmd)? {
        command::ERROR_REPORT => {
            let error_code = cur.read_i8()?;
            let command = command::parse(cur.read_u16::<LittleEndian>()?)?;
            Reply::ErrorReport(ErrorReport {
                error_code,
                command
            })
        },
        _ => {
            return Err(anyhow::anyhow!("Unexpected command: {}", cmd));
        }
    };
    Ok(msg)
}

pub fn encode<R: Request>(r: &R) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.write_u16::<LittleEndian>(R::CMD.value()).unwrap();
    r.encode(&mut buf);
    crc::wrap(&mut buf);
    buf
}
