/* Nuki-rs: Control a Nuki Smart Lock with the Bluetooth API in Rust.
 * Copyright (C) 2022  Yuri Iozzelli <y.iozzelli@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use anyhow::Result;
use byteorder::WriteBytesExt;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use dryoc::constants::CRYPTO_SECRETBOX_MACBYTES;
use num_enum::{TryFromPrimitive, IntoPrimitive};
use std::convert::TryInto;

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
pub struct KeyturnerStates {
    pub nuki_state: NukiState,
    pub lock_state: LockState,
    pub trigger: Trigger,
    pub current_time: [u8; 7],
    pub timezone_offset: i16,
    pub battery_critical: bool,
    pub battery_charging: bool,
    pub battery_percentage: u8,
    pub config_update_count: u8,
    pub lock_n_go_timer: u8,
    pub last_lock_action: u8,
    pub last_lock_action_trigger: Trigger,
    pub last_lock_action_completion_status: u8,
    pub door_sensor_state: DoorSensorState,

}
#[derive(PartialEq, Eq, Clone, Copy, Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum NukiState {
    Uninitialized = 0x00,
    PairingMode = 0x01,
    DoorMode = 0x02,
    MaintenanceMode = 0x04,
}
#[derive(PartialEq, Eq, Clone, Copy, Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum LockState {
    Uncalibrated = 0x00,
    Locked = 0x01,
    Unlocking = 0x02,
    Unlocked = 0x03,
    Locking = 0x04,
    Unlatched = 0x05,
    UnlockedLockNGo = 0x06,
    Unlatching = 0x07,
    Calibration = 0xfc,
    BootRun = 0xfd,
    MotorBlocked = 0xfe,
    Undefined = 0xff,
}
#[derive(PartialEq, Eq, Clone, Copy, Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum Trigger {
    System = 0x00,
    Manual = 0x01,
    Button = 0x02,
    Automatic = 0x03,
    AutoLock = 0x06,
}
#[derive(PartialEq, Eq, Clone, Copy, Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum DoorSensorState {
    Unavailable = 0x00,
    Deactivated = 0x01,
    DoorClosed = 0x02,
    DoorOpened = 0x03,
    DoorStateUnknown = 0x04,
    Calibrating = 0x05,
}

impl Message for KeyturnerStates {
    const CMD: command::CommandId = command::KEYTURNER_STATES;

    fn encode(&self, _buf: &mut Vec<u8>) {
        unreachable!();
    }
    fn decode(cur: &mut Cursor<&[u8]>) -> Result<Self> {
        let nuki_state = cur.read_u8()?.try_into()?;
        let lock_state = cur.read_u8()?.try_into()?;
        let trigger = cur.read_u8()?.try_into()?;
        let mut current_time = [0; 7];
        cur.read_exact(&mut current_time)?;
        let timezone_offset = cur.read_i16::<LittleEndian>()?;
        let critical_battery_state = cur.read_u8()?;
        let battery_critical = (critical_battery_state & 0x01) == 0x01;
        let battery_charging = (critical_battery_state & 0x02) == 0x02;
        let battery_percentage = (critical_battery_state & 0xfc) >> 1;
        let config_update_count = cur.read_u8()?;
        let lock_n_go_timer = cur.read_u8()?;
        let last_lock_action = cur.read_u8()?;
        let last_lock_action_trigger = cur.read_u8()?.try_into()?;
        let last_lock_action_completion_status = cur.read_u8()?;
        let door_sensor_state = cur.read_u8()?.try_into()?;
        cur.read_u16::<LittleEndian>()?; // night mode flag. NOTE: Seems incorrect!
        cur.read_u8()?; // Accessory battery state;
        // Next 3 bytes are not documented
        cur.read_u8()?;
        cur.read_u8()?;
        cur.read_u8()?;
        Ok(KeyturnerStates {
            nuki_state,
            lock_state,
            trigger,
            current_time,
            timezone_offset,
            battery_critical,
            battery_charging,
            battery_percentage,
            config_update_count,
            lock_n_go_timer,
            last_lock_action,
            last_lock_action_trigger,
            last_lock_action_completion_status,
            door_sensor_state,
        })
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct LockAction {
    pub lock_action: LockActionKind,
    pub app_id: u32,
    pub flags: u8,
    pub name_suffix: Option<[u8; 20]>,
    pub nonce: [u8; 32],
}
#[derive(PartialEq, Eq, Clone, Copy, Debug, IntoPrimitive)]
#[repr(u8)]
pub enum LockActionKind {
    Unlock = 0x01,
    Lock = 0x02,
    Unlatch = 0x03,
    LockNGo = 0x04,
    LockNGoWithUnlatch = 0x05,
    FullLock = 0x06,
    FobAction1 = 0x81,
    FobAction2 = 0x82,
    FobAction3 = 0x83,
}
impl LockAction {
    pub fn new(
        lock_action: LockActionKind,
        app_id: u32,
        flags: u8,
        name_suffix: Option<&[u8; 20]>,
        nonce: &[u8; 32],
    ) -> LockAction {
        LockAction {
            lock_action,
            app_id,
            flags,
            name_suffix: name_suffix.cloned(),
            nonce: *nonce,
        }
    }
}
impl Message for LockAction {
    const CMD: command::CommandId = command::LOCK_ACTION;

    fn encode(&self, buf: &mut Vec<u8>) {
        buf.write_u8(self.lock_action.into()).unwrap();
        buf.write_u32::<LittleEndian>(self.app_id).unwrap();
        buf.write_u8(self.flags).unwrap();
        if let Some(name_suffix) = &self.name_suffix {
            buf.write_all(name_suffix).unwrap();
        }
        buf.write_all(&self.nonce).unwrap();
    }
    fn decode(_cur: &mut Cursor<&[u8]>) -> Result<Self> {
        unreachable!();
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
    log::debug!("decode_inner: {:x?}", data);
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
        return Err(anyhow::anyhow!("Unexpected extra bytes: {:x?}", remaining_slice(&cur)));
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
        .write_u16::<LittleEndian>((plain.len() + CRYPTO_SECRETBOX_MACBYTES) as u16)
        .unwrap();
    crypto::encrypt(&mut payload, &plain, &nonce, &key).unwrap();
    payload
}

pub fn decrypt<M: Message>(payload: &[u8], key: &crypto::Key) -> Result<M> {
    log::debug!("decrypting: {:x?}", payload);
    let mut cur = Cursor::new(payload);
    let mut nonce: crypto::Nonce = [0; 24];
    cur.read_exact(&mut nonce)?;
    let auth_id = cur.read_u32::<LittleEndian>()?;
    let len = cur.read_u16::<LittleEndian>()? as usize;
    let encrypted = remaining_slice(&cur);
    if len != encrypted.len() {
        return Err(anyhow::anyhow!(
            "Inconsistent length! outer: {}, inner: {}",
            len,
            encrypted.len()
        ));
    }
    let plain = crypto::decrypt(encrypted, &nonce, key)?;
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
