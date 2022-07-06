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

use std::io::Cursor;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use crc_any::CRC;

pub fn unwrap(payload: &[u8]) -> anyhow::Result<&[u8]> {
        let (data, crc) = payload.split_at(payload.len()-2);
        let mut crc_cur = Cursor::new(crc);
        let crc = crc_cur.read_u16::<LittleEndian>()?;
        let mut crc_gen = CRC::crc16ccitt_false();
        crc_gen.digest(data);
        let crc_check = crc_gen.get_crc() as u16;
        if crc != crc_check {
                Err(anyhow::anyhow!("Wrong crc! computed: {:x}, found: {:x}", crc_check, crc))
        } else {
                Ok(data)
        }
}
pub fn wrap(data: &mut Vec<u8>) {
        let mut crc_gen = CRC::crc16ccitt_false();
        crc_gen.digest(&data);
        let crc_value = crc_gen.get_crc() as u16;
        data.write_u16::<LittleEndian>(crc_value).unwrap();
}
