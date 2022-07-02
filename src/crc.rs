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
