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

mod nuki;
mod command;
mod message;
mod crc;
mod crypto;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();
    let mut nuki = if let Ok(auth) = std::fs::read_to_string("auth.json") {
        println!("already authenticated");
        let auth = serde_json::from_str(&auth)?;
        nuki::Nuki::with_auth(auth).await?
    } else {
        println!("pairing...");
        let n = nuki::Nuki::pair().await?;
        let auth = n.get_auth();
        let dump = serde_json::to_string(&auth)?;
        std::fs::write("auth.json", dump)?;
        n
    };
    let states = nuki.read_keyturner_states().await?;
    println!("{:?}", states);
    nuki.lock_action(message::LockActionKind::Unlock).await?;
    Ok(())
}
