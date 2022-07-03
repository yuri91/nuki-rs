use crate::command;
use crate::message;
use crate::crypto;
use btleplug::api::{
    Central, Manager as _, Peripheral as _, ScanFilter, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use btleplug::api::Characteristic;
use futures::stream::{Stream, StreamExt};
use std::pin::Pin;
use uuid::Uuid;
use std::cell::RefCell;
use byteorder::{LittleEndian, WriteBytesExt};

use anyhow::Result;

type NotificationStream = Pin<Box<dyn Stream<Item = btleplug::api::ValueNotification> + Send>>;

const KEYTURNER_PAIRING_GDIO: Uuid = Uuid::from_bytes([
    0xa9, 0x2e, 0xe1, 0x01, 0x55, 0x01, 0x11, 0xe4, 0x91, 0x6c, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66,
]);

pub struct Nuki {
    p: Peripheral,
    stream: RefCell<NotificationStream>,
    keyturner_pairing: Characteristic,
}
impl Nuki {
    pub async fn new() -> Result<Nuki> {
        let manager = Manager::new().await?;

        // get the first bluetooth adapter
        let adapters = manager.adapters().await?;
        let central = adapters
            .into_iter().next()
            .ok_or_else(|| anyhow::anyhow!("cannot find adapter"))?;

        let mut events = central.events().await?;
        // start scanning for devices
        central.start_scan(ScanFilter::default()).await?;

        // Wait for nuki to be discovered
        let p = wait_for_nuki(&central, &mut events).await?;

        // connect to the device
        p.connect().await?;

        // discover services and characteristics
        p.discover_services().await?;

        // find the characteristic we want
        let chars = p.characteristics();
        let keyturner_pairing = chars
            .iter()
            .find(|c| c.uuid == KEYTURNER_PAIRING_GDIO)
            .ok_or_else(|| anyhow::anyhow!("cannot find Keyturner Pairing Service GDIO"))?
            .clone();
        println!("{:?}", keyturner_pairing);
        p.subscribe(&keyturner_pairing).await?;
        let stream = RefCell::new(p.notifications().await?);
        Ok(Nuki {
            p,
            stream,
            keyturner_pairing
        })
    }
    pub async fn pair(&mut self) -> Result<()> {
        let (pubkey, privkey) = crypto::gen_keypair(); 

        let req = message::RequestData::new(command::PUBLIC_KEY);
        let reply: message::PublicKey = self.send(&self.keyturner_pairing, &req).await?;

        let nuki_pubkey = reply.key;
        let shared_key = crypto::get_shared_key(&privkey, &nuki_pubkey);

        let req = message::PublicKey::new(pubkey);
        let resp: message::Challenge = self.send(&self.keyturner_pairing, &req).await?;

        let nonce_nuki = resp.nonce;
        let authenticator = crypto::h1([&pubkey[..], &nuki_pubkey[..], &nonce_nuki[..]], &shared_key);

        let req = message::AuthorizationAuthenticator::new(&authenticator);
        let resp: message::Challenge = self.send(&self.keyturner_pairing, &req).await?;

        let id_type = 0u8;
        let app_id = 0xc0febabeu32;
        let mut app_id_bytes = Vec::new();
        app_id_bytes.write_u32::<LittleEndian>(app_id).unwrap();
        let name = b"rustynuke";
        let mut name_bytes = [0u8; 32];
        name_bytes[0..name.len()].copy_from_slice(name);
        let nonce = crypto::gen_key();
        let nonce_nuki2 = resp.nonce;
        let authenticator = crypto::h1([&[id_type], &app_id_bytes[..], &name_bytes[..], &nonce[..], &nonce_nuki2[..]], &shared_key);

        let req = message::AuthorizationData::new(&authenticator, id_type, app_id, &name_bytes, &nonce);
        let resp: message::AuthorizationId = self.send(&self.keyturner_pairing, &req).await?;

        // TODO: check authenticator consistency
        let auth_id = resp.auth_id;

        let nonce_nuki3 = resp.nonce;
        let mut auth_id_bytes = Vec::new();
        auth_id_bytes.write_u32::<LittleEndian>(auth_id).unwrap();
        let authenticator = crypto::h1([&auth_id_bytes[..], &nonce_nuki3[..]], &shared_key);

        let req = message::AuthorizationIdComfirmation::new(&authenticator, auth_id);
        let resp: message::Status = self.send(&self.keyturner_pairing, &req).await?;

        println!("status: {:?}", resp.status);
        Ok(())
    }

    async fn send<REP: message::Message, REQ: message::Message>(&self, char: &Characteristic, r: &REQ) -> Result<REP> {
        println!("sending: {:?}", r);
        let buf = message::encode(r);
        self.p.write(char, &buf, WriteType::WithResponse).await?;
        let data = self.wait_for_notification(char).await?;
        let reply = message::decode(&data)?;
        println!("received: {:?}", reply);
        Ok(reply)
    }
    async fn wait_for_notification(
        &self,
        char: &Characteristic,
    ) -> anyhow::Result<Vec<u8>> {
        let mut stream = self.stream.borrow_mut();
        while let Some(n) = stream.next().await {
            if n.uuid == char.uuid {
                return Ok(n.value);
            } else {
                log::debug!("Ignored notification: {:?}", n);
            }
        }
        return Err(anyhow::anyhow!("Unexpected stream end"));
    }
}

type CentralStream =Pin<Box<dyn Stream<Item = btleplug::api::CentralEvent> + Send>>;
async fn wait_for_nuki(central: &Adapter, events: &mut CentralStream) -> Result<Peripheral> {
    while let Some(event) = events.next().await {
        match event {
            btleplug::api::CentralEvent::DeviceDiscovered(id) => {
                log::debug!("DeviceDiscovered: {:?}", id);
                let p = central.peripheral(&id).await?;
                if let Some(name) = p.properties()
                    .await?
                    .map(|props| props.local_name)
                    .flatten()
                {
                    if name == "Nuki_2E5F0EFC" {
                        log::debug!("Found nuki: {:?}", p);
                        return Ok(p);
                    }
                }
            }
            _ => {}
        }
    }
    Err(anyhow::anyhow!("Cannot find nuki adapter"))
}
