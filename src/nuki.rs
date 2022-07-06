use crate::command;
use crate::message;
use crate::crypto;
use btleplug::api::{
    Central, Manager as _, Peripheral as _, ScanFilter, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use btleplug::api::Characteristic;
use futures::stream::{Stream, StreamExt};
use std::io::Write;
use std::pin::Pin;
use uuid::Uuid;
use std::cell::RefCell;
use byteorder::{LittleEndian, WriteBytesExt};
use serde::{Serialize, Deserialize};

use anyhow::Result;

type NotificationStream = Pin<Box<dyn Stream<Item = btleplug::api::ValueNotification> + Send>>;

const KEYTURNER_PAIRING_GDIO: Uuid = Uuid::from_bytes([
    0xa9, 0x2e, 0xe1, 0x01, 0x55, 0x01, 0x11, 0xe4, 0x91, 0x6c, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66,
]);
const KEYTURNER_USDIO: Uuid = Uuid::from_bytes([
    0xa9,0x2e,0xe2,0x02,0x55,0x01,0x11,0xe4,0x91,0x6c,0x08,0x00,0x20,0x0c,0x9a,0x66,
]);

struct NukiInner {
    p: Peripheral,
    stream: RefCell<NotificationStream>,
    keyturner_pairing: Characteristic,
    keyturner: Characteristic,
}
struct NukiUnpaired {
    inner: NukiInner,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct AuthState {
    pub pubkey: crypto::PublicKey,
    pub privkey: crypto::SecretKey,
    pub nuki_pubkey: crypto::PublicKey,
    pub auth_id: u32,
}
pub struct Nuki {
    auth: AuthState,
    shared_key: crypto::Key,
    inner: NukiInner,
}

impl NukiInner {
    async fn new() -> Result<NukiInner> {
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
        p.subscribe(&keyturner_pairing).await?;
        let keyturner = chars
            .iter()
            .find(|c| c.uuid == KEYTURNER_USDIO)
            .ok_or_else(|| anyhow::anyhow!("cannot find Keyturner Service USDIO"))?
            .clone();
        p.subscribe(&keyturner).await?;
        let stream = RefCell::new(p.notifications().await?);
        Ok(NukiInner {
            p,
            stream,
            keyturner_pairing,
            keyturner,
        })
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
impl NukiUnpaired {
    async fn send<REP: message::Message, REQ: message::Message>(&self, r: &REQ) -> Result<REP> {
        let buf = message::encode(r);
        self.inner.p.write(&self.inner.keyturner_pairing, &buf, WriteType::WithResponse).await?;
        let data = self.inner.wait_for_notification(&self.inner.keyturner_pairing).await?;
        let reply = message::decode(&data)?;
        Ok(reply)
    }

    async fn new() -> Result<NukiUnpaired> {
        let inner = NukiInner::new().await?;
        Ok(NukiUnpaired {
            inner
        })
    }

    async fn pair(self) -> Result<Nuki> {
        let (pubkey, privkey) = crypto::gen_keypair(); 

        let req = message::RequestData::new(command::PUBLIC_KEY);
        let reply: message::PublicKey = self.send(&req).await?;

        let nuki_pubkey = reply.key;
        let shared_key = crypto::get_shared_key(&privkey, &nuki_pubkey);

        let req = message::PublicKey::new(pubkey);
        let resp: message::Challenge = self.send(&req).await?;

        let nonce_nuki = resp.nonce;
        let authenticator = crypto::h1([&pubkey[..], &nuki_pubkey[..], &nonce_nuki[..]], &shared_key);

        let req = message::AuthorizationAuthenticator::new(&authenticator);
        let resp: message::Challenge = self.send(&req).await?;

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
        let resp: message::AuthorizationId = self.send(&req).await?;

        // TODO: check authenticator consistency
        let auth_id = resp.auth_id;

        let nonce_nuki3 = resp.nonce;
        let mut auth_id_bytes = Vec::new();
        auth_id_bytes.write_u32::<LittleEndian>(auth_id).unwrap();
        let authenticator = crypto::h1([&auth_id_bytes[..], &nonce_nuki3[..]], &shared_key);

        let req = message::AuthorizationIdComfirmation::new(&authenticator, auth_id);
        let resp: message::Status = self.send(&req).await?;

        if resp.status != message::StatusKind::Complete {
            return Err(anyhow::anyhow!("Unexpected final status: ACCEPTED"));
        }
        Ok(Nuki {
            auth: AuthState {
                pubkey,
                privkey,
                nuki_pubkey,
                auth_id,
            },
            shared_key,
            inner: self.inner,
        })
    }
}

impl Nuki {
    pub async fn pair() -> Result<Nuki> {
        let nuki = NukiUnpaired::new().await?;
        nuki.pair().await
    }
    pub async fn with_auth(auth: AuthState) -> Result<Nuki> {
        let inner = NukiInner::new().await?;
        let shared_key = crypto::get_shared_key(&auth.privkey, &auth.nuki_pubkey);
        Ok(Nuki {
            auth,
            shared_key,
            inner
        })
    }
    pub fn get_auth(&self) -> AuthState {
        self.auth.clone()
    }

    async fn send<REP: message::Message, REQ: message::Message>(&self, r: &REQ) -> Result<REP> {
        let buf = message::encrypt(r, self.auth.auth_id, &self.shared_key);
        self.inner.p.write(&self.inner.keyturner, &buf, WriteType::WithResponse).await?;
        let data = self.inner.wait_for_notification(&self.inner.keyturner).await?;
        let reply = message::decrypt(&data, &self.shared_key)?;
        Ok(reply)
    }
    pub async fn read_keyturner_states(&self) -> Result<message::KeyturnerStates> {
        let req = message::RequestData::new(command::KEYTURNER_STATES);
        let resp: message::KeyturnerStates = self.send(&req).await?;

        Ok(resp)
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
