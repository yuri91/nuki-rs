use crate::command;
use crate::message;
use btleplug::api::{
    Central, Manager as _, Peripheral as _, ScanFilter, WriteType,
};
use btleplug::platform::{Adapter, Manager, Peripheral};
use btleplug::api::Characteristic;
use futures::stream::{Stream, StreamExt};
use std::pin::Pin;
use uuid::Uuid;
use std::time::Duration;
use std::cell::RefCell;
use tokio::time;

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
        let req = message::RequestData::new(command::PUBLIC_KEY);
        let reply = self.send(&self.keyturner_pairing, &req).await?;
        println!("pkey: {:x?}", reply);
        Ok(())
    }

    async fn send<R: message::Request>(&self, char: &Characteristic, r: &R) -> Result<message::Reply> {
        let buf = message::encode(r);
        self.p.write(char, &buf, WriteType::WithResponse).await?;
        let data = self.wait_for_notification(char).await?;
        let reply = message::decode(&data)?;
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
