mod nuki;
mod command;
mod message;
mod crc;
mod crypto;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let mut n = nuki::Nuki::new().await?;
    n.pair().await?;
    Ok(())
}
