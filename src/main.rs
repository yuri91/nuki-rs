mod nuki;
mod command;
mod message;
mod crc;
mod crypto;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();
    let nuki = if let Ok(auth) = std::fs::read_to_string("auth.json") {
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
    Ok(())
}
