use dryoc::classic::crypto_core::{crypto_scalarmult, crypto_core_hsalsa20};
use dryoc::classic::crypto_secretbox::{crypto_secretbox_keygen, crypto_secretbox_easy, crypto_secretbox_open_easy};
use dryoc::classic::crypto_box::crypto_box_keypair;
use dryoc::constants::CRYPTO_SECRETBOX_MACBYTES;
use dryoc::types::NewByteArray;

pub use dryoc::classic::crypto_secretbox::{Key, Nonce};
pub use dryoc::classic::crypto_box::{PublicKey, SecretKey};

pub fn gen_key() -> Key {
    crypto_secretbox_keygen()
}

pub fn gen_nonce() -> Nonce {
    Nonce::gen()
}

pub fn gen_keypair() -> (PublicKey, SecretKey) {
    crypto_box_keypair()
}

pub fn dh1(local_priv: &SecretKey, remote_pub: &PublicKey) -> Key {
    let mut ret = [0; 32];
    crypto_scalarmult(&mut ret, local_priv, remote_pub);
    ret
}

pub fn kdf1(dh1: &Key) -> Key {
    let _0 = [0; 16];
    let mut ret = [0; 32];
    crypto_core_hsalsa20(&mut ret, &_0, dh1, None);
    ret
}

pub fn h1<'a>(data: impl IntoIterator<Item=&'a [u8]>, key: &Key) -> [u8; 32] {
    let mut hmac = hmac_sha256::HMAC::new(key);
    for d in data {
        hmac.update(d);
    }
    hmac.finalize()
}

pub fn get_shared_key(local_priv: &SecretKey, remote_pub: &PublicKey) -> Key {
    kdf1(&dh1(local_priv, remote_pub))
}

pub fn encrypt(buf: &mut Vec<u8>, message: &[u8], nonce: &Nonce, key: &Key) -> anyhow::Result<()> {
    let start = buf.len();
    buf.resize(start + message.len() + CRYPTO_SECRETBOX_MACBYTES, 0);
    let cyphertext = &mut buf[start..];
    crypto_secretbox_easy(cyphertext, message, nonce, key)?;
    Ok(())
}

pub fn decrypt(ciphertext: &[u8], nonce: &Nonce, key: &Key) -> anyhow::Result<Vec<u8>> {
    let mut msg = vec![0; ciphertext.len() - CRYPTO_SECRETBOX_MACBYTES];
    crypto_secretbox_open_easy(&mut msg, ciphertext, nonce, key)?;
    Ok(msg)
}
