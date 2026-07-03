#![allow(clippy::too_many_arguments)]
use super::*;

pub fn announce(whoami: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let me = Handle::new(whoami).map_err(|_| anyhow!("invalid --as handle"))?;
    let client = DirectoryClient::new(directory);
    let token = client.login(&identity)?;
    client.announce(&token, &me)?;
    println!("announced '{}' online", me.as_str());
    Ok(())
}



pub fn verify(peer: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let client = DirectoryClient::new(directory);
    let (peer_handle, peer_record) = lookup_verified(&client, &fs, peer)?;
    let sn = safety::safety_number(&identity.wallet_public(), &peer_record.record.wallet);
    println!("safety number with '{}': {sn}", peer_handle.as_str());
    println!("compare it with them out of band — if it matches, no one is impersonating either of you.");
    Ok(())
}



pub fn presence(peer: &str, directory: &str) -> Result<()> {
    let identity = store::load_identity()?;
    let fs = open_history(&identity)?;
    let handle_str = contacts::resolve(&fs, peer)?;
    let handle = Handle::new(handle_str).map_err(|_| anyhow!("invalid handle or nickname"))?;
    let client = DirectoryClient::new(directory);
    let online = client.presence(&handle)?;
    println!("{} is {}", handle.as_str(), if online { "online" } else { "offline" });
    Ok(())
}



/// Resolve a nickname to a handle (or pass a raw handle through), then verify
/// the record matches any pinned wallet for that contact (TOFU).
pub fn lookup_verified(
    client: &DirectoryClient,
    fs: &FileStore,
    input: &str,
) -> Result<(Handle, SignedRecord)> {
    let resolved = contacts::resolve(fs, input)?;
    let handle = Handle::new(resolved).map_err(|_| anyhow!("invalid handle or nickname"))?;
    let record = client.lookup(&handle)?;
    record
        .verify()
        .map_err(|_| anyhow!("peer's record failed verification"))?;

    if let Some(contact) = contacts::by_handle(fs, handle.as_str())? {
        if contact.wallet != record.record.wallet {
            bail!(
                "'{}' identity CHANGED since you added it — refusing (possible impersonation)",
                handle.as_str()
            );
        }
    }
    Ok((handle, record))
}
