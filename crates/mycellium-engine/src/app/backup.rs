#![allow(clippy::too_many_arguments)]
use super::*;

pub fn wipe(yes: bool) -> Result<()> {
    if !yes {
        bail!("this erases ALL local data (identity + messages); re-run with --yes to confirm");
    }
    let dir = store::data_dir();
    if dir.exists() {
        std::fs::remove_dir_all(&dir).context("could not wipe data directory")?;
    }
    println!("wiped all local data");
    Ok(())
}



/// A portable backup: the encrypted identity plus every store entry. Each part
/// is already encrypted at rest — the seed is Argon2id-sealed under the identity
/// passphrase, and the history keys derive from the seed — so the bundle's
/// security rests on that passphrase rather than a separate export layer. It is
/// still a high-value collection: written 0600, with a safe-storage warning.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Backup {
    identity: Vec<u8>,
    store: Vec<(String, Vec<u8>)>,
}



pub fn export_backup(path: &str) -> Result<()> {
    // Require unlocking the identity to authorize the export.
    let _ = store::load_identity()?;
    let identity = std::fs::read(store::path()).context("could not read identity")?;

    let store_dir = store::data_dir().join("history");
    let mut entries = Vec::new();
    if store_dir.exists() {
        for entry in std::fs::read_dir(&store_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let name = entry.file_name().to_string_lossy().into_owned();
                entries.push((name, std::fs::read(entry.path())?));
            }
        }
    }

    let backup = Backup { identity, store: entries };
    std::fs::write(path, wire::encode(&backup)).context("could not write backup")?;
    // Restrict the file where the platform supports it (the bundle is a
    // high-value collection, even though every entry is already encrypted).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    println!("exported identity + {} store entries to {path}", backup.store.len());
    println!(
        "  \u{26a0} this backup's security rests entirely on your identity passphrase: the seed is\n  \
         Argon2id-sealed under it, and the history keys derive from the seed. Anyone who obtains\n  \
         BOTH this file AND your passphrase can restore your whole account — store it safely, offline."
    );
    Ok(())
}



pub fn import_backup(path: &str) -> Result<()> {
    if store::exists() {
        bail!(
            "an identity already exists at {} — import into a fresh MYCELLIUM_HOME",
            store::path().display()
        );
    }
    let bytes = std::fs::read(path).context("could not read backup")?;
    let backup: Backup = wire::decode(&bytes).map_err(|_| anyhow!("not a valid backup file"))?;

    std::fs::create_dir_all(store::data_dir())?;
    std::fs::write(store::path(), &backup.identity)?;

    let store_dir = store::data_dir().join("history");
    std::fs::create_dir_all(&store_dir)?;
    for (name, data) in &backup.store {
        // Only ever write a basename inside the store dir.
        if let Some(safe) = std::path::Path::new(name).file_name().and_then(|n| n.to_str()) {
            std::fs::write(store_dir.join(safe), data)?;
        }
    }
    println!("imported identity + {} store entries", backup.store.len());
    Ok(())
}
