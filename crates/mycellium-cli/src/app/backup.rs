//! CLI backup and local-data lifecycle commands.
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
    let identity = store::load_identity()?;
    // Opening the store replays any committed transaction journal before raw
    // encrypted files are collected into the bundle.
    drop(open_history(&identity)?);
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

    let backup = Backup {
        identity,
        store: entries,
    };
    mycellium_storage::atomic_write(std::path::Path::new(path), &wire::encode(&backup))
        .context("could not write backup")?;
    println!(
        "exported identity + {} store entries to {path}",
        backup.store.len()
    );
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
            "an identity already exists at {} — import into a fresh configured data directory",
            store::path().display()
        );
    }
    let bytes = std::fs::read(path).context("could not read backup")?;
    let backup: Backup = wire::decode(&bytes).map_err(|_| anyhow!("not a valid backup file"))?;

    // Authenticate and structurally validate the crown-jewel blob before any
    // destination file exists. A bad passphrase or corrupt backup leaves the
    // configured data directory untouched.
    let _identity = store::open_identity(&backup.identity)?;

    let mut names = std::collections::HashSet::new();
    for (name, _) in &backup.store {
        let valid = !name.is_empty()
            && name.len().is_multiple_of(2)
            && name.bytes().all(|byte| byte.is_ascii_hexdigit())
            && names.insert(name.clone());
        if !valid {
            bail!("backup contains an invalid or duplicate store entry name");
        }
    }

    publish_backup_tree(&store::data_dir(), &backup)?;
    println!("imported identity + {} store entries", backup.store.len());
    Ok(())
}

/// Stage the complete encrypted tree beside its destination and publish it with
/// one directory rename. A crash before rename leaves no apparent identity; a
/// retry removes the known staging directory and starts clean. A crash after
/// rename sees the complete tree.
fn publish_backup_tree(destination: &std::path::Path, backup: &Backup) -> Result<()> {
    if destination.exists() {
        let mut entries = std::fs::read_dir(destination)?;
        if entries.next().transpose()?.is_some() {
            bail!("data directory '{}' is not empty", destination.display());
        }
        std::fs::remove_dir(destination)?;
    }
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    mycellium_storage::create_private_dir(parent)?;
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("invalid data directory"))?;
    let staging = parent.join(format!(".{name}.import-staging"));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }

    let result = (|| -> Result<()> {
        let history = staging.join("history");
        mycellium_storage::create_private_dir(&history)?;
        mycellium_storage::atomic_write(&staging.join("identity.enc"), &backup.identity)?;
        for (name, data) in &backup.store {
            mycellium_storage::atomic_write(&history.join(name), data)?;
        }
        std::fs::File::open(&history)?.sync_all()?;
        std::fs::File::open(&staging)?.sync_all()?;
        std::fs::rename(&staging, destination)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&staging);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_tree_is_published_as_one_complete_directory() {
        let parent =
            std::env::temp_dir().join(format!("mycellium-backup-publish-{}", std::process::id()));
        let destination = parent.join("account");
        let staging = parent.join(".account.import-staging");
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("partial"), b"old failed import").unwrap();
        let backup = Backup {
            identity: b"sealed identity".to_vec(),
            store: vec![("00ff".into(), b"encrypted history".to_vec())],
        };

        publish_backup_tree(&destination, &backup).unwrap();

        assert!(!staging.exists());
        assert_eq!(
            std::fs::read(destination.join("identity.enc")).unwrap(),
            b"sealed identity"
        );
        assert_eq!(
            std::fs::read(destination.join("history/00ff")).unwrap(),
            b"encrypted history"
        );
        let _ = std::fs::remove_dir_all(parent);
    }
}
