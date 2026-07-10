//! CLI formatting and message-building helpers.
#![allow(clippy::too_many_arguments)]
use super::*;

/// This account's own display name. When set, it is the free-form name others
/// see; when empty, the handle itself is used.
pub fn own_name() -> String {
    store::display_name()
}

/// The display name to publish in a record for `handle` — the account's set
/// name if any, else the identifier string.
pub fn display_name_for(handle: &Handle) -> String {
    let name = own_name();
    if name.is_empty() {
        handle.as_str().to_string()
    } else {
        name
    }
}

/// Open the encrypted local history store for this identity.
pub fn open_history(identity: &Identity) -> Result<FileStore> {
    FileStore::open(store::data_dir().join("history"), identity.storage_key())
        .context("could not open local history store")
}

/// Truncate a preview string to a readable length.
pub fn preview(text: &str) -> String {
    let text: String = text.chars().take(48).collect();
    text
}

pub use mycellium_engine::wireops::hex;

/// A short random message id (native).
pub fn random_id() -> String {
    mycellium_engine::wireops::random_id(&mut OsPlatform)
}

/// Parse a duration like `30s`, `10m`, `1h`, `7d` into seconds.
pub fn parse_duration(s: &str) -> Result<u64> {
    let s = s.trim();
    let (num, mult) = if let Some(n) = s.strip_suffix('s') {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = s.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = s.strip_suffix('d') {
        (n, 86400)
    } else {
        (s, 1)
    };
    let value: u64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid duration '{s}' (use e.g. 30s, 10m, 1h, 7d)"))?;
    Ok(value * mult)
}

/// Maximum attachment size (kept small since attachments ride inline).
const MAX_ATTACHMENT: usize = 256 * 1024;

/// Build a message from the `send`/`group send` flags.
#[allow(clippy::too_many_arguments)]
pub fn build_message(
    message: Option<&str>,
    reply_to: Option<&str>,
    react: Option<&str>,
    to: Option<&str>,
    file: Option<&str>,
    edit: Option<&str>,
    delete: Option<&str>,
    expires_at: Option<u64>,
) -> Result<AppMessage> {
    let body = if let Some(target) = delete {
        Body::Delete {
            to: target.to_string(),
        }
    } else if let Some(target) = edit {
        let text = message.ok_or_else(|| anyhow!("--edit requires --message"))?;
        Body::Edit {
            to: target.to_string(),
            text: text.to_string(),
        }
    } else if let Some(path) = file {
        let data = std::fs::read(path).with_context(|| format!("could not read '{path}'"))?;
        if data.len() > MAX_ATTACHMENT {
            bail!("file too large (max {} KiB)", MAX_ATTACHMENT / 1024);
        }
        let name = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file")
            .to_string();
        Body::File {
            mime: guess_mime(&name),
            name,
            data,
        }
    } else if let Some(emoji) = react {
        let to = to.ok_or_else(|| anyhow!("--react requires --to <message-id>"))?;
        Body::Reaction {
            to: to.to_string(),
            emoji: emoji.to_string(),
        }
    } else if let Some(target) = reply_to {
        let text = message.ok_or_else(|| anyhow!("--reply-to requires --message"))?;
        Body::Reply {
            to: target.to_string(),
            text: text.to_string(),
        }
    } else {
        Body::Text(
            message
                .ok_or_else(|| anyhow!("--message is required"))?
                .to_string(),
        )
    };
    Ok(AppMessage {
        id: random_id(),
        timestamp: OsPlatform.now_unix_secs(),
        expires_at,
        body,
    })
}

/// Resolve an expiry timestamp for a conversation `key`: an explicit `--expire`
/// duration, else the stored per-conversation default, else none.
pub fn resolve_expiry(fs: &FileStore, key: &str, expire: Option<&str>) -> Result<Option<u64>> {
    let ttl = match expire {
        Some(dur) => Some(parse_duration(dur)?),
        None => expiry::get(fs, key)?,
    };
    Ok(ttl.map(|secs| OsPlatform.now_unix_secs() + secs))
}

/// A best-effort MIME type from a file name's extension.
pub fn guess_mime(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    let mime = match ext.as_str() {
        "txt" | "md" => "text/plain",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "pdf" => "application/pdf",
        "json" => "application/json",
        _ => "application/octet-stream",
    };
    mime.to_string()
}

/// Save an attachment to the configured downloads directory (name sanitized to a
/// basename).
pub fn save_attachment(name: &str, data: &[u8]) -> Result<std::path::PathBuf> {
    let dir = store::data_dir().join("downloads");
    save_attachment_in(&dir, name, data)
}

/// Save `data` under a sanitized basename in `dir`, **never overwriting**: if the
/// name is taken, append " (n)" until a free name is found (and `create_new` so a
/// race can't clobber an existing file either).
fn save_attachment_in(
    dir: &std::path::Path,
    name: &str,
    data: &[u8],
) -> Result<std::path::PathBuf> {
    use std::io::Write;
    let safe = std::path::Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("file");
    std::fs::create_dir_all(dir)?;
    let (stem, ext) = match safe.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (safe.to_string(), String::new()),
    };
    for n in 0..10_000 {
        let candidate = if n == 0 {
            dir.join(safe)
        } else {
            dir.join(format!("{stem} ({n}){ext}"))
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut f) => {
                f.write_all(data)?;
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("too many attachments named '{safe}'")
}

#[cfg(test)]
mod tests {
    use super::save_attachment_in;

    #[test]
    fn attachments_never_overwrite() {
        let dir = std::env::temp_dir().join(format!("myc-attach-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // Path traversal is stripped to a basename.
        let p0 = save_attachment_in(&dir, "../../etc/passwd", b"a").unwrap();
        assert_eq!(p0.file_name().unwrap(), "passwd");

        // Same name twice → distinct files, both preserved.
        let p1 = save_attachment_in(&dir, "pic.png", b"first").unwrap();
        let p2 = save_attachment_in(&dir, "pic.png", b"second").unwrap();
        assert_ne!(p1, p2);
        assert_eq!(p1.file_name().unwrap(), "pic.png");
        assert_eq!(p2.file_name().unwrap(), "pic (1).png");
        assert_eq!(std::fs::read(&p1).unwrap(), b"first");
        assert_eq!(std::fs::read(&p2).unwrap(), b"second");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
