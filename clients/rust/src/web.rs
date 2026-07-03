//! The browser PWA, embedded in the binary so the client ships as one file.

/// Look up a static asset by request path. Returns `(bytes, content-type)`.
pub fn asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    let entry: (&[u8], &str) = match path {
        "/index.html" => (include_bytes!("../web/index.html"), "text/html; charset=utf-8"),
        "/app.js" => (include_bytes!("../web/app.js"), "text/javascript; charset=utf-8"),
        "/styles.css" => (include_bytes!("../web/styles.css"), "text/css; charset=utf-8"),
        "/manifest.webmanifest" => {
            (include_bytes!("../web/manifest.webmanifest"), "application/manifest+json")
        }
        "/sw.js" => (include_bytes!("../web/sw.js"), "text/javascript; charset=utf-8"),
        "/icon.svg" => (include_bytes!("../web/icon.svg"), "image/svg+xml"),
        _ => return None,
    };
    Some(entry)
}
