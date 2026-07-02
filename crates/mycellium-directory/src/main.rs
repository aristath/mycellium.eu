//! The directory binary — a thin wrapper over [`mycellium_directory::serve`].

fn main() {
    let addr = std::env::var("MYCELLIUM_DIRECTORY_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    println!("mycellium-directory listening on http://{addr}");
    if let Err(err) = mycellium_directory::serve(&addr) {
        eprintln!("mycellium-directory failed: {err}");
        std::process::exit(1);
    }
}
