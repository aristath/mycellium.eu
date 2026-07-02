//! The directory binary — a thin wrapper over [`messe_directory::serve`].

fn main() {
    let addr = std::env::var("MESSE_DIRECTORY_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    println!("messe-directory listening on http://{addr}");
    if let Err(err) = messe_directory::serve(&addr) {
        eprintln!("messe-directory failed: {err}");
        std::process::exit(1);
    }
}
