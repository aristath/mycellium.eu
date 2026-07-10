use anyhow::Result;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut data_dir = "data/registry".to_string();
    let mut dev_tcp = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            "--data-dir" => {
                data_dir = args.next().unwrap_or_else(|| {
                    eprintln!("--data-dir requires a value");
                    std::process::exit(2);
                });
            }
            "--dev-tcp" => {
                dev_tcp = Some(args.next().unwrap_or_else(|| {
                    eprintln!("--dev-tcp requires a value");
                    std::process::exit(2);
                }));
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_help();
                std::process::exit(2);
            }
        }
    }

    if let Some(addr) = dev_tcp {
        mycellium_registry::serve_tcp_dev(&addr, data_dir)
    } else {
        mycellium_registry::serve_unix(data_dir)
    }
}

fn print_help() {
    println!("Usage: mycellium-registry [--data-dir DIR]");
    println!("       mycellium-registry --dev-tcp ADDR [--data-dir DIR]");
    println!();
    println!("Options:");
    println!("  --data-dir DIR   Registry data directory [default: data/registry]");
    println!("  --dev-tcp ADDR   Explicit localhost HTTP development listener");
    println!();
    println!("Environment:");
    println!(
        "  MYCELLIUM_REGISTRY_SECRET             Required 64+ hex chars, e.g. openssl rand -hex 32"
    );
    println!();
    println!("Security:");
    println!("  Production serving uses <data-dir>/registry.sock behind a trusted HTTPS edge.");
    println!("  The edge must strip incoming client-identity headers and set its own");
    println!("  X-Mycellium-Edge-Client-Key header for registry rate limiting.");
    println!("  TCP serving is development-only and refuses all non-loopback binds.");
    println!("  Account creation requires short-lived one-time creation grants.");
}
