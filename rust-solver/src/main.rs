mod decrypt;
mod encrypt;
mod gf16;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let result = if args.get(1).map(String::as_str) == Some("--decrypt") {
        decrypt::run()
    } else {
        encrypt::run()
    };

    if let Err(e) = result {
        eprintln!("Got error: {}", e);
        std::process::exit(1);
    }
}
