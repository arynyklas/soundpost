mod toolchain;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.split_first() {
        Some((cmd, rest)) if cmd == "toolchain" => match toolchain::run(rest) {
            Ok(line) => println!("{line}"),
            Err(err) => {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        },
        _ => println!("usage: cargo xtask <command>\n  toolchain verify"),
    }
}
