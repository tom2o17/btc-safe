//! TEST-ONLY offline signer for curl demos against CHAIN=memory (deterministic throwaway keys).
//!   cargo run -q -p btc-safe-testkit --example testsigner -- owners
//!   cargo run -q -p btc-safe-testkit --example testsigner -- sign <0|1|2> <psbt-base64>
#![allow(clippy::disallowed_types, clippy::disallowed_methods)]

use std::str::FromStr;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let owners = btc_safe_testkit::three_owners();
    match args.get(1).map(String::as_str) {
        Some("owners") => {
            let v: Vec<String> = owners
                .iter()
                .map(|o| format!(r#"{{"name":"{}","xpub":"{}","fingerprint":"{}","path":"m/48'/1'/0'/2'"}}"#, o.name, o.xpub, o.fingerprint))
                .collect();
            println!("[{}]", v.join(","));
        }
        Some("sign") => {
            let i: usize = args[2].parse().expect("owner index");
            let mut psbt = bitcoin::Psbt::from_str(args[3].trim()).expect("psbt");
            let n = owners[i].sign(&mut psbt);
            eprintln!("{} signed {} input(s)", owners[i].name, n);
            println!("{psbt}");
        }
        _ => eprintln!("usage: testsigner owners | testsigner sign <idx> <psbt>"),
    }
}
