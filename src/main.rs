use clap::{arg, Command};

fn cli() -> Command<'static> {
    Command::new("txc")
        .about("Text utils CLI tools")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .allow_invalid_utf8_for_external_subcommands(true)
        .subcommand(
            Command::new("ud")
                .about("txc::urlencode")
                .arg(arg!(<INPUT> "Text to be converted").required(false)),
        )
        .subcommand(
            Command::new("ud")
                .about("txc::urldecode")
                .arg(arg!(<INPUT> "Text to be converted").required(false)),
        )
        .subcommand(
            Command::new("hd")
                .about("txc::htmldecode|txc::htmlunescape")
                .arg(arg!(<INPUT> "Text to be converted").required(false)),
        )
        .subcommand(
            Command::new("he")
                .about("txc:htmlencode|txc::htmlescape")
                .arg(arg!(<INPUT> "Text to be converted").required(false)),
        )
}

fn process<I: IntoIterator<Item = String>>(strings: I, command: &str) {
    for string in strings {
        match command {
            "ue" => println!("{}", urlencoding::encode(&string)),
            "ud" => println!("{}", urlencoding::decode(&string).unwrap()),
            "he" => println!("{}", html_escape::encode_text(&string)),
            "hd" => println!("{}", html_escape::decode_html_entities(&string)),
            _ => {}
        }
    }
}

fn main() {
    let matches = cli().get_matches();

    use std::io::BufRead;

    match matches.subcommand() {
        Some((command @ ("ue" | "ud" | "he" | "hd"), sub_matches)) => {
            match sub_matches.values_of("INPUT") {
                Some(values) => process(values.map(|ln| ln.to_string()), command),
                None => process(
                    std::io::stdin().lock().lines().map(|ln| ln.unwrap()),
                    command,
                ),
            }
        }
        _ => {}
    }
}
