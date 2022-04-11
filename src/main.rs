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
        .subcommand(
            Command::new("uuid")
                .about("txc:new_uuid"),
        )
        .subcommand(
            Command::new("uuid1")
                .about("txc:new_uuid1"),
        )
        .subcommand(
            Command::new("uuid3")
                .about("txc:new_uuid3")
                .arg(arg!(-n --names <NAMES> "Names to be used in the UUID3 generation, separated by commas").default_value("foo").required(false))
                .arg(arg!(-q --quantity <QUANTITY> "How many UUID3's to ge genrated").default_value("1").required(false))
        )
        .subcommand(
            Command::new("uuid4")
                .about("txc:new_uuid4")
                .arg(arg!(-q --quantity <QUANTITY> "How many UUID4's to ge genrated").default_value("1").required(false)),
        )
        .subcommand(
            Command::new("uuid5")
                .about("txc:new_uuid5"),
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
        },
        Some((command @ ("uuid" | "uuid1" | "uuid2" | "uuid3" | "uuid4" | "uuid5"), sub_matches)) => {
            
            use uuid::Uuid;

            let q = sub_matches.value_of("quantity").unwrap().parse::<usize>().expect("Invalid number");

            match command {
                "uuid" => println!("{}", Uuid::new_v4().to_hyphenated()),
                "uuid1" => {
                    use uuid::v1::{Timestamp, Context};
                    let context = Context::new(42);
                    let ts = Timestamp::from_unix(&context, 1497624119, 1234);
                    let uuid = Uuid::new_v1(ts, &[1, 2, 3, 4, 5, 6]).expect("failed to generate UUID");
                    println!("{}", uuid.to_hyphenated())
                },
                "uuid3" => {
                    let names = sub_matches.value_of("names").unwrap().split(",").map(|s| s.to_string()).collect::<Vec<String>>();

                    if names.len() != q {
                        panic!("Invalid number of names");
                    }
                    
                    (0..q).into_iter()
                        .map(|i| Uuid::new_v3(&Uuid::NAMESPACE_DNS, names[i].as_bytes()).to_hyphenated())
                        .for_each(|uuid| println!("{}", uuid))
                },
                "uuid4" => {
                    let q = sub_matches.value_of("quantity").unwrap().parse::<usize>().expect("Invalid number");
                    (0..q).into_iter()
                        .map(|_| Uuid::new_v4().to_hyphenated())
                        .for_each(|uuid| println!("{}", uuid))
                },
                "uuid5" => println!("{}", Uuid::new_v5(&Uuid::NAMESPACE_DNS, &[1, 2, 3, 4, 5, 6]).to_hyphenated()),
                _ => {}
            }
        },
        _ => {}
    };

    Ok(())

}
