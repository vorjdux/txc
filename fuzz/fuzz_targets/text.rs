//! Every parser of text a person or an import gives, on arbitrary input.
#![no_main]

use libfuzzer_sys::fuzz_target;
use txc::vault::import::{Format, read};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = txc::vault::totp::code(text, 1_700_000_000);
    let _ = txc::vault::model::origin_for_display(text);
    let _ = txc::vault::model::displayable(text);
    let _ = txc::vault::slip39::share_value(text);
    let _ = txc::vault::template::parse(text);
    let _ = txc::vault::authority::normalize_card(text);
    for format in [Format::Bitwarden, Format::Csv, Format::Env] {
        let _ = read(format, text);
    }
});
