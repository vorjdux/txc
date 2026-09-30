//! Every parser of data from the folder, the local files or a person,
//! given arbitrary input, fails cleanly or succeeds; none panics (study
//! section 13: no crash on hostile input). The fuzz targets under `fuzz/`
//! drive the same entry points for longer.

use proptest::prelude::*;

use crate::vault::authority::{
    Certificate, Genesis, IssuedCertificate, Renewal, RenewalRequest, SignedGenesis,
};
use crate::vault::control::{Checkpoint, Fact, Forward, Join, SenderKeyBody};
use crate::vault::object::Payload;

/// Arbitrary bytes, and arbitrary bytes after a real prefix so parsing gets
/// past the first check.
fn bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        proptest::collection::vec(any::<u8>(), 0..512),
        proptest::collection::vec(any::<u8>(), 0..512).prop_map(|mut tail| {
            let mut out = b"txc/v1/".to_vec();
            out.append(&mut tail);
            out
        }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn object_and_control_bodies_never_panic(input in bytes()) {
        let _ = Payload::decode(&input);
        let _ = Fact::decode(&input);
        let _ = SenderKeyBody::decode(&input);
        let _ = Join::decode(&input);
        let _ = Forward::decode(&input);
        let _ = Checkpoint::decode(&input);
        let _ = Genesis::decode(&input);
        let _ = SignedGenesis::decode(&input);
        let _ = Certificate::decode(&input);
        let _ = IssuedCertificate::decode(&input);
        let _ = RenewalRequest::decode(&input);
        let _ = Renewal::decode(&input);
    }

    #[test]
    fn text_a_person_or_an_import_gives_never_panics(text in ".{0,300}") {
        let _ = crate::vault::totp::code(&text, 1_700_000_000);
        let _ = crate::vault::model::origin_for_display(&text);
        let _ = crate::vault::model::mixes_scripts(&text);
        let _ = crate::vault::model::displayable(&text);
        let _ = crate::vault::slip39::share_value(&text);
        let _ = crate::vault::template::parse(&text);
        let _ = crate::vault::template::parse_setting(&text);
        let _ = crate::vault::authority::normalize_card(&text);
        for format in [
            crate::vault::import::Format::Bitwarden,
            crate::vault::import::Format::Csv,
            crate::vault::import::Format::Env,
        ] {
            let _ = crate::vault::import::read(format, &text);
        }
    }
}
