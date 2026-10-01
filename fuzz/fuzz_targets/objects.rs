//! Every decoder of what a device reads from the folder, on arbitrary
//! bytes: none may panic, whatever a hostile folder holds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use txc::vault::authority::{
    Certificate, Genesis, IssuedCertificate, Renewal, RenewalRequest, SignedGenesis,
};
use txc::vault::control::{Checkpoint, Fact, Forward, Join, SenderKeyBody};
use txc::vault::object::Payload;

fuzz_target!(|data: &[u8]| {
    let _ = Payload::decode(data);
    let _ = Fact::decode(data);
    let _ = SenderKeyBody::decode(data);
    let _ = Join::decode(data);
    let _ = Forward::decode(data);
    let _ = Checkpoint::decode(data);
    let _ = Genesis::decode(data);
    let _ = SignedGenesis::decode(data);
    let _ = Certificate::decode(data);
    let _ = IssuedCertificate::decode(data);
    let _ = RenewalRequest::decode(data);
    let _ = Renewal::decode(data);
});
