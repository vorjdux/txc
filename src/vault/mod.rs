//! A local, encrypted vault for passwords, API keys, logins and private notes.
//!
//! # How it is protected
//!
//! Everything is built from [age](https://age-encryption.org), a small, well
//! reviewed and openly specified format: X25519 for keys, ChaCha20-Poly1305
//! for data, HMAC-SHA256 and scrypt. The design is public, so its safety
//! rests entirely on keys, never on anyone not knowing how it works.
//!
//! - **The identity** is an age X25519 key stored in `identity.age`, itself
//!   encrypted with a passphrase through scrypt at N = 2^18. Opening a vault
//!   takes both the file and the passphrase.
//! - **A vault** is one age file encrypted to one or more public keys: this
//!   device, other devices, a backup key. Names, usernames and addresses are
//!   inside that encryption, so the file shows nothing but its size.
//! - **Each secret** is sealed again as an age file of its own inside the
//!   vault. Browsing a vault decrypts none of them; copying opens exactly one.
//! - **Trust.** Encryption does not say who wrote a file, and anyone with a
//!   public key can build a vault for it. Each vault therefore carries a
//!   random key that only its recipients can read, and each device pins a tag
//!   of that key along with the recipients and a generation counter, in a
//!   record authenticated with a key derived from the identity. A forged
//!   vault, a changed list of recipients and an old copy put back are all
//!   refused until trusted again on purpose.
//! - **At rest** files are written atomically, never through a link, and on
//!   Unix are readable by their owner alone and refused when another user
//!   could have changed them. Windows has no mode bits: there the default
//!   directory inside the user's profile is what keeps other users out.
//! - **In memory** keys and secrets are wiped when dropped. On Unix the
//!   process cannot write a core dump, and on Linux other processes of the
//!   same user cannot attach to it; Windows offers neither.
//! - **On the clipboard** a secret is kept out of clipboard history where the
//!   system allows, and cleared after a short time if it is still there.
//!
//! Vault files can be copied, synchronised or committed without exposing
//! anything. They can also be opened without txc: `age -d -i identity.age`
//! decrypts a vault to JSON, and each sealed value in it is base64 of another
//! age file the same identity decrypts.
//!
//! # What it does not protect against
//!
//! Malware already running as you while the vault is unlocked, a keylogger
//! reading the passphrase, and anything that reads the clipboard during the
//! seconds a secret is on it.

pub mod clipboard;
pub mod command;
mod crypto;
mod document;
mod grant;
pub mod harden;
mod home;
mod keyring;
pub mod model;
pub mod prompt;
mod recent;
mod trust;

#[cfg(debug_assertions)]
pub use crypto::TEST_WORK_FACTOR_VARIABLE;
pub(crate) use crypto::WriteKey;
pub use document::Vault;
pub use home::{HOME_VARIABLE, Home};
pub use keyring::{Change, Inspection, Keyring, NewEntry, NotTrusted, Opened};
pub use recent::{MAX_RECENT, Use, ago};
pub use trust::Standing;

/// Fixtures shared with the interface's tests.
#[cfg(test)]
pub(crate) mod test_support {
    pub use super::home::tests::Scratch;
    pub use super::keyring::tests::{PASSPHRASE, keyring};
}
