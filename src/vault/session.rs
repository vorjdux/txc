//! Sessions: one unlock, then any number of commands without the passphrase.
//!
//! Deriving the key from the passphrase costs about a second on purpose, and
//! paying it on every `txc vault copy` makes the vault tiresome enough that
//! people start keeping secrets elsewhere. A session pays it once.
//!
//! Nothing listens and nothing stays running. `txc vault unlock` seals the
//! unlocked identity under a random session key and writes that blob to a
//! private, per-user directory; the session key itself is kept where only this
//! login can reach it:
//!
//! - **Linux:** the kernel session keyring, readable only by processes that
//!   possess that keyring (the processes of this login), with a timeout.
//! - **macOS:** the login Keychain.
//! - **Windows:** the key is sealed with DPAPI inside the blob itself, and the
//!   blob is bound to this logon session.
//!
//! A session ends when it has been idle for too long, when it reaches its
//! absolute limit, when the computer has slept since it started (checked on
//! the next use, from the gap between a clock that counts suspend and one that
//! does not), or with `txc vault lock`. It never contains the write key, so a
//! session can read and copy but a change still asks for the write passphrase.

// The one module besides `harden` allowed to call the operating system
// directly: the kernel keyring, the Keychain and DPAPI have no safe wrapper
// in the standard library. Every call is on a buffer this module owns.
#![allow(unsafe_code)]
// Header fields are fixed-size integers read from a buffer whose length is
// checked first, and every offset is bounded by the blob's read limit.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
// A session that does not open is reported as ended, never with the
// cipher's own error, so map_err discards the source on purpose here.
#![allow(clippy::map_err_ignore)]

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use age::secrecy::ExposeSecret;
use anyhow::{Context, Result, anyhow, bail, ensure};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::vault::crypto::{self, Identity};
use crate::vault::home::{self, Home, PRIVATE};

/// A session ends after this long without use, unless asked otherwise.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(15 * 60);
/// A session ends after this long whatever happens, unless asked otherwise.
pub const DEFAULT_MAX: Duration = Duration::from_secs(8 * 60 * 60);
/// The longest a session may be asked to last.
pub const LONGEST_MAX: Duration = Duration::from_secs(24 * 60 * 60);

const VERSION: u8 = 2;
const HEADER_LEN: usize = 1 + 8 * 5;
const NONCE_LEN: usize = 24;
const BLOB_LIMIT: usize = 64 * 1024;
/// Clocks drift apart by a few milliseconds without any sleep; a real
/// suspend is seconds at the least.
const SLEEP_SLACK_MS: u64 = 3_000;

/// What a session holds: the identity of today's vaults, and the
/// key-encryption key of each synced vault the passphrase opened.
#[derive(Default)]
pub struct Contents {
    /// The identity, when this home has one.
    pub identity: Option<Identity>,
    /// Each synced vault's key-encryption key, by name.
    pub synced: std::collections::BTreeMap<String, Zeroizing<[u8; 32]>>,
}

impl Contents {
    /// One line per item: `identity AGE-SECRET-KEY-...` and
    /// `synced NAME HEX`; names never hold spaces or line breaks.
    fn encode(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::new());
        if let Some(identity) = &self.identity {
            text.push_str("identity ");
            text.push_str(identity.to_string().expose_secret());
            text.push('\n');
        }
        for (name, kek) in &self.synced {
            text.push_str("synced ");
            text.push_str(name);
            text.push(' ');
            text.push_str(&data_encoding::HEXLOWER.encode(&kek[..]));
            text.push('\n');
        }
        text
    }

    fn decode(text: &str) -> Result<Self> {
        let mut contents = Self::default();
        for line in text.lines() {
            match line.split_once(' ') {
                Some(("identity", identity)) => {
                    contents.identity = Some(crypto::parse_identity(identity)?);
                }
                Some(("synced", rest)) => {
                    let (name, hex) = rest
                        .split_once(' ')
                        .context("the session file is damaged")?;
                    let bytes = Zeroizing::new(
                        data_encoding::HEXLOWER
                            .decode(hex.as_bytes())
                            .map_err(|_| anyhow!("the session file is damaged"))?,
                    );
                    let kek = <[u8; 32]>::try_from(bytes.as_slice())
                        .map_err(|_| anyhow!("the session file is damaged"))?;
                    contents.synced.insert(name.to_owned(), Zeroizing::new(kek));
                }
                _ => bail!("the session file is damaged"),
            }
        }
        Ok(contents)
    }
}

/// What `resume` found.
pub enum Resumed {
    /// The session is open: here is what it holds.
    Open(Contents),
    /// There was a session, and it ended for this reason.
    Ended(&'static str),
    /// There is no session.
    None,
}

/// How long a session is left, for `txc vault unlock` to report.
pub struct Opened {
    /// How long the session may sit unused before it ends.
    pub idle: Duration,
    /// How long the session lasts at most.
    pub max: Duration,
}

struct Header {
    created: u64,
    expires: u64,
    idle: u64,
    sleep_gap_ms: u64,
    binding: u64,
}

impl Header {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0; HEADER_LEN];
        out[0] = VERSION;
        for (i, value) in [
            self.created,
            self.expires,
            self.idle,
            self.sleep_gap_ms,
            self.binding,
        ]
        .into_iter()
        .enumerate()
        {
            let at = 1 + i * 8;
            out[at..at + 8].copy_from_slice(&value.to_be_bytes());
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= HEADER_LEN && bytes[0] == VERSION,
            "unknown session format"
        );
        let field = |i: usize| {
            let at = 1 + i * 8;
            let mut word = [0; 8];
            word.copy_from_slice(&bytes[at..at + 8]);
            u64::from_be_bytes(word)
        };
        Ok(Self {
            created: field(0),
            expires: field(1),
            idle: field(2),
            sleep_gap_ms: field(3),
            binding: field(4),
        })
    }
}

/// A stable name for the sessions of one vault home.
fn session_id(home: &Home) -> String {
    let root = std::fs::canonicalize(home.root()).unwrap_or_else(|_| home.root().to_path_buf());
    let digest = crypto::sha256(&[root.to_string_lossy().as_bytes()]);
    data_encoding::HEXLOWER.encode(&digest[..16])
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn paths(id: &str) -> Result<(PathBuf, PathBuf)> {
    let dir = platform::session_dir()?;
    Ok((
        dir.join(format!("{id}.session")),
        dir.join(format!("{id}.used")),
    ))
}

/// Opens a session for this home with the identity already unlocked.
///
/// # Errors
///
/// Returns an error when this system offers no place to keep a session key.
pub fn start(home: &Home, contents: &Contents, idle: Duration, max: Duration) -> Result<Opened> {
    ensure!(
        !idle.is_zero() && !max.is_zero(),
        "a session must last some time"
    );
    ensure!(
        max <= LONGEST_MAX,
        "a session lasts at most {} hours",
        LONGEST_MAX.as_secs() / 3600
    );
    let idle = idle.min(max);
    let id = session_id(home);
    let (blob_path, used_path) = paths(&id)?;

    let created = now();
    let header = Header {
        created,
        expires: created.saturating_add(max.as_secs()),
        idle: idle.as_secs(),
        sleep_gap_ms: platform::sleep_gap_ms(),
        binding: platform::binding(),
    }
    .encode();

    let key = crypto::random_key();
    let embedded = platform::seal_key(&id, &key, idle)?;
    let mut nonce = [0; NONCE_LEN];
    rand::fill(&mut nonce[..]);
    let secret = contents.encode();
    let aad = [&header[..], id.as_bytes()].concat();
    let sealed = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| anyhow!("the session key has the wrong length"))?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: secret.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("cannot seal the session"))?;

    let embedded_len =
        u16::try_from(embedded.len()).context("the sealed session key is too large")?;
    let mut blob = Vec::with_capacity(HEADER_LEN + 2 + embedded.len() + NONCE_LEN + sealed.len());
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&embedded_len.to_be_bytes());
    blob.extend_from_slice(&embedded);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&sealed);

    home::write_atomic(&blob_path, &blob, None)?;
    home::write_atomic(&used_path, &created.to_be_bytes(), None)?;
    Ok(Opened { idle, max })
}

/// Picks up the session for this home, if one is open, and counts this as a
/// use. A session that has expired, sat idle too long, or outlived a sleep is
/// ended here.
///
/// # Errors
///
/// Returns an error only when a session file exists but cannot be read.
pub fn resume(home: &Home) -> Result<Resumed> {
    let id = session_id(home);
    let Ok((blob_path, used_path)) = paths(&id) else {
        return Ok(Resumed::None);
    };
    if !home::exists(&blob_path) {
        return Ok(Resumed::None);
    }
    let blob = Zeroizing::new(home::read_private(&blob_path, BLOB_LIMIT, PRIVATE)?);
    let Ok(header) = Header::decode(&blob) else {
        return Ok(end_with(&id, "it was written by another version of txc"));
    };
    let now = now();
    if now >= header.expires {
        return Ok(end_with(&id, "it reached its time limit"));
    }
    let used = home::read_private(&used_path, 64, PRIVATE)
        .ok()
        .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
        .map_or(header.created, u64::from_be_bytes);
    if now.saturating_sub(used) > header.idle {
        return Ok(end_with(&id, "it was idle for too long"));
    }
    if header.binding != platform::binding() {
        return Ok(end_with(&id, "it belongs to another login"));
    }
    if platform::sleep_gap_ms().saturating_sub(header.sleep_gap_ms) > SLEEP_SLACK_MS {
        return Ok(end_with(&id, "the computer slept since it started"));
    }

    let rest = &blob[HEADER_LEN..];
    ensure!(rest.len() >= 2, "the session file is damaged");
    let embedded_len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
    ensure!(
        rest.len() >= 2 + embedded_len + NONCE_LEN,
        "the session file is damaged"
    );
    let embedded = &rest[2..2 + embedded_len];
    let nonce = &rest[2 + embedded_len..2 + embedded_len + NONCE_LEN];
    let sealed = &rest[2 + embedded_len + NONCE_LEN..];

    let Some(key) = platform::open_key(&id, embedded, Duration::from_secs(header.idle)) else {
        return Ok(end_with(&id, "its key is gone from this login"));
    };
    let aad = [&blob[..HEADER_LEN], id.as_bytes()].concat();
    let Ok(plain) = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| ())
        .and_then(|cipher| {
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: sealed,
                        aad: &aad,
                    },
                )
                .map_err(|_| ())
        })
    else {
        return Ok(end_with(&id, "it does not open with its key"));
    };
    let plain = Zeroizing::new(plain);
    let text = std::str::from_utf8(&plain).context("the session file is damaged")?;
    let contents = Contents::decode(text)?;

    home::write_atomic(&used_path, &now.to_be_bytes(), None)?;
    Ok(Resumed::Open(contents))
}

fn end_with(id: &str, reason: &'static str) -> Resumed {
    forget(id);
    Resumed::Ended(reason)
}

fn forget(id: &str) {
    platform::forget_key(id);
    if let Ok((blob_path, used_path)) = paths(id) {
        // Best effort: a file already gone is the state we want.
        std::fs::remove_file(blob_path).ok();
        std::fs::remove_file(used_path).ok();
    }
}

/// Ends the session for this home. Returns whether there was one.
#[must_use]
pub fn end(home: &Home) -> bool {
    let id = session_id(home);
    let existed = paths(&id).is_ok_and(|(blob_path, _)| home::exists(&blob_path));
    forget(&id);
    existed
}

// ------------------------------------------------------------------ Linux --

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::CString;
    use std::io;
    use std::path::PathBuf;
    use std::time::Duration;

    use anyhow::{Context, Result, anyhow, ensure};
    use zeroize::Zeroizing;

    use crate::vault::crypto::Key;

    const KEY_SPEC_SESSION_KEYRING: libc::c_long = -3;
    const KEYCTL_REVOKE: libc::c_long = 3;
    const KEYCTL_SETPERM: libc::c_long = 5;
    const KEYCTL_SEARCH: libc::c_long = 10;
    const KEYCTL_READ: libc::c_long = 11;
    const KEYCTL_SET_TIMEOUT: libc::c_long = 15;
    /// View, read, write, search, link and set-attribute, for the possessor
    /// only: nothing for the user, group or others.
    const POSSESSOR_ALL: libc::c_long = 0x3f00_0000;

    fn description(id: &str) -> Result<CString> {
        CString::new(format!("txc-vault-session:{id}")).context("a session id has no NUL")
    }

    fn search(id: &str) -> Option<libc::c_long> {
        let kind = c"user";
        let name = description(id).ok()?;
        // SAFETY: both strings are NUL terminated and live for the call; the
        // destination keyring 0 means none.
        let found = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_SEARCH,
                KEY_SPEC_SESSION_KEYRING,
                kind.as_ptr(),
                name.as_ptr(),
                0,
            )
        };
        (found > 0).then_some(found)
    }

    pub(super) fn seal_key(id: &str, key: &Key, idle: Duration) -> Result<Vec<u8>> {
        let kind = c"user";
        let name = description(id)?;
        // SAFETY: the strings are NUL terminated and the payload pointer and
        // length describe the key buffer, all alive for the call.
        let serial = unsafe {
            libc::syscall(
                libc::SYS_add_key,
                kind.as_ptr(),
                name.as_ptr(),
                key.as_ptr(),
                key.len(),
                KEY_SPEC_SESSION_KEYRING,
            )
        };
        if serial < 0 {
            return Err(anyhow!(
                "cannot keep a session key in the kernel keyring: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: plain integer arguments on a key this process just created.
        let restricted =
            unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_SETPERM, serial, POSSESSOR_ALL) };
        ensure!(
            restricted == 0,
            "cannot restrict the session key to this login"
        );
        set_timeout(serial, idle);
        Ok(Vec::new())
    }

    fn set_timeout(serial: libc::c_long, idle: Duration) {
        let seconds = libc::c_long::try_from(idle.as_secs()).unwrap_or(libc::c_long::MAX);
        // SAFETY: plain integer arguments. A failure leaves the key without a
        // kernel timeout; the session still ends by its own idle check.
        unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_SET_TIMEOUT, serial, seconds) };
    }

    pub(super) fn open_key(id: &str, _: &[u8], idle: Duration) -> Option<Key> {
        let serial = search(id)?;
        let mut key = Zeroizing::new([0_u8; 32]);
        // SAFETY: the buffer pointer and length describe `key`, which lives for
        // the call; the kernel writes at most that many bytes.
        let read = unsafe {
            libc::syscall(
                libc::SYS_keyctl,
                KEYCTL_READ,
                serial,
                key.as_mut_ptr(),
                key.len(),
            )
        };
        if read != 32 {
            return None;
        }
        set_timeout(serial, idle);
        Some(key)
    }

    pub(super) fn forget_key(id: &str) {
        if let Some(serial) = search(id) {
            // SAFETY: plain integer arguments on a key found in this login's keyring.
            unsafe { libc::syscall(libc::SYS_keyctl, KEYCTL_REVOKE, serial) };
        }
    }

    pub(super) fn session_dir() -> Result<PathBuf> {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .filter(|value| !value.is_empty())
            .context("sessions need XDG_RUNTIME_DIR, the per-login directory kept in memory")?;
        let dir = PathBuf::from(runtime).join("txc");
        super::private_dir(&dir)?;
        Ok(dir)
    }

    fn clock_ms(clock: libc::clockid_t) -> u64 {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: the pointer is to a timespec this function owns.
        unsafe { libc::clock_gettime(clock, &raw mut time) };
        u64::try_from(time.tv_sec).unwrap_or(0) * 1000
            + u64::try_from(time.tv_nsec).unwrap_or(0) / 1_000_000
    }

    /// Boot time counts suspend and monotonic time does not, so the gap
    /// between them grows by exactly the time spent asleep.
    pub(super) fn sleep_gap_ms() -> u64 {
        clock_ms(libc::CLOCK_BOOTTIME).saturating_sub(clock_ms(libc::CLOCK_MONOTONIC))
    }

    /// The keyring is already per login and cleared at logout.
    pub(super) const fn binding() -> u64 {
        0
    }
}

// ------------------------------------------------------------------ macOS --

#[cfg(target_os = "macos")]
mod platform {
    use std::path::PathBuf;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };
    use zeroize::Zeroizing;

    use crate::vault::crypto::Key;

    const SERVICE: &str = "txc vault session";

    pub(super) fn seal_key(id: &str, key: &Key, _: Duration) -> Result<Vec<u8>> {
        delete_generic_password(SERVICE, id).ok();
        set_generic_password(SERVICE, id, &key[..])
            .context("cannot keep a session key in the Keychain")?;
        Ok(Vec::new())
    }

    pub(super) fn open_key(id: &str, _: &[u8], _: Duration) -> Option<Key> {
        let bytes = get_generic_password(SERVICE, id).ok()?;
        let bytes = Zeroizing::new(bytes);
        let array = <[u8; 32]>::try_from(bytes.as_slice()).ok()?;
        Some(Zeroizing::new(array))
    }

    pub(super) fn forget_key(id: &str) {
        delete_generic_password(SERVICE, id).ok();
    }

    pub(super) fn session_dir() -> Result<PathBuf> {
        // The per-user temporary directory, private to this user and emptied
        // at restart.
        let dir = std::env::temp_dir().join("txc-sessions");
        super::private_dir(&dir)?;
        Ok(dir)
    }

    fn clock_ms(clock: libc::clockid_t) -> u64 {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: the pointer is to a timespec this function owns.
        unsafe { libc::clock_gettime(clock, &raw mut time) };
        u64::try_from(time.tv_sec).unwrap_or(0) * 1000
            + u64::try_from(time.tv_nsec).unwrap_or(0) / 1_000_000
    }

    /// On macOS the monotonic clock counts sleep and the raw uptime clock does
    /// not, so the gap grows by the time spent asleep.
    pub(super) fn sleep_gap_ms() -> u64 {
        clock_ms(libc::CLOCK_MONOTONIC).saturating_sub(clock_ms(libc::CLOCK_UPTIME_RAW))
    }

    /// The boot time, to the minute: the Keychain outlives a restart, a
    /// session must not.
    pub(super) fn binding() -> u64 {
        let wall = super::now();
        wall.saturating_sub(clock_ms(libc::CLOCK_MONOTONIC) / 1000) / 60
    }
}

// ---------------------------------------------------------------- Windows --

#[cfg(windows)]
mod platform {
    use std::path::PathBuf;
    use std::ptr;
    use std::time::Duration;

    use anyhow::{Context, Result, anyhow};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
    };
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_QUERY, TOKEN_STATISTICS, TokenStatistics,
    };
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTime;
    use zeroize::Zeroizing;

    use crate::vault::crypto::Key;

    fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(bytes.len()).unwrap_or(0),
            pbData: bytes.as_ptr().cast_mut(),
        }
    }

    fn take(out: &CRYPT_INTEGER_BLOB) -> Zeroizing<Vec<u8>> {
        // SAFETY: DPAPI returned a buffer of cbData bytes at pbData, which is
        // copied and then released with LocalFree, as its documentation says.
        let copy = unsafe {
            std::slice::from_raw_parts(out.pbData, usize::try_from(out.cbData).unwrap_or(0))
                .to_vec()
        };
        // SAFETY: pbData was allocated by DPAPI with LocalAlloc.
        unsafe { LocalFree(out.pbData.cast()) };
        Zeroizing::new(copy)
    }

    /// The session key sealed with DPAPI, so only this user on this machine
    /// can open it; the session id is the extra entropy.
    pub(super) fn seal_key(id: &str, key: &Key, _: Duration) -> Result<Vec<u8>> {
        let input = blob(&key[..]);
        let entropy = blob(id.as_bytes());
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        // SAFETY: every pointer is to a live blob or null where optional; the
        // output is filled by DPAPI and released in `take`.
        let ok = unsafe {
            CryptProtectData(
                &raw const input,
                ptr::null(),
                &raw const entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut out,
            )
        };
        if ok == 0 {
            return Err(anyhow!("cannot seal the session key with DPAPI"));
        }
        Ok(take(&out).to_vec())
    }

    pub(super) fn open_key(id: &str, embedded: &[u8], _: Duration) -> Option<Key> {
        let input = blob(embedded);
        let entropy = blob(id.as_bytes());
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };
        // SAFETY: as in `seal_key`.
        let ok = unsafe {
            CryptUnprotectData(
                &raw const input,
                ptr::null_mut(),
                &raw const entropy,
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut out,
            )
        };
        if ok == 0 {
            return None;
        }
        let bytes = take(&out);
        let array = <[u8; 32]>::try_from(bytes.as_slice()).ok()?;
        Some(Zeroizing::new(array))
    }

    pub(super) const fn forget_key(_: &str) {}

    pub(super) fn session_dir() -> Result<PathBuf> {
        let base = std::env::var_os("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .context("sessions need LOCALAPPDATA")?;
        let dir = PathBuf::from(base).join("txc").join("sessions");
        super::private_dir(&dir)?;
        Ok(dir)
    }

    /// The tick count counts sleep and the unbiased interrupt time does not,
    /// so the gap grows by the time spent asleep.
    pub(super) fn sleep_gap_ms() -> u64 {
        let mut unbiased = 0_u64;
        // SAFETY: both calls only write to or return plain integers.
        let (ticks, ok) = unsafe {
            (
                GetTickCount64(),
                QueryUnbiasedInterruptTime(&raw mut unbiased),
            )
        };
        if ok == 0 {
            return 0;
        }
        ticks.saturating_sub(unbiased / 10_000)
    }

    /// The logon session id, so a session never crosses to another logon.
    pub(super) fn binding() -> u64 {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: the process handle is a pseudo handle; the token handle is
        // written by the call and closed below.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
            return 0;
        }
        // SAFETY: TOKEN_STATISTICS is plain data; zeroed is a valid value.
        let mut stats: TOKEN_STATISTICS = unsafe { std::mem::zeroed() };
        let mut size = 0_u32;
        // SAFETY: the buffer is `stats`, of the size passed.
        let ok = unsafe {
            GetTokenInformation(
                token,
                TokenStatistics,
                (&raw mut stats).cast(),
                u32::try_from(std::mem::size_of::<TOKEN_STATISTICS>()).unwrap_or(0),
                &raw mut size,
            )
        };
        // SAFETY: the handle was opened above.
        unsafe { CloseHandle(token) };
        if ok == 0 {
            return 0;
        }
        (u64::from(stats.AuthenticationId.HighPart.cast_unsigned()) << 32)
            | u64::from(stats.AuthenticationId.LowPart)
    }
}

// ----------------------------------------------------------------- others --

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod platform {
    use std::path::PathBuf;
    use std::time::Duration;

    use anyhow::{Result, bail};

    use crate::vault::crypto::Key;

    pub(super) fn seal_key(_: &str, _: &Key, _: Duration) -> Result<Vec<u8>> {
        bail!("sessions are not available on this system yet")
    }
    pub(super) const fn open_key(_: &str, _: &[u8], _: Duration) -> Option<Key> {
        None
    }
    pub(super) const fn forget_key(_: &str) {}
    pub(super) fn session_dir() -> Result<PathBuf> {
        bail!("sessions are not available on this system yet")
    }
    pub(super) const fn sleep_gap_ms() -> u64 {
        0
    }
    pub(super) const fn binding() -> u64 {
        0
    }
}

/// Creates a directory readable by this user alone, or checks that an
/// existing one is.
fn private_dir(dir: &std::path::Path) -> Result<()> {
    home::private_dir(dir, PRIVATE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_reads_back_what_was_written() {
        let header = Header {
            created: 1,
            expires: 2,
            idle: 3,
            sleep_gap_ms: 4,
            binding: 5,
        };
        let read = Header::decode(&header.encode()).unwrap();
        assert_eq!(
            [
                read.created,
                read.expires,
                read.idle,
                read.sleep_gap_ms,
                read.binding
            ],
            [1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn a_header_of_another_version_is_refused() {
        let mut bytes = Header {
            created: 1,
            expires: 2,
            idle: 3,
            sleep_gap_ms: 4,
            binding: 5,
        }
        .encode();
        bytes[0] = VERSION + 1;
        assert!(Header::decode(&bytes).is_err());
        assert!(Header::decode(&bytes[..10]).is_err());
    }

    #[test]
    fn a_session_must_last_some_time_and_not_for_ever() {
        let scratch = crate::vault::test_support::Scratch::new("session-limits");
        let contents = Contents {
            identity: Some(crypto::new_identity()),
            ..Contents::default()
        };
        let home = Home::at(&scratch.0);
        assert!(start(&home, &contents, Duration::ZERO, DEFAULT_MAX).is_err());
        assert!(
            start(
                &home,
                &contents,
                DEFAULT_IDLE,
                LONGEST_MAX + Duration::from_secs(1)
            )
            .is_err()
        );
    }

    #[test]
    fn contents_round_trip() {
        let mut contents = Contents {
            identity: Some(crypto::new_identity()),
            ..Contents::default()
        };
        contents
            .synced
            .insert("work".to_owned(), Zeroizing::new([7; 32]));
        contents
            .synced
            .insert("home".to_owned(), Zeroizing::new([9; 32]));
        let read = Contents::decode(&contents.encode()).unwrap();
        assert_eq!(
            read.identity
                .map(|identity| identity.to_string().expose_secret().to_owned()),
            contents
                .identity
                .map(|identity| identity.to_string().expose_secret().to_owned())
        );
        assert_eq!(read.synced.len(), 2);
        assert_eq!(*read.synced["work"], [7; 32]);
        assert!(Contents::decode("nonsense line").is_err());
        assert!(Contents::decode("").unwrap().identity.is_none());
    }
}
