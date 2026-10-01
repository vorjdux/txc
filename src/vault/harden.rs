//! Making the process a poorer target while secrets are in its memory.
//!
//! This is defence in depth rather than a boundary: a program running as
//! root, or with the right capability, can still read the memory of any
//! process. What it does stop are the ordinary leaks. A crash no longer writes
//! a core file with an unlocked key in it, and on Linux a debugger or another
//! program running as the same user can no longer attach to txc or read its
//! memory through `/proc`.

// The one module allowed to call the C library directly. Every call is a
// plain system call on a value this module owns.
#![allow(unsafe_code)]

/// Applies every protection the platform offers.
///
/// Safe to call more than once. Nothing here can fail in a way worth
/// reporting: a protection the system refuses is simply not in place, which
/// is the state the process started in.
///
/// ```
/// txc::vault::harden::process();
/// ```
// On Windows there is nothing to call, which would let this be const there.
#[cfg_attr(windows, allow(clippy::missing_const_for_fn))]
pub fn process() {
    // Read while the files it needs are still reachable.
    let _checked = swap();
    #[cfg(unix)]
    unix::no_core_dumps();
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unix::not_dumpable();
}

/// Whether other programs of the same user could inspect this process.
///
/// Only Linux can answer, which is why this exists only there.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[must_use]
pub fn is_dumpable() -> bool {
    // SAFETY: PR_GET_DUMPABLE takes no further arguments and only reads the
    // state of this process.
    unsafe { libc::prctl(libc::PR_GET_DUMPABLE) != 0 }
}

/// Locks this process's memory, now and later, so secrets are never
/// written to swap: only where the system's lock limit is large enough that
/// later allocations cannot fail for it (256 MiB or unlimited). Returns
/// whether it is locked. For the keyholder, which is small and long-lived.
#[must_use]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "macos")),
    allow(clippy::missing_const_for_fn)
)]
pub fn lock_memory() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes into the rlimit it is given, which lives
        // for the whole call.
        let read = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &raw mut limit) } == 0;
        let generous = limit.rlim_cur == libc::RLIM_INFINITY || limit.rlim_cur >= 256 << 20;
        if !read || !generous {
            return false;
        }
        // SAFETY: mlockall takes flags only and changes no memory contents.
        unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) == 0 }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        false
    }
}

/// Whether swap and the hibernation image are encrypted, as far as this
/// system says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Swap {
    /// Encrypted, in memory only, or absent.
    Safe,
    /// A swap area or hibernation target that is not encrypted.
    Unencrypted(String),
    /// This system does not say.
    Unknown,
}

/// Checks swap and the hibernation target (study section 11): on Linux,
/// every swap area and the resume device must sit on dm-crypt, or be zram;
/// macOS always encrypts swap. Worked out once, the first time it is asked,
/// which is before the process confines itself: [`process`] asks.
#[must_use]
pub fn swap() -> Swap {
    static CHECKED: std::sync::OnceLock<Swap> = std::sync::OnceLock::new();
    CHECKED.get_or_init(check_swap).clone()
}

fn check_swap() -> Swap {
    // Debug builds only: the tests say what the swap is, since CI runners
    // swap to plain files.
    #[cfg(debug_assertions)]
    match std::env::var("TXC_VAULT_TEST_SWAP").as_deref() {
        Ok("safe") => return Swap::Safe,
        Ok("unencrypted") => return Swap::Unencrypted("the swap area /test".to_owned()),
        _ => {}
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(swaps) = std::fs::read_to_string("/proc/swaps") else {
            return Swap::Unknown;
        };
        linux_swap(
            &swaps,
            std::fs::read_to_string("/sys/power/resume")
                .unwrap_or_default()
                .trim(),
        )
    }
    #[cfg(target_os = "macos")]
    {
        Swap::Safe
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Swap::Unknown
    }
}

/// Whether the block device `major:minor` is dm-crypt, or stacked on it.
#[cfg(target_os = "linux")]
fn on_dm_crypt(device: &str, depth: u8) -> Option<bool> {
    let base = std::path::Path::new("/sys/dev/block").join(device);
    if !base.exists() {
        return None;
    }
    if std::fs::read_to_string(base.join("dm/uuid")).is_ok_and(|uuid| uuid.starts_with("CRYPT-")) {
        return Some(true);
    }
    if depth == 0 {
        return Some(false);
    }
    let slaves: Vec<String> = std::fs::read_dir(base.join("slaves"))
        .map(|entries| {
            entries
                .filter_map(|entry| std::fs::read_to_string(entry.ok()?.path().join("dev")).ok())
                .map(|dev| dev.trim().to_owned())
                .collect()
        })
        .unwrap_or_default();
    if slaves.is_empty() {
        return Some(false);
    }
    Some(
        slaves
            .iter()
            .all(|slave| on_dm_crypt(slave, depth.saturating_sub(1)) == Some(true)),
    )
}

#[cfg(target_os = "linux")]
fn linux_swap(swaps: &str, resume: &str) -> Swap {
    use std::os::unix::fs::MetadataExt;
    let device_of = |path: &str| -> Option<String> {
        let metadata = std::fs::metadata(path).ok()?;
        let device = if metadata.file_type().is_file() {
            metadata.dev()
        } else {
            metadata.rdev()
        };
        // SAFETY-free: the major and minor numbers are pure arithmetic.
        Some(format!("{}:{}", libc::major(device), libc::minor(device)))
    };
    let mut unknown = false;
    for line in swaps.lines().skip(1) {
        let Some(path) = line.split_whitespace().next() else {
            continue;
        };
        if path.starts_with("/dev/zram") {
            continue;
        }
        match device_of(path).and_then(|device| on_dm_crypt(&device, 4)) {
            Some(true) => {}
            Some(false) => return Swap::Unencrypted(format!("the swap area {path}")),
            None => unknown = true,
        }
    }
    if !resume.is_empty() && resume != "0:0" {
        match on_dm_crypt(resume, 4) {
            Some(true) => {}
            Some(false) => {
                return Swap::Unencrypted(format!("the hibernation target {resume}"));
            }
            None => unknown = true,
        }
    }
    if unknown { Swap::Unknown } else { Swap::Safe }
}

/// Whether the passphrase would be typed where any X11 client can read the
/// keys (study section 11). Detection from a terminal is a best guess:
/// the session type when logind gives it, else an X display without a
/// Wayland one.
#[must_use]
pub fn under_x11() -> bool {
    if cfg!(not(target_os = "linux")) {
        return false;
    }
    match std::env::var("XDG_SESSION_TYPE").as_deref() {
        Ok("x11") => true,
        Ok("wayland" | "tty") => false,
        _ => std::env::var_os("DISPLAY").is_some() && std::env::var_os("WAYLAND_DISPLAY").is_none(),
    }
}

/// Whether the person asked to type passphrases under X11 all the same.
#[must_use]
pub fn x11_allowed() -> bool {
    std::env::var_os("TXC_VAULT_ALLOW_X11").is_some_and(|value| value == "1")
}

/// The user this process runs as, for checking who owns the vault files.
#[cfg(unix)]
pub(crate) fn user_id() -> u32 {
    // SAFETY: getuid cannot fail and has no side effects.
    unsafe { libc::getuid() }
}

#[cfg(unix)]
mod unix {
    /// Sets the core file size limit to zero, both soft and hard, so no crash
    /// of this process can write its memory to disk.
    pub fn no_core_dumps() {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: the pointer is to an initialised rlimit that lives for the
        // whole call, and setrlimit only reads it.
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, &raw const limit);
        }
    }

    /// Marks the process as not dumpable. Besides core files, this is what
    /// stops ptrace and `/proc/<pid>/mem` for other processes of the same user.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn not_dumpable() {
        // The argument is read as an unsigned long, so it is passed at that
        // width rather than as a variadic int.
        let disable: libc::c_ulong = 0;
        // SAFETY: PR_SET_DUMPABLE reads exactly one argument, given here.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, disable);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(target_os = "linux")]
    fn swap_on_a_plain_partition_is_unencrypted_and_zram_is_not_swap_on_disk() {
        use super::{Swap, linux_swap};
        let header = "Filename\tType\tSize\tUsed\tPriority\n";
        assert_eq!(linux_swap(header, ""), Swap::Safe, "no swap at all");
        assert_eq!(
            linux_swap(&format!("{header}/dev/zram0 partition 8G 0 100\n"), "0:0"),
            Swap::Safe
        );
        // A device that does not exist here is not known either way.
        assert_eq!(
            linux_swap(&format!("{header}/nonexistent/swap file 1G 0 -2\n"), ""),
            Swap::Unknown
        );
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn the_process_stops_being_dumpable() {
        super::process();
        assert!(!super::is_dumpable());
        // And asking twice does no harm.
        super::process();
        assert!(!super::is_dumpable());
    }
}
