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
pub fn process() {
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
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn the_process_stops_being_dumpable() {
        super::process();
        assert!(!super::is_dumpable());
        // And asking twice does no harm.
        super::process();
        assert!(!super::is_dumpable());
    }
}
