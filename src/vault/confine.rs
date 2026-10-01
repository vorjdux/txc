//! Confining a process that holds vault keys (study sections 4 and 11): it
//! may reach only the files it needs, open no network socket and run no
//! program. Each platform provides what it can, and [`Confinement`] says
//! what was actually applied, so `status` shows a missing protection rather
//! than hiding it.
//!
//! - **Linux:** Landlock limits the file system to the paths given, on every
//!   thread where the kernel supports it (ABI 8); seccomp makes `execve`,
//!   `execveat`, `ptrace` and every socket but Unix sockets fail with
//!   `EPERM`, on every thread.
//! - **macOS:** a sandbox profile denies the network, running programs, and
//!   writing outside the paths given.
//! - **Windows:** a mitigation policy forbids creating child processes. The
//!   network is not confined: that needs an `AppContainer`, and `status` says
//!   so.
//!
//! Confinement cannot be undone, so it is applied only once everything the
//! command needs from outside (the keystore, the terminal prompts) is done.

// The one module besides `harden`, `session`, `deliver` and `store` allowed
// to call the operating system directly: the sandboxes have no safe wrapper
// in the standard library.
#![allow(unsafe_code)]

use std::path::Path;

/// What confinement was put in place.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Confinement {
    /// Files outside the given paths cannot be reached.
    pub files: bool,
    /// Every thread is confined, not only the one that asked.
    pub all_threads: bool,
    /// No network socket can be opened.
    pub network: bool,
    /// No program can be run.
    pub programs: bool,
}

impl Confinement {
    /// The protections that are missing, in words, for `status`.
    #[must_use]
    pub fn missing(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.files {
            missing.push("file access is not limited");
        } else if !self.all_threads {
            missing.push("file limits cover only the main thread");
        }
        if !self.network {
            missing.push("network access is not blocked");
        }
        if !self.programs {
            missing.push("running programs is not blocked");
        }
        missing
    }
}

/// Confines this process: files only under `writable` (read and write) and
/// `readable` (read only), no network, no programs.
#[must_use]
pub fn confine(writable: &[&Path], readable: &[&Path]) -> Confinement {
    platform::confine(writable, readable)
}

#[cfg(target_os = "linux")]
mod platform {
    use std::collections::BTreeMap;
    use std::path::Path;

    use landlock::{
        ABI, Access, AccessFs, RestrictSelfAttr, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus, path_beneath_rules,
    };
    use seccompiler::{
        SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    };

    use super::Confinement;

    /// Files the C library and the terminal need, read only.
    const SYSTEM: &[&str] = &[
        "/etc/localtime",
        "/usr/share/zoneinfo",
        "/proc/self",
        "/dev/urandom",
    ];
    /// Devices the prompts and the clipboard clean-up still use.
    const DEVICES: &[&str] = &["/dev/tty", "/dev/null"];

    fn landlock(writable: &[&Path], readable: &[&Path]) -> (bool, bool) {
        let abi = ABI::V8;
        let applied = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .and_then(Ruleset::create)
            .and_then(|ruleset| {
                ruleset.add_rules(path_beneath_rules(writable, AccessFs::from_all(abi)))
            })
            .and_then(|ruleset| {
                ruleset.add_rules(path_beneath_rules(DEVICES, AccessFs::from_all(abi)))
            })
            .and_then(|ruleset| {
                ruleset.add_rules(path_beneath_rules(readable, AccessFs::from_read(abi)))
            })
            .and_then(|ruleset| {
                ruleset.add_rules(path_beneath_rules(SYSTEM, AccessFs::from_read(abi)))
            })
            .and_then(|ruleset| ruleset.all_threads(true))
            .and_then(landlock::RulesetCreated::restrict_self);
        match applied {
            Ok(status) => (
                status.ruleset != RulesetStatus::NotEnforced,
                status.all_threads,
            ),
            Err(_) => (false, false),
        }
    }

    fn seccomp() -> bool {
        let socket_family = |family: i32| {
            SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                u64::try_from(family).unwrap_or(0),
            )
            .and_then(|condition| SeccompRule::new(vec![condition]))
        };
        let Ok(socket_rules) = [
            libc::AF_INET,
            libc::AF_INET6,
            libc::AF_PACKET,
            libc::AF_NETLINK,
        ]
        .into_iter()
        .map(socket_family)
        .collect::<Result<Vec<_>, _>>() else {
            return false;
        };
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        rules.insert(libc::SYS_socket, socket_rules);
        for call in [
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
        ] {
            rules.insert(call, Vec::new());
        }
        let Ok(arch) = std::env::consts::ARCH.try_into() else {
            return false;
        };
        let errno = u32::try_from(libc::EPERM).unwrap_or(1);
        SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(errno),
            arch,
        )
        .ok()
        .and_then(|filter| filter.try_into().ok())
        .is_some_and(|program: seccompiler::BpfProgram| {
            seccompiler::apply_filter_all_threads(&program).is_ok()
        })
    }

    pub(super) fn confine(writable: &[&Path], readable: &[&Path]) -> Confinement {
        let (files, all_threads) = landlock(writable, readable);
        let calls = seccomp();
        Confinement {
            files,
            all_threads,
            network: calls,
            programs: calls,
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::{CString, c_char, c_int};
    use std::path::Path;

    use super::Confinement;

    unsafe extern "C" {
        fn sandbox_init(profile: *const c_char, flags: u64, error: *mut *mut c_char) -> c_int;
        fn sandbox_free_error(error: *mut c_char);
    }

    fn quoted(path: &Path) -> Option<String> {
        let text = path.to_str()?;
        (!text.contains(['"', '\\'])).then(|| format!("(subpath \"{text}\")"))
    }

    pub(super) fn confine(writable: &[&Path], _readable: &[&Path]) -> Confinement {
        // The sandbox matches real paths: /var and /tmp are links into
        // /private, so each path is allowed as given and as it resolves.
        let mut all: Vec<std::path::PathBuf> = Vec::new();
        for path in writable {
            all.push(path.to_path_buf());
            if let Ok(real) = std::fs::canonicalize(path)
                && real != *path
            {
                all.push(real);
            }
        }
        let Some(paths) = all
            .iter()
            .map(|path| quoted(path))
            .collect::<Option<Vec<_>>>()
        else {
            return Confinement::default();
        };
        let profile = format!(
            "(version 1)(allow default)(deny network*)(deny process-exec*)(deny process-fork)\
             (deny file-write* (require-not (require-any {} (literal \"/dev/tty\") (literal \"/dev/null\"))))",
            paths.join(" ")
        );
        let Ok(profile) = CString::new(profile) else {
            return Confinement::default();
        };
        let mut error: *mut c_char = std::ptr::null_mut();
        // SAFETY: the profile is a valid C string for the call; the error
        // pointer is written only on failure, and freed with the matching
        // function.
        let result = unsafe { sandbox_init(profile.as_ptr(), 0, &raw mut error) };
        if !error.is_null() {
            // SAFETY: allocated by sandbox_init for this call.
            unsafe { sandbox_free_error(error) };
        }
        let applied = result == 0;
        Confinement {
            files: applied,
            all_threads: applied,
            network: applied,
            programs: applied,
        }
    }
}

#[cfg(windows)]
mod platform {
    use std::path::Path;

    use windows_sys::Win32::System::SystemServices::PROCESS_MITIGATION_CHILD_PROCESS_POLICY;
    use windows_sys::Win32::System::Threading::{
        ProcessChildProcessPolicy, SetProcessMitigationPolicy,
    };

    use super::Confinement;

    pub(super) fn confine(_writable: &[&Path], _readable: &[&Path]) -> Confinement {
        let mut policy = PROCESS_MITIGATION_CHILD_PROCESS_POLICY::default();
        // Bit 0: NoChildProcessCreation.
        policy.Anonymous.Flags = 1;
        // SAFETY: the buffer is a policy of the size passed, for the policy
        // named.
        let applied = unsafe {
            SetProcessMitigationPolicy(
                ProcessChildProcessPolicy,
                (&raw const policy).cast(),
                size_of::<PROCESS_MITIGATION_CHILD_PROCESS_POLICY>(),
            )
        } != 0;
        Confinement {
            files: false,
            all_threads: applied,
            network: false,
            programs: applied,
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod platform {
    use std::path::Path;

    use super::Confinement;

    pub(super) const fn confine(_writable: &[&Path], _readable: &[&Path]) -> Confinement {
        Confinement {
            files: false,
            all_threads: false,
            network: false,
            programs: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;

    /// Confinement cannot be undone, so it is tested in a child: this test
    /// binary run again for the one test below, told so by a variable.
    const CHILD: &str = "TXC_CONFINE_CHILD";

    #[test]
    fn a_confined_process_reaches_only_its_paths_and_cannot_run_programs() {
        if std::env::var_os(CHILD).is_some() {
            return;
        }
        let scratch = crate::vault::test_support::Scratch::new("confine");
        std::fs::create_dir_all(scratch.0.join("allowed")).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "vault::confine::tests::confined_child",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD, &scratch.0)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{text}");
        assert!(text.contains("1 passed"), "{text}");
    }

    #[test]
    #[ignore = "run only as the child of the test above"]
    fn confined_child() {
        let Some(root) = std::env::var_os(CHILD) else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        let allowed = root.join("allowed");
        let applied = confine(&[&allowed], &[]);
        if cfg!(target_os = "linux") {
            assert!(
                applied.files && applied.network && applied.programs,
                "{applied:?}"
            );
            assert!(std::fs::write(allowed.join("inside"), b"ok").is_ok());
            assert!(std::fs::write(root.join("outside"), b"no").is_err());
            assert!(std::fs::read_to_string("/etc/hostname").is_err());
            assert!(std::net::TcpListener::bind("127.0.0.1:0").is_err());
            assert!(Command::new("/bin/true").status().is_err());
        }
        if cfg!(windows) {
            assert!(applied.programs, "{applied:?}");
            assert!(!applied.missing().is_empty());
        }
    }
}
