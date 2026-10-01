//! Handing a secret to a program as a file that never touches the disk.
//!
//! Many programs take a certificate, a key or a password file by path rather
//! than from their environment. Writing the secret to a file would leave it on
//! disk; instead the program is given a path to a descriptor it inherits:
//!
//! - **Linux:** a sealed memfd, mode 0600, that nobody can change once
//!   written. The program sees `/dev/fd/N` and can read it as often as it
//!   likes.
//! - **macOS and other Unix:** one end of a socket pair, seen as
//!   `/dev/fd/N`. It can be read once, which is what most programs do. Not a
//!   pipe: macOS reports every pipe as mode 0660, which `ssh` refuses for a
//!   private key and nothing can change, while a socket shows no permission
//!   bits at all.
//! - **Windows:** a one-shot named pipe that only the current user may open,
//!   served once and then gone.

// The one module besides `harden` and `session` allowed to call the operating
// system directly: memfd sealing, pipes and named pipes have no safe wrapper
// in the standard library. Every call is on a descriptor this module owns.
#![allow(unsafe_code)]

use std::process::Command;

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::Result;
use zeroize::Zeroizing;

/// A secret prepared for a child process. Keep it alive until the child has
/// been spawned, then call [`Delivery::after_spawn`].
pub struct Delivery {
    /// The path the child opens.
    pub path: String,
    inner: platform::Inner,
}

impl Delivery {
    /// Prepares the secret and arranges for `command` to inherit it.
    ///
    /// # Errors
    ///
    /// Returns an error when the system refuses to create the descriptor.
    pub fn prepare(secret: &SecretString, command: &mut Command) -> Result<Self> {
        let bytes = Zeroizing::new(secret.expose_secret().as_bytes().to_vec());
        let (path, inner) = platform::prepare(bytes, command)?;
        Ok(Self { path, inner })
    }

    /// Releases the parent's copy of the descriptor once the child has its
    /// own.
    pub fn after_spawn(self) {
        platform::after_spawn(self.inner);
    }
}

/// A private key for `ssh`, which refuses a key whose file others could
/// read. On Linux and Windows it is a [`Delivery`]. On macOS and other Unix
/// systems neither a pipe nor a socket can show an owner-only mode, so the
/// key, made for this one connection and certified for minutes, is written
/// to a file of mode 0600 in a new directory of mode 0700 inside the
/// per-user temporary directory, and erased as soon as `ssh` exits.
pub struct PrivateKey {
    path: String,
    inherited: Option<Delivery>,
    #[cfg(all(unix, not(target_os = "linux")))]
    dir: Option<std::path::PathBuf>,
}

impl PrivateKey {
    /// Prepares the key for `command`.
    ///
    /// # Errors
    ///
    /// Returns an error when the descriptor or the file cannot be made.
    pub fn prepare(secret: &SecretString, command: &mut Command) -> Result<Self> {
        #[cfg(all(unix, not(target_os = "linux")))]
        {
            let _ = command;
            let (path, dir) = private_file(secret)?;
            Ok(Self {
                path,
                inherited: None,
                dir: Some(dir),
            })
        }
        #[cfg(not(all(unix, not(target_os = "linux"))))]
        {
            let delivery = Delivery::prepare(secret, command)?;
            Ok(Self {
                path: delivery.path.clone(),
                inherited: Some(delivery),
            })
        }
    }

    /// The path `ssh` reads the key from.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Releases the parent's descriptor once the child has its own.
    pub fn after_spawn(&mut self) {
        if let Some(delivery) = self.inherited.take() {
            delivery.after_spawn();
        }
    }

    /// Erases the key file, if there is one, once the child is done.
    pub fn finish(self) {
        #[cfg(all(unix, not(target_os = "linux")))]
        if let Some(dir) = &self.dir {
            erase(dir);
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn private_file(secret: &SecretString) -> Result<(String, std::path::PathBuf)> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

    let dir = std::env::temp_dir().join(format!("txc-ssh-{}", uuid::Uuid::new_v4().simple()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|error| anyhow::anyhow!("cannot make a private directory for the key: {error}"))?;
    let path = dir.join("key");
    let written = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut file| {
            file.write_all(secret.expose_secret().as_bytes())?;
            file.sync_all()
        });
    if let Err(error) = written {
        erase(&dir);
        anyhow::bail!("cannot write the key for ssh: {error}");
    }
    Ok((path.to_string_lossy().into_owned(), dir))
}

/// Overwrites the key with zeros and removes it and its directory.
#[cfg(all(unix, not(target_os = "linux")))]
fn erase(dir: &std::path::Path) {
    let path = dir.join("key");
    if let Ok(metadata) = std::fs::metadata(&path) {
        let zeros = vec![0_u8; usize::try_from(metadata.len()).unwrap_or(0)];
        std::fs::write(&path, zeros).ok();
    }
    std::fs::remove_file(&path).ok();
    std::fs::remove_dir(dir).ok();
}

#[cfg(target_os = "linux")]
mod platform {
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::Command;

    use anyhow::{Result, anyhow, ensure};
    use zeroize::Zeroizing;

    pub(super) struct Inner(OwnedFd);

    // The same signature as the platforms that move the bytes to a thread.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn prepare(bytes: Zeroizing<Vec<u8>>, _: &mut Command) -> Result<(String, Inner)> {
        // SAFETY: the name is a NUL terminated literal; the flags are valid.
        let raw = unsafe {
            libc::memfd_create(
                c"txc-secret".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            )
        };
        if raw < 0 {
            return Err(anyhow!(
                "cannot create a memory file: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: memfd_create returned a fresh descriptor this code now owns.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut file = File::from(owned.try_clone()?);
        file.write_all(&bytes)?;
        drop(file);
        // SAFETY: plain calls on the descriptor owned above.
        let sealed = unsafe {
            libc::fchmod(raw, 0o600) == 0
                && libc::fcntl(
                    raw,
                    libc::F_ADD_SEALS,
                    libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL,
                ) == 0
                // Only the child inherits it: close-on-exec is cleared last.
                && libc::fcntl(raw, libc::F_SETFD, 0) == 0
        };
        ensure!(
            sealed,
            "cannot seal the memory file: {}",
            std::io::Error::last_os_error()
        );
        Ok((format!("/dev/fd/{}", owned.as_raw_fd()), Inner(owned)))
    }

    pub(super) fn after_spawn(inner: Inner) {
        drop(inner.0);
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod platform {
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::Command;

    use anyhow::{Result, anyhow, ensure};
    use zeroize::Zeroizing;

    pub(super) struct Inner(OwnedFd);

    pub(super) fn prepare(bytes: Zeroizing<Vec<u8>>, _: &mut Command) -> Result<(String, Inner)> {
        let mut fds = [0; 2];
        // SAFETY: the pointer is to an array of two descriptors, as
        // socketpair needs.
        if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) } != 0 {
            return Err(anyhow!(
                "cannot create a socket pair: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: socketpair returned two fresh descriptors this code now
        // owns.
        let (reader, writer) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // SAFETY: plain calls on the descriptors owned above: the writer stays
        // with txc, the reader is inherited by the child alone.
        let ok = unsafe {
            libc::fcntl(writer.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) == 0
                && libc::fcntl(reader.as_raw_fd(), libc::F_SETFD, 0) == 0
        };
        ensure!(
            ok,
            "cannot prepare the socket pair: {}",
            std::io::Error::last_os_error()
        );
        // Written from a thread, so a secret larger than the socket's buffer
        // does not block txc before the child starts reading; closing the
        // writing end then gives the reader its end of file.
        std::thread::spawn(move || {
            let mut file = File::from(writer);
            // A child that never reads it is its own business.
            file.write_all(&bytes).ok();
        });
        Ok((format!("/dev/fd/{}", reader.as_raw_fd()), Inner(reader)))
    }

    pub(super) fn after_spawn(inner: Inner) {
        drop(inner.0);
    }
}

#[cfg(windows)]
mod platform {
    use std::process::Command;
    use std::ptr;

    use anyhow::{Result, anyhow};
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FlushFileBuffers, PIPE_ACCESS_OUTBOUND, WriteFile,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use zeroize::Zeroizing;

    pub(super) struct Inner;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// A pipe handle moved to the serving thread.
    struct Pipe(HANDLE);
    // SAFETY: a pipe handle may be used from any thread; only one uses it.
    unsafe impl Send for Pipe {}

    pub(super) fn prepare(bytes: Zeroizing<Vec<u8>>, _: &mut Command) -> Result<(String, Inner)> {
        let name = format!(r"\\.\pipe\txc-secret-{}", uuid::Uuid::new_v4().simple());
        // Full access for the owner (the current user) and nobody else; the
        // default pipe DACL would let everyone read.
        let sddl = wide("D:P(A;;GA;;;OW)");
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: the SDDL string is NUL terminated; the descriptor is
        // allocated by the call and freed below with LocalFree.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(anyhow!("cannot build the pipe's access list"));
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let size = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let wide_name = wide(&name);
        // SAFETY: the name is NUL terminated and the attributes point at a
        // live descriptor for the duration of the call.
        let handle = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                size,
                size,
                0,
                &raw const attributes,
            )
        };
        // SAFETY: allocated by the conversion above.
        unsafe { LocalFree(descriptor) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(anyhow!(
                "cannot create a named pipe: {}",
                std::io::Error::last_os_error()
            ));
        }
        let pipe = Pipe(handle);
        std::thread::spawn(move || {
            let pipe = pipe;
            let mut written = 0_u32;
            // SAFETY: the handle is the pipe created above, used by this
            // thread alone and closed at the end; the buffer is `bytes`.
            unsafe {
                if ConnectNamedPipe(pipe.0, ptr::null_mut()) != 0 {
                    WriteFile(
                        pipe.0,
                        bytes.as_ptr(),
                        size,
                        &raw mut written,
                        ptr::null_mut(),
                    );
                    FlushFileBuffers(pipe.0);
                    DisconnectNamedPipe(pipe.0);
                }
                CloseHandle(pipe.0);
            }
        });
        Ok((name, Inner))
    }

    pub(super) const fn after_spawn(_: Inner) {}
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(all(unix, not(target_os = "linux")))]
    fn an_ssh_key_file_is_private_and_erased_when_done() {
        use std::os::unix::fs::PermissionsExt;
        let mut command = std::process::Command::new("true");
        let key = super::PrivateKey::prepare(
            &age::secrecy::SecretString::from("key".to_owned()),
            &mut command,
        )
        .unwrap();
        let path = std::path::PathBuf::from(key.path());
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "key");
        key.finish();
        assert!(!path.exists() && !path.parent().unwrap().exists());
    }
}
