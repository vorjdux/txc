//! The shared vault folder: one flat directory of immutable, randomly named
//! objects (study section 7).
//!
//! The folder lives in a sync client's tree, where anyone who can write to
//! the account can plant a symlink, a FIFO, a hard link to a local file or a
//! huge file. Every read therefore follows the folder handling rules:
//!
//! 1. Open relative to the held `objects` directory, refusing symlinks
//!    anywhere: `openat2` with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` on
//!    Linux, `O_NOFOLLOW_ANY` on macOS, `NtCreateFile` relative to the
//!    directory handle with `FILE_OPEN_REPARSE_POINT` on Windows. Opens never
//!    block, so a FIFO cannot hang a reader.
//! 2. Accept only regular files with one link, checked on the open handle.
//! 3. Accept only names of 64 lowercase hex digits; count everything else.
//! 4. Check the size before reading, and cap the number of objects.
//! 5. Read the file once into memory; callers verify and use that buffer.
//!
//! Rule 6, quarantine after repeated failures, is local policy and lives
//! with the local state; [`Object::modified`] is what it needs.
//!
//! Writes go to a `.tmp-` name in the same directory, are flushed to stable
//! storage (`F_FULLFSYNC` on macOS, which [`File::sync_all`] uses there), and
//! are renamed into place without ever replacing an object:
//! `renameat2(RENAME_NOREPLACE)`, `renameatx_np(RENAME_EXCL)`, or `MoveFileEx`
//! without the replace flag. A file system that lacks the no-replace rename
//! gets a hard link and an unlink, which cannot replace either.

// The one module besides `harden`, `session` and `deliver` allowed to call the
// operating system directly: the safe opens and no-replace renames above have
// no wrapper in the standard library. Every call is on a directory handle
// this module owns and a name it has checked.
#![allow(unsafe_code)]

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail, ensure};

use crate::vault::object::MAX_OBJECT_BYTES;

/// The most objects a folder may hold before txc refuses to read it. A
/// personal vault holds a few hundred after compaction (rule 19).
pub const MAX_OBJECTS: usize = 100_000;

const TMP_PREFIX: &str = ".tmp-";
const NAME_BYTES: usize = 32;

/// An object's name: 32 random bytes, written as 64 lowercase hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name([u8; NAME_BYTES]);

impl Name {
    fn random() -> Self {
        let mut bytes = [0; NAME_BYTES];
        rand::fill(&mut bytes[..]);
        Self(bytes)
    }

    /// Reads a name, accepting only 64 lowercase hex digits.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != NAME_BYTES * 2 {
            return None;
        }
        let mut bytes = [0; NAME_BYTES];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
            let [high, low] = pair else { return None };
            *byte = (nibble(*high)? << 4) | nibble(*low)?;
        }
        Some(Self(bytes))
    }
}

const fn nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(digit.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// What a listing found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listing {
    /// The objects, sorted.
    pub names: Vec<Name>,
    /// Writes in flight, by this or another device.
    pub in_flight: usize,
    /// Everything else: names no txc writes, reported but never read.
    pub ignored: usize,
}

/// An object read under the folder rules.
#[derive(Debug)]
pub struct Object {
    /// The file's content, read once.
    pub bytes: Vec<u8>,
    /// When the file last changed, for the quarantine rule.
    pub modified: SystemTime,
}

/// A vault folder's `objects` directory, held open.
pub struct Store {
    path: PathBuf,
    dir: File,
    max_bytes: usize,
    max_objects: usize,
}

impl Store {
    /// Opens the `objects` directory of a vault folder, creating it when
    /// `create` is set. The directory itself must not be a symlink.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory is missing and `create` is not
    /// set, is not a directory, or is a symlink.
    pub fn open(folder: &Path, create: bool) -> Result<Self> {
        let path = folder.join("objects");
        if create {
            match platform::create_dir(&path) {
                Err(error) if error.kind() != io::ErrorKind::AlreadyExists => {
                    return Err(error).with_context(|| format!("cannot create {}", path.display()));
                }
                _ => {}
            }
        }
        let dir =
            platform::open_dir(&path).with_context(|| format!("cannot open {}", path.display()))?;
        Ok(Self {
            path,
            dir,
            max_bytes: MAX_OBJECT_BYTES,
            max_objects: MAX_OBJECTS,
        })
    }

    /// The directory's path, for messages.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Lists the objects in the folder.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be read or holds more
    /// objects than any vault should.
    pub fn list(&self) -> Result<Listing> {
        let mut listing = Listing::default();
        for entry in fs::read_dir(&self.path)
            .with_context(|| format!("cannot read {}", self.path.display()))?
        {
            let entry = entry?;
            let file_name = entry.file_name();
            match file_name.to_str() {
                Some(text) if text.starts_with(TMP_PREFIX) => {
                    listing.in_flight = listing.in_flight.saturating_add(1);
                }
                Some(text) => match Name::parse(text) {
                    Some(name) => listing.names.push(name),
                    None => listing.ignored = listing.ignored.saturating_add(1),
                },
                None => listing.ignored = listing.ignored.saturating_add(1),
            }
            ensure!(
                listing.names.len() <= self.max_objects,
                "{} holds more than {} objects; refusing to read it",
                self.path.display(),
                self.max_objects
            );
        }
        listing.names.sort_unstable();
        Ok(listing)
    }

    /// Reads one object under the folder rules. Returns `None` when it is
    /// gone, which is normal: another device collected it.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is not a regular file with one link,
    /// is larger than any object txc writes, or cannot be read.
    pub fn read(&self, name: &Name) -> Result<Option<Object>> {
        let text = name.to_string();
        let file = match platform::open_object(&self.dir, &text) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("object {text} cannot be opened safely"));
            }
        };
        let facts =
            platform::inspect(&file).with_context(|| format!("cannot inspect object {text}"))?;
        ensure!(facts.regular, "object {text} is not a regular file");
        ensure!(
            facts.links == 1,
            "object {text} has {} links; refusing it",
            facts.links
        );
        ensure!(
            facts.size <= self.max_bytes as u64,
            "object {text} is larger than any txc writes"
        );
        let mut bytes = Vec::with_capacity(usize::try_from(facts.size).unwrap_or(0));
        file.take((self.max_bytes as u64).saturating_add(1))
            .read_to_end(&mut bytes)
            .with_context(|| format!("cannot read object {text}"))?;
        ensure!(
            bytes.len() <= self.max_bytes,
            "object {text} grew while being read; refusing it"
        );
        Ok(Some(Object {
            bytes,
            modified: facts.modified,
        }))
    }

    /// Writes a new object under a fresh random name and returns the name.
    /// The object is on stable storage when this returns, and no existing
    /// object was replaced.
    ///
    /// # Errors
    ///
    /// Returns an error when the object is too large or the write fails.
    pub fn write(&self, bytes: &[u8]) -> Result<Name> {
        ensure!(
            bytes.len() <= self.max_bytes,
            "the object is larger than any txc writes"
        );
        let tmp = format!("{TMP_PREFIX}{}", Name::random());
        let tmp_path = self.path.join(&tmp);
        let result = Self::write_tmp(&tmp_path, bytes).and_then(|()| {
            // A fresh 256-bit name never collides; retry anyway rather than
            // trust that, since the rename refuses to replace.
            for _ in 0..3 {
                let name = Name::random();
                match platform::rename_no_replace(&self.dir, &self.path, &tmp, &name.to_string()) {
                    Ok(()) => {
                        platform::sync_dir(&self.dir)?;
                        return Ok(name);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            bail!("could not find a free object name")
        });
        if result.is_err() {
            // Best effort: a leftover is swept later.
            fs::remove_file(&tmp_path).ok();
        }
        result.with_context(|| format!("cannot write an object to {}", self.path.display()))
    }

    fn write_tmp(path: &Path, bytes: &[u8]) -> Result<()> {
        let mut file = platform::create_new(path)?;
        io::Write::write_all(&mut file, bytes)?;
        file.sync_all()?;
        Ok(())
    }

    /// Removes an object, for garbage collection of this device's own
    /// superseded objects. An object already gone is not an error.
    ///
    /// # Errors
    ///
    /// Returns an error when the file exists but cannot be removed.
    pub fn remove(&self, name: &Name) -> Result<()> {
        match fs::remove_file(self.path.join(name.to_string())) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => {
                Err(error).with_context(|| format!("cannot remove object {name}"))
            }
            _ => Ok(()),
        }
    }

    /// Removes writes in flight older than `age`: what a crash or a killed
    /// process left behind. Returns how many were removed.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be read.
    pub fn sweep(&self, age: Duration) -> Result<usize> {
        let now = SystemTime::now();
        let mut removed = 0_usize;
        for entry in fs::read_dir(&self.path)? {
            let entry = entry?;
            let is_tmp = entry
                .file_name()
                .to_str()
                .is_some_and(|text| text.starts_with(TMP_PREFIX));
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let old = metadata
                .modified()
                .ok()
                .and_then(|at| now.duration_since(at).ok())
                .is_some_and(|since| since >= age);
            if is_tmp && metadata.is_file() && old && fs::remove_file(entry.path()).is_ok() {
                removed = removed.saturating_add(1);
            }
        }
        Ok(removed)
    }
}

/// What the open handle says about a file.
struct Facts {
    regular: bool,
    links: u64,
    size: u64,
    modified: SystemTime,
}

#[cfg(unix)]
mod platform {
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use super::Facts;

    pub(super) fn create_dir(path: &Path) -> io::Result<()> {
        fs::DirBuilder::new().mode(0o700).create(path)
    }

    pub(super) fn open_dir(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    pub(super) fn create_new(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
    }

    fn c_name(name: &str) -> io::Result<CString> {
        CString::new(name).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }

    fn owned(fd: libc::c_int) -> io::Result<File> {
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by a successful open and nothing
        // else owns it.
        Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    const READ_FLAGS: libc::c_int =
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;

    #[cfg(target_os = "linux")]
    pub(super) fn open_object(dir: &File, name: &str) -> io::Result<File> {
        let path = c_name(name)?;
        // SAFETY: `open_how` is plain data, for which all zeroes is valid.
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = READ_FLAGS as u64;
        how.resolve = libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS;
        // SAFETY: `how` and `path` outlive the call, and the size passed is
        // the size of `how`.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dir.as_raw_fd(),
                path.as_ptr(),
                &raw const how,
                size_of::<libc::open_how>(),
            )
        };
        match owned(libc::c_int::try_from(fd).unwrap_or(-1)) {
            // Kernels before 5.6, and sandboxes that filter openat2: a
            // single checked name component with O_NOFOLLOW, relative to the
            // held directory, cannot leave it either.
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOSYS | libc::EPERM | libc::E2BIG)
                ) =>
            {
                openat(dir, &path, READ_FLAGS)
            }
            other => other,
        }
    }

    #[cfg(target_os = "macos")]
    pub(super) fn open_object(dir: &File, name: &str) -> io::Result<File> {
        openat(dir, &c_name(name)?, READ_FLAGS | libc::O_NOFOLLOW_ANY)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) fn open_object(dir: &File, name: &str) -> io::Result<File> {
        openat(dir, &c_name(name)?, READ_FLAGS)
    }

    fn openat(dir: &File, path: &CString, flags: libc::c_int) -> io::Result<File> {
        // SAFETY: `path` is a valid C string that outlives the call.
        owned(unsafe { libc::openat(dir.as_raw_fd(), path.as_ptr(), flags) })
    }

    pub(super) fn inspect(file: &File) -> io::Result<Facts> {
        let metadata = file.metadata()?;
        Ok(Facts {
            regular: metadata.file_type().is_file(),
            links: metadata.nlink(),
            size: metadata.len(),
            modified: metadata.modified()?,
        })
    }

    pub(super) fn rename_no_replace(dir: &File, _: &Path, from: &str, to: &str) -> io::Result<()> {
        let (from, to) = (c_name(from)?, c_name(to)?);
        match native_rename(dir, &from, &to) {
            // The file system has no no-replace rename (some network and
            // FUSE file systems): a hard link refuses an existing name too.
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EINVAL | libc::ENOSYS | libc::ENOTSUP)
                ) =>
            {
                link_then_unlink(dir, &from, &to)
            }
            other => other,
        }
    }

    fn check(result: libc::c_int) -> io::Result<()> {
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(target_os = "linux")]
    fn native_rename(dir: &File, from: &CString, to: &CString) -> io::Result<()> {
        let fd = dir.as_raw_fd();
        // SAFETY: both names are valid C strings that outlive the call.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                fd,
                from.as_ptr(),
                fd,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        check(libc::c_int::try_from(result).unwrap_or(-1))
    }

    #[cfg(target_os = "macos")]
    fn native_rename(dir: &File, from: &CString, to: &CString) -> io::Result<()> {
        let fd = dir.as_raw_fd();
        // SAFETY: both names are valid C strings that outlive the call.
        check(unsafe { libc::renameatx_np(fd, from.as_ptr(), fd, to.as_ptr(), libc::RENAME_EXCL) })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn native_rename(_: &File, _: &CString, _: &CString) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    fn link_then_unlink(dir: &File, from: &CString, to: &CString) -> io::Result<()> {
        let fd = dir.as_raw_fd();
        // SAFETY: both names are valid C strings that outlive the calls.
        check(unsafe { libc::linkat(fd, from.as_ptr(), fd, to.as_ptr(), 0) })?;
        // SAFETY: as above.
        check(unsafe { libc::unlinkat(fd, from.as_ptr(), 0) })
    }

    pub(super) fn sync_dir(dir: &File) -> io::Result<()> {
        dir.sync_all()
    }
}

#[cfg(windows)]
mod platform {
    use std::fs::{self, File, OpenOptions};
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::Path;

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{RtlNtStatusToDosError, UNICODE_STRING};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileStandardInfo,
        GetFileInformationByHandleEx, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    use super::Facts;

    pub(super) fn create_dir(path: &Path) -> io::Result<()> {
        fs::create_dir(path)
    }

    /// Opens the directory without delete sharing, so it cannot be renamed
    /// or replaced while it is held, and refuses a junction or symlink.
    pub(super) fn open_dir(path: &Path) -> io::Result<File> {
        let dir = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        let metadata = dir.metadata()?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a plain directory",
            ));
        }
        Ok(dir)
    }

    pub(super) fn create_new(path: &Path) -> io::Result<File> {
        OpenOptions::new().write(true).create_new(true).open(path)
    }

    fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
        text.encode_wide().chain(std::iter::once(0)).collect()
    }

    /// Opens a name relative to the held directory handle, as a file and
    /// never a directory, without following a reparse point.
    pub(super) fn open_object(dir: &File, name: &str) -> io::Result<File> {
        let mut units: Vec<u16> = name.encode_utf16().collect();
        let length = u16::try_from(units.len().saturating_mul(2))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let object_name = UNICODE_STRING {
            Length: length,
            MaximumLength: length,
            Buffer: units.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: u32::try_from(size_of::<OBJECT_ATTRIBUTES>()).unwrap_or(0),
            RootDirectory: dir.as_raw_handle(),
            ObjectName: &raw const object_name,
            Attributes: 0,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut handle = std::ptr::null_mut();
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: every pointer refers to a local that outlives the call, and
        // `units` backs `object_name` for its whole length.
        let status = unsafe {
            NtCreateFile(
                &raw mut handle,
                FILE_GENERIC_READ,
                &raw const attributes,
                &raw mut status_block,
                std::ptr::null(),
                0,
                FILE_SHARE_READ,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
                std::ptr::null(),
                0,
            )
        };
        if status < 0 {
            // SAFETY: a pure conversion of a status code.
            let code = unsafe { RtlNtStatusToDosError(status) };
            return Err(io::Error::from_raw_os_error(
                i32::try_from(code).unwrap_or(i32::MAX),
            ));
        }
        // SAFETY: the call succeeded, so `handle` is a new handle nothing else
        // owns.
        Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle) }))
    }

    pub(super) fn inspect(file: &File) -> io::Result<Facts> {
        let mut standard = FILE_STANDARD_INFO::default();
        // SAFETY: the buffer is a `FILE_STANDARD_INFO` of the size passed.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileStandardInfo,
                (&raw mut standard).cast(),
                u32::try_from(size_of::<FILE_STANDARD_INFO>()).unwrap_or(0),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let metadata = file.metadata()?;
        Ok(Facts {
            regular: !standard.Directory
                && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            links: u64::from(standard.NumberOfLinks),
            size: u64::try_from(standard.EndOfFile).unwrap_or(u64::MAX),
            modified: metadata.modified()?,
        })
    }

    /// `MoveFileEx` without `MOVEFILE_REPLACE_EXISTING` refuses an existing
    /// name. The directory is held without delete sharing, so the paths
    /// resolve inside it.
    pub(super) fn rename_no_replace(_: &File, path: &Path, from: &str, to: &str) -> io::Result<()> {
        let (from, to) = (
            wide(path.join(from).as_os_str()),
            wide(path.join(to).as_os_str()),
        );
        // SAFETY: both are NUL-terminated wide strings that outlive the call.
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Windows has no directory flush; `MOVEFILE_WRITE_THROUGH` makes the
    /// rename durable before it returns.
    #[allow(clippy::unnecessary_wraps, reason = "the same signature as on Unix")]
    pub(super) const fn sync_dir(_: &File) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::test_support::Scratch;

    fn scratch() -> Scratch {
        let scratch = Scratch::new("store");
        fs::create_dir_all(&scratch.0).unwrap();
        scratch
    }

    fn store() -> (Scratch, Store) {
        let folder = scratch();
        let store = Store::open(&folder.0, true).unwrap();
        (folder, store)
    }

    #[test]
    fn a_name_is_exactly_64_lowercase_hex_digits() {
        let name = Name::random();
        assert_eq!(Name::parse(&name.to_string()), Some(name));
        assert_eq!(
            Name::parse(&"a".repeat(64)).map(|name| name.to_string()),
            Some("a".repeat(64))
        );
        for bad in [
            "A".repeat(64),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
            format!("{}é", "a".repeat(62)),
        ] {
            assert_eq!(Name::parse(&bad), None, "{bad}");
        }
    }

    #[test]
    fn an_object_round_trips_and_is_never_replaced() {
        let (_folder, store) = store();
        let first = store.write(b"first").unwrap();
        let second = store.write(b"second").unwrap();
        assert_ne!(first, second);
        assert_eq!(store.read(&first).unwrap().unwrap().bytes, b"first");
        assert_eq!(store.list().unwrap().names.len(), 2);

        let (tmp, target) = (format!("{TMP_PREFIX}x"), first.to_string());
        fs::write(store.path().join(&tmp), b"other").unwrap();
        let error =
            platform::rename_no_replace(&store.dir, store.path(), &tmp, &target).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(store.read(&first).unwrap().unwrap().bytes, b"first");
    }

    #[test]
    fn a_listing_reads_only_object_names() {
        let (_folder, store) = store();
        let name = store.write(b"object").unwrap();
        fs::write(store.path().join(format!("{TMP_PREFIX}abc")), b"").unwrap();
        fs::write(store.path().join("README"), b"").unwrap();
        fs::write(store.path().join("A".repeat(64)), b"").unwrap();
        let listing = store.list().unwrap();
        assert_eq!(
            listing,
            Listing {
                names: vec![name],
                in_flight: 1,
                ignored: 2
            }
        );
    }

    #[test]
    fn a_missing_object_is_gone_not_an_error() {
        let (_folder, store) = store();
        assert!(store.read(&Name::random()).unwrap().is_none());
        store.remove(&Name::random()).unwrap();
        let name = store.write(b"x").unwrap();
        store.remove(&name).unwrap();
        assert!(store.read(&name).unwrap().is_none());
    }

    #[test]
    fn caps_on_size_and_count_hold() {
        let (_folder, mut store) = store();
        store.max_bytes = 4;
        assert!(store.write(b"12345").is_err());
        store.max_bytes = 8;
        let name = store.write(b"12345").unwrap();
        store.max_bytes = 4;
        assert!(store.read(&name).is_err());
        store.max_objects = 1;
        store.write(b"1").unwrap();
        assert!(store.list().is_err());
    }

    #[test]
    fn a_hard_link_is_refused() {
        let (folder, store) = store();
        let outside = folder.0.as_path().join("secret");
        fs::write(&outside, b"local file").unwrap();
        let name = Name::random();
        fs::hard_link(&outside, store.path().join(name.to_string())).unwrap();
        assert!(store.read(&name).is_err());
    }

    #[test]
    fn stale_writes_in_flight_are_swept() {
        let (_folder, store) = store();
        let name = store.write(b"kept").unwrap();
        fs::write(store.path().join(format!("{TMP_PREFIX}old")), b"").unwrap();
        assert_eq!(store.sweep(Duration::from_secs(3600)).unwrap(), 0);
        assert_eq!(store.sweep(Duration::ZERO).unwrap(), 1);
        assert_eq!(store.list().unwrap().names, vec![name]);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_and_fifos_are_refused_without_blocking() {
        let (folder, store) = store();
        let outside = folder.0.as_path().join("secret");
        fs::write(&outside, b"local file").unwrap();
        let link = Name::random();
        std::os::unix::fs::symlink(&outside, store.path().join(link.to_string())).unwrap();
        assert!(store.read(&link).is_err());

        let fifo = Name::random();
        let path = std::ffi::CString::new(
            store
                .path()
                .join(fifo.to_string())
                .into_os_string()
                .into_encoded_bytes(),
        )
        .unwrap();
        // SAFETY: a valid C string for the duration of the call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(store.read(&fifo).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn an_objects_directory_that_is_a_symlink_is_refused() {
        let folder = scratch();
        let elsewhere = folder.0.as_path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let vault = folder.0.as_path().join("vault");
        fs::create_dir(&vault).unwrap();
        std::os::unix::fs::symlink(&elsewhere, vault.join("objects")).unwrap();
        assert!(Store::open(&vault, false).is_err());
    }

    #[test]
    fn a_missing_folder_is_created_only_when_asked() {
        let folder = scratch();
        assert!(Store::open(folder.0.as_path(), false).is_err());
        assert!(Store::open(folder.0.as_path(), true).is_ok());
        assert!(Store::open(folder.0.as_path(), false).is_ok());
    }

    #[test]
    fn an_error_names_what_was_refused() {
        let (_folder, store) = store();
        let name = Name::random();
        fs::create_dir(store.path().join(name.to_string())).unwrap();
        let message = format!("{:#}", store.read(&name).unwrap_err());
        assert!(message.contains(&name.to_string()), "{message}");
    }
}
