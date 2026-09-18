//! Where the vault keeps its files, and reading and writing them safely.
//!
//! Files are written to a temporary file and renamed into place, so a crash
//! never leaves one half written, and a link is never followed to reach one.
//!
//! On Unix they are created readable by their owner alone, and refused when
//! they are not regular files, belong to another user, or could have been
//! changed by another user. Windows has no mode bits, so none of those checks
//! happen there: the default directory inside the user's profile is what keeps
//! other users out, and a directory chosen with `--home` is not checked.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};

use crate::vault::model::check_vault_name;

/// The environment variable naming the vault directory, for a portable
/// install or a second, separate set of vaults.
pub const HOME_VARIABLE: &str = "TXC_VAULT_HOME";

const IDENTITY_FILE: &str = "identity.age";
const TRUST_FILE: &str = "trust.json";
const VAULTS_DIR: &str = "vaults";
const VAULT_SUFFIX: &str = ".vault.age";

/// The largest identity file read, in bytes.
pub(crate) const IDENTITY_LIMIT: usize = 64 * 1024;
/// The largest trust file read, in bytes.
pub(crate) const TRUST_LIMIT: usize = 4 * 1024 * 1024;
/// The largest vault file read, in bytes.
pub(crate) const VAULT_LIMIT: usize = 64 * 1024 * 1024;

/// Permission bits that must be clear on something only its owner may read:
/// the identity, the trust records and the directory holding them.
pub(crate) const PRIVATE: u32 = 0o077;
/// Permission bits that must be clear on something only its owner may
/// change: the vault files, which are encrypted but must not be replaced.
pub(crate) const UNCHANGEABLE: u32 = 0o022;

/// The directory holding the identity, the trust records and the vaults.
///
/// ```
/// use txc::vault::Home;
///
/// let home = Home::at("/tmp/example-vault-home");
/// assert!(home.identity_path().ends_with("identity.age"));
/// assert!(home.vault_path("work")?.ends_with("vaults/work.vault.age"));
/// // Names are checked before they become paths.
/// assert!(home.vault_path("../escape").is_err());
/// # Ok::<(), anyhow::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Home {
    root: PathBuf,
}

impl Home {
    /// Finds the vault directory: the path given, then `TXC_VAULT_HOME`, then
    /// the platform's place for application data.
    ///
    /// # Errors
    ///
    /// Returns an error when `TXC_VAULT_HOME` is not absolute, or when no
    /// home directory can be found.
    pub fn locate(explicit: Option<&Path>) -> Result<Self> {
        if let Some(path) = explicit {
            return Ok(Self::at(path));
        }
        if let Some(value) = std::env::var_os(HOME_VARIABLE).filter(|v| !v.is_empty()) {
            let path = PathBuf::from(value);
            ensure!(
                path.is_absolute(),
                "{HOME_VARIABLE} must be an absolute path"
            );
            return Ok(Self::at(path));
        }
        default_root().map(Self::at)
    }

    /// A vault directory at a known path.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The directory itself.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The passphrase protected identity.
    #[must_use]
    pub fn identity_path(&self) -> PathBuf {
        self.root.join(IDENTITY_FILE)
    }

    /// The record of which vaults this device trusts.
    #[must_use]
    pub fn trust_path(&self) -> PathBuf {
        self.root.join(TRUST_FILE)
    }

    /// The directory of vault files, which is the part to copy between
    /// devices.
    #[must_use]
    pub fn vaults_dir(&self) -> PathBuf {
        self.root.join(VAULTS_DIR)
    }

    /// The file of the vault with this name.
    ///
    /// # Errors
    ///
    /// Returns an error when the name is not a valid vault name.
    pub fn vault_path(&self, name: &str) -> Result<PathBuf> {
        check_vault_name(name)?;
        Ok(self.vaults_dir().join(format!("{name}{VAULT_SUFFIX}")))
    }

    /// Whether an identity has been created here.
    #[must_use]
    pub fn has_identity(&self) -> bool {
        fs::symlink_metadata(self.identity_path()).is_ok()
    }

    /// The names of the vaults here, sorted. Reading a name needs no key, so
    /// nothing is decrypted.
    ///
    /// Anything that is not a regular file with a valid name is left out,
    /// symbolic links included.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory exists but cannot be read.
    pub fn vault_names(&self) -> Result<Vec<String>> {
        let dir = self.vaults_dir();
        let listing = match fs::read_dir(&dir) {
            Ok(listing) => listing,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error).with_context(|| format!("cannot list {}", dir.display()));
            }
        };

        let mut names = Vec::new();
        for item in listing {
            let item = item.with_context(|| format!("cannot list {}", dir.display()))?;
            let file_name = item.file_name();
            let Some(name) = file_name
                .to_str()
                .and_then(|file_name| file_name.strip_suffix(VAULT_SUFFIX))
            else {
                continue;
            };
            if check_vault_name(name).is_ok() && item.file_type()?.is_file() {
                names.push(name.to_string());
            }
        }
        names.sort();
        Ok(names)
    }

    /// Creates the directories, readable by their owner alone, and checks
    /// that nobody else can reach into them.
    pub(crate) fn prepare(&self) -> Result<()> {
        private_dir(&self.root, PRIVATE)?;
        private_dir(&self.vaults_dir(), UNCHANGEABLE)
    }

    /// Checks the directories that already exist, without creating any.
    pub(crate) fn check(&self) -> Result<()> {
        check_dir(&self.root, PRIVATE)?;
        if fs::symlink_metadata(self.vaults_dir()).is_ok() {
            check_dir(&self.vaults_dir(), UNCHANGEABLE)?;
        }
        Ok(())
    }
}

/// Creates a directory if it is missing, then checks it.
fn private_dir(path: &Path, forbidden: u32) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("cannot create {}", path.display()))?;
    check_dir(path, forbidden)
}

fn check_dir(path: &Path, forbidden: u32) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("cannot read {}", path.display()))?;
    ensure!(
        metadata.is_dir(),
        "{} is not a directory; txc does not follow links here",
        path.display()
    );
    check_permissions(path, &metadata, forbidden)
}

/// Refuses a file or directory owned by someone else, or open to them in a
/// way `forbidden` rules out.
#[cfg(unix)]
fn check_permissions(path: &Path, metadata: &fs::Metadata, forbidden: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    ensure!(
        metadata.uid() == crate::vault::harden::user_id(),
        "{} belongs to another user, so txc will not trust it",
        path.display()
    );
    let mode = metadata.mode() & 0o777;
    let (what, fix) = if forbidden == PRIVATE {
        ("read or changed", "go-rwx")
    } else {
        ("changed", "go-w")
    };
    ensure!(
        mode & forbidden == 0,
        "{} can be {what} by other users (mode {mode:o}); fix it with: chmod {fix} {}",
        path.display(),
        path.display()
    );
    Ok(())
}

/// Windows has no mode bits, and nothing is checked there. Under the default
/// directory, inside the user's profile, its access list already keeps other
/// users out; a directory chosen with `--home` or `TXC_VAULT_HOME` is not
/// checked at all.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
const fn check_permissions(_: &Path, _: &fs::Metadata, _: u32) -> Result<()> {
    Ok(())
}

/// Reads a whole file the vault owns.
///
/// Links are not followed, the checks are made on the file actually opened
/// rather than on the path, and nothing larger than `limit` is read.
pub(crate) fn read_private(path: &Path, limit: usize, forbidden: u32) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Opens a symbolic link or a junction itself rather than whatever it
        // points at, so the check below refuses it as not a regular file.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("cannot read {}", path.display()))?;
    ensure!(
        metadata.is_file(),
        "{} is not a regular file",
        path.display()
    );
    check_permissions(path, &metadata, forbidden)?;
    ensure!(
        metadata.len() <= limit as u64,
        "{} is larger than anything txc writes, so it is not read",
        path.display()
    );

    // Sized up front, so the buffer is never reallocated and copied.
    let mut bytes = Vec::with_capacity(limit.min(metadata.len() as usize).saturating_add(1));
    file.take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read {}", path.display()))?;
    ensure!(
        bytes.len() <= limit,
        "{} grew while it was being read",
        path.display()
    );
    Ok(bytes)
}

/// Whether a file is there at all, without following a link to decide.
pub(crate) fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Replaces a file in one step: the new content goes to a temporary file in
/// the same directory, is flushed to disk, and is renamed over the old one.
///
/// With `backup`, the previous content is kept beside it with `.bak` added,
/// replaced the same way.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8], backup: Option<u32>) -> Result<()> {
    let dir = path.parent().context("a vault file has a directory")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("vault file names are UTF-8")?;

    if let Some(forbidden) = backup
        && exists(path)
    {
        let previous = read_private(path, VAULT_LIMIT, forbidden)?;
        replace(dir, &format!("{name}.bak"), &previous)?;
    }
    replace(dir, name, bytes)
}

fn replace(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let temporary = dir.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4().simple()));
    let target = dir.join(name);

    let written = (|| -> io::Result<()> {
        let mut file = create_private(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        rename_over(&temporary, &target)?;
        sync_dir(dir)
    })();

    if written.is_err() {
        // Best effort: the write already failed, so a failed cleanup of the
        // temporary file changes nothing we can report.
        fs::remove_file(&temporary).ok();
    }
    written.with_context(|| format!("cannot write {}", target.display()))
}

/// Renames the temporary file over the target.
///
/// On Windows this fails while another program holds the target open, which a
/// sync client, a search indexer or a virus scanner does as a matter of
/// course, and succeeds a moment later. Everywhere else the rename either
/// works or fails for good, so it is tried once.
fn rename_over(temporary: &Path, target: &Path) -> io::Result<()> {
    #[cfg(windows)]
    for wait in [20, 40, 80, 160] {
        match fs::rename(temporary, target) {
            Ok(()) => return Ok(()),
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(wait)),
        }
    }
    fs::rename(temporary, target)
}

/// Creates a new file that only its owner can read, failing if anything is
/// already at that path, a link included.
fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// Flushes a directory, which is what makes a rename survive a power cut.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
const fn sync_dir(_: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn default_root() -> Result<PathBuf> {
    let base = std::env::var_os("APPDATA")
        .filter(|value| !value.is_empty())
        .context("cannot find the application data directory; set APPDATA or TXC_VAULT_HOME")?;
    Ok(PathBuf::from(base).join("txc").join("vault"))
}

#[cfg(target_os = "macos")]
fn default_root() -> Result<PathBuf> {
    Ok(user_home()?.join("Library/Application Support/txc/vault"))
}

#[cfg(all(not(windows), not(target_os = "macos")))]
fn default_root() -> Result<PathBuf> {
    // The XDG rules say a relative value is to be ignored.
    let base = match std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
    {
        Some(path) => path,
        None => user_home()?.join(".local/share"),
    };
    Ok(base.join("txc").join("vault"))
}

#[cfg(not(windows))]
fn user_home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .context("cannot find your home directory; set HOME or TXC_VAULT_HOME")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fresh directory for one test, removed when dropped.
    pub struct Scratch(pub PathBuf);

    impl Scratch {
        pub fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "txc-vault-{label}-{}-{}",
                std::process::id(),
                uuid::Uuid::new_v4().simple()
            ));
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_write_replaces_the_file_and_keeps_the_previous_one() {
        let scratch = Scratch::new("atomic");
        let home = Home::at(&scratch.0);
        home.prepare().unwrap();
        let path = home.vault_path("work").unwrap();

        write_atomic(&path, b"first", Some(UNCHANGEABLE)).unwrap();
        write_atomic(&path, b"second", Some(UNCHANGEABLE)).unwrap();

        assert_eq!(read_private(&path, 100, UNCHANGEABLE).unwrap(), b"second");
        let backup = path.with_file_name("work.vault.age.bak");
        assert_eq!(fs::read(backup).unwrap(), b"first");
        // No temporary file is left behind.
        let leftovers = fs::read_dir(home.vaults_dir())
            .unwrap()
            .filter(|item| {
                item.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn only_valid_regular_files_are_listed_as_vaults() {
        let scratch = Scratch::new("names");
        let home = Home::at(&scratch.0);
        home.prepare().unwrap();
        let dir = home.vaults_dir();
        fs::write(dir.join("work.vault.age"), b"x").unwrap();
        fs::write(dir.join("personal.vault.age"), b"x").unwrap();
        fs::write(dir.join("Bad Name.vault.age"), b"x").unwrap();
        fs::write(dir.join("notes.txt"), b"x").unwrap();
        fs::create_dir(dir.join("folder.vault.age")).unwrap();

        assert_eq!(home.vault_names().unwrap(), ["personal", "work"]);
    }

    #[test]
    fn a_missing_directory_has_no_vaults() {
        let home = Home::at(std::env::temp_dir().join("txc-vault-does-not-exist"));
        assert!(home.vault_names().unwrap().is_empty());
    }

    #[test]
    fn a_file_larger_than_the_limit_is_not_read() {
        let scratch = Scratch::new("limit");
        let home = Home::at(&scratch.0);
        home.prepare().unwrap();
        let path = home.vault_path("big").unwrap();
        write_atomic(&path, &[0; 64], None).unwrap();
        assert!(read_private(&path, 63, UNCHANGEABLE).is_err());
        assert!(read_private(&path, 64, UNCHANGEABLE).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn files_are_created_private_and_open_files_are_refused() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = Scratch::new("modes");
        let home = Home::at(&scratch.0);
        home.prepare().unwrap();
        let root_mode = fs::metadata(home.root()).unwrap().permissions().mode() & 0o777;
        assert_eq!(root_mode, 0o700);

        let path = home.identity_path();
        write_atomic(&path, b"key", None).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = read_private(&path, 100, PRIVATE).unwrap_err().to_string();
        assert!(error.contains("other users"), "{error}");

        fs::set_permissions(home.root(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(home.check().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn links_are_not_followed() {
        let scratch = Scratch::new("links");
        let home = Home::at(&scratch.0);
        home.prepare().unwrap();
        let real = scratch.0.join("real");
        write_atomic(&real, b"secret", None).unwrap();
        let link = home.vault_path("linked").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(read_private(&link, 100, UNCHANGEABLE).is_err());
        assert!(home.vault_names().unwrap().is_empty());
    }
}
