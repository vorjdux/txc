//! The keyholder: a small process that alone holds a synced vault's keys
//! (study sections 4 and 11).
//!
//! A long-running front end, such as the interactive screen, starts one
//! keyholder per synced vault as a child, `txc vault keyholder`, and talks
//! to it over its standard input and output. The keyholder opens the vault,
//! then confines itself: its own files only, no network socket and no
//! program. The front end never holds a vault key: it gets entries with
//! their secrets sealed, and one secret when the person asks to copy or see
//! it, which is the release the clipboard and the screen need.
//!
//! Messages are length-prefixed JSON; both ends are the same txc binary.

use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context as _, Result, anyhow, bail, ensure};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::vault::confine;
use crate::vault::home::Home;
use crate::vault::model::{Entry, Kind};
use crate::vault::synced::Synced;
use crate::vault::{Change, NewEntry, session, synced_command, synced_model};

/// The largest message either side accepts.
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// What the front end asks.
#[derive(Serialize, Deserialize)]
enum Request {
    /// Open the vault: from the session when `passphrase` is `None`.
    Open {
        name: String,
        passphrase: Option<String>,
    },
    Entries,
    Reveal {
        entry: String,
        field: String,
    },
    Add {
        name: String,
        kind: String,
        plain: Vec<(String, String)>,
        secrets: Vec<(String, String)>,
        tags: Vec<String>,
        favourite: bool,
    },
    Change {
        name: String,
        rename: Option<String>,
        plain: Vec<(String, String)>,
        secrets: Vec<(String, String)>,
        remove: Vec<String>,
        tag: Vec<String>,
        untag: Vec<String>,
        favourite: Option<bool>,
    },
    Remove {
        name: String,
    },
    Sync,
    Status,
    Classes,
}

/// What the keyholder answers.
#[derive(Serialize, Deserialize)]
enum Response {
    Done,
    Entries(Vec<Entry>),
    Secret(String),
    Lines(Vec<String>),
    Classes(Vec<(String, String)>),
    Failed(String),
}

fn write_message<T: Serialize>(out: &mut impl Write, message: &T) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(message)?);
    let length = u32::try_from(bytes.len()).context("a message is too large")?;
    out.write_all(&length.to_be_bytes())?;
    out.write_all(&bytes)?;
    out.flush()?;
    Ok(())
}

fn read_message<T: for<'de> Deserialize<'de>>(input: &mut impl Read) -> Result<Option<T>> {
    let mut length = [0_u8; 4];
    match input.read_exact(&mut length) {
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        other => other?,
    }
    let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
    ensure!(length <= MAX_MESSAGE, "a message is too large");
    let mut bytes = Zeroizing::new(vec![0; length]);
    input.read_exact(&mut bytes)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

fn secret_pairs(pairs: Vec<(String, String)>) -> Vec<(String, SecretString)> {
    pairs
        .into_iter()
        .map(|(name, value)| (name, SecretString::from(value)))
        .collect()
}

fn revealed_pairs(pairs: &[(String, SecretString)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, value)| (name.clone(), value.expose_secret().to_owned()))
        .collect()
}

// ------------------------------------------------------------ the keyholder --

fn answer(
    home: &Home,
    vault: &mut Option<Synced>,
    request: Request,
    confined: bool,
) -> Result<Response> {
    if let Request::Open { name, passphrase } = request {
        ensure!(vault.is_none(), "this keyholder already holds a vault");
        let mut opened = if let Some(passphrase) = passphrase {
            Synced::open(
                home,
                &name,
                &SecretString::from(passphrase),
                &crate::vault::hardware::NoTerminal,
            )?
        } else {
            let session::Resumed::Open(mut contents) = session::resume(home)? else {
                bail!("there is no session to open {name} from");
            };
            let kek = contents
                .synced
                .remove(&name)
                .with_context(|| format!("the session does not hold {name}"))?;
            Synced::open_with(home, &name, kek)?
        };
        opened.sync()?;
        // Everything from outside (the keystore, the session) is done:
        // from here on this process reaches only its own files.
        let objects = opened.store().path().to_path_buf();
        // What this system cannot confine is listed by status --all.
        if confined {
            let _confinement = confine::confine(&[home.root(), &objects], &[]);
        }
        *vault = Some(opened);
        return Ok(Response::Done);
    }
    let vault = vault.as_mut().context("no vault is open")?;
    Ok(match request {
        Request::Open { .. } => unreachable!("handled above"),
        Request::Entries => Response::Entries(synced_model::entries(vault)?),
        Request::Reveal { entry, field } => Response::Secret(
            synced_command::reveal(vault, &entry, Some(&field))?
                .expose_secret()
                .to_owned(),
        ),
        Request::Add {
            name,
            kind,
            plain,
            secrets,
            tags,
            favourite,
        } => {
            let kind = Kind::from_id(&kind).context("an unknown kind")?;
            let new = NewEntry {
                name,
                kind,
                plain,
                secrets: secret_pairs(secrets),
                tags,
                favourite,
            };
            synced_model::add(vault, &new)?;
            Response::Done
        }
        Request::Change {
            name,
            rename,
            plain,
            secrets,
            remove,
            tag,
            untag,
            favourite,
        } => {
            let change = Change {
                rename,
                plain,
                secrets: secret_pairs(secrets),
                remove,
                tag,
                untag,
                favourite,
            };
            synced_model::change(vault, &name, &change)?;
            Response::Done
        }
        Request::Remove { name } => {
            synced_model::remove(vault, &name)?;
            Response::Done
        }
        Request::Status => Response::Lines(synced_command::status_lines(home, vault, None)?),
        Request::Classes => Response::Classes(synced_model::classes(vault)?),
        Request::Sync => {
            vault.sync()?;
            Response::Done
        }
    })
}

/// Runs `txc vault keyholder`: serves requests on standard input until it
/// closes.
///
/// # Errors
///
/// Returns an error when the pipe breaks.
pub fn serve(home: &Home) -> Result<()> {
    crate::vault::harden::process();
    let mut input = BufReader::new(io::stdin().lock());
    let mut output = BufWriter::new(io::stdout().lock());
    let mut vault = None;
    while let Some(request) = read_message::<Request>(&mut input)? {
        let response = answer(home, &mut vault, request, true)
            .unwrap_or_else(|error| Response::Failed(format!("{error:#}")));
        write_message(&mut output, &response)?;
    }
    Ok(())
}

// ------------------------------------------------------------ the front end --

/// A synced vault as a front end holds it: through a keyholder process, or
/// in this process where no keyholder can be started (unit tests).
pub enum Holder {
    /// A keyholder child.
    Remote(Box<Remote>),
    /// The vault in this process.
    Local(Box<Local>),
}

/// A vault held in this process, answering as a keyholder would but never
/// confining it: the process is a front end.
pub struct Local {
    home: Home,
    vault: Option<Synced>,
}

/// A running keyholder.
pub struct Remote {
    child: Child,
    input: Option<BufWriter<ChildStdin>>,
    output: BufReader<ChildStdout>,
}

impl Remote {
    fn ask(&mut self, request: &Request) -> Result<Response> {
        write_message(
            self.input.as_mut().context("the keyholder is closed")?,
            request,
        )?;
        read_message(&mut self.output)?.context("the keyholder stopped")
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        // Closing its input ends it, and waiting reaps it.
        self.input.take();
        self.child.wait().ok();
    }
}

impl Holder {
    /// Starts a keyholder with `program` (the txc binary) and opens a vault
    /// in it, from the session or with the passphrase.
    ///
    /// # Errors
    ///
    /// Returns an error when the keyholder does not start or the vault does
    /// not open.
    pub fn spawn(
        program: &Path,
        home: &Home,
        name: &str,
        passphrase: Option<&SecretString>,
    ) -> Result<Self> {
        let mut command = Command::new(program);
        command
            .arg("vault")
            .arg("--home")
            .arg(home.root())
            .arg("keyholder");
        Self::start(command, name, passphrase)
    }

    /// Starts a keyholder from a prepared command, `txc vault ... keyholder`,
    /// and opens a vault in it.
    ///
    /// # Errors
    ///
    /// Returns an error when the keyholder does not start or the vault does
    /// not open.
    pub fn start(
        mut command: Command,
        name: &str,
        passphrase: Option<&SecretString>,
    ) -> Result<Self> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("cannot start the keyholder")?;
        let input = BufWriter::new(child.stdin.take().context("the keyholder has no input")?);
        let output = BufReader::new(child.stdout.take().context("the keyholder has no output")?);
        let mut remote = Remote {
            child,
            input: Some(input),
            output,
        };
        let request = Request::Open {
            name: name.to_owned(),
            passphrase: passphrase.map(|passphrase| passphrase.expose_secret().to_owned()),
        };
        match remote.ask(&request)? {
            Response::Done => Ok(Self::Remote(Box::new(remote))),
            Response::Failed(message) => bail!("{message}"),
            _ => bail!("the keyholder answered out of turn"),
        }
    }

    /// The keyholder's process id, when it runs as its own process.
    #[must_use]
    pub fn process_id(&self) -> Option<u32> {
        match self {
            Self::Remote(remote) => Some(remote.child.id()),
            Self::Local(_) => None,
        }
    }

    /// Holds a vault in this process, opened from the session or with the
    /// passphrase, where no keyholder can be started.
    ///
    /// # Errors
    ///
    /// Returns an error when the vault does not open.
    pub fn local(home: &Home, name: &str, passphrase: Option<&SecretString>) -> Result<Self> {
        let mut local = Local {
            home: home.clone(),
            vault: None,
        };
        let request = Request::Open {
            name: name.to_owned(),
            passphrase: passphrase.map(|passphrase| passphrase.expose_secret().to_owned()),
        };
        match answer(&local.home, &mut local.vault, request, false)? {
            Response::Done => Ok(Self::Local(Box::new(local))),
            _ => bail!("the vault did not open"),
        }
    }

    fn ask(&mut self, request: Request) -> Result<Response> {
        match self {
            Self::Remote(remote) => remote.ask(&request),
            Self::Local(local) => answer(&local.home, &mut local.vault, request, false),
        }
    }

    fn done(&mut self, request: Request) -> Result<()> {
        match self.ask(request)? {
            Response::Done => Ok(()),
            Response::Failed(message) => Err(anyhow!("{message}")),
            _ => bail!("the keyholder answered out of turn"),
        }
    }

    /// The entries, with their secrets sealed.
    ///
    /// # Errors
    ///
    /// Returns an error when the keyholder fails.
    pub fn entries(&mut self) -> Result<Vec<Entry>> {
        match self.ask(Request::Entries)? {
            Response::Entries(entries) => Ok(entries),
            Response::Failed(message) => Err(anyhow!("{message}")),
            _ => bail!("the keyholder answered out of turn"),
        }
    }

    /// One secret, released for the clipboard or the screen.
    ///
    /// # Errors
    ///
    /// Returns an error when the field does not exist or is never released.
    pub fn reveal(&mut self, entry: &str, field: &str) -> Result<SecretString> {
        match self.ask(Request::Reveal {
            entry: entry.to_owned(),
            field: field.to_owned(),
        })? {
            Response::Secret(secret) => Ok(SecretString::from(secret)),
            Response::Failed(message) => Err(anyhow!("{message}")),
            _ => bail!("the keyholder answered out of turn"),
        }
    }

    /// Adds an entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the keyholder refuses.
    pub fn add(&mut self, new: &NewEntry) -> Result<()> {
        self.done(Request::Add {
            name: new.name.clone(),
            kind: new.kind.id().to_owned(),
            plain: new.plain.clone(),
            secrets: revealed_pairs(&new.secrets),
            tags: new.tags.clone(),
            favourite: new.favourite,
        })
    }

    /// Changes an entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the keyholder refuses.
    pub fn change(&mut self, name: &str, change: &Change) -> Result<()> {
        self.done(Request::Change {
            name: name.to_owned(),
            rename: change.rename.clone(),
            plain: change.plain.clone(),
            secrets: revealed_pairs(&change.secrets),
            remove: change.remove.clone(),
            tag: change.tag.clone(),
            untag: change.untag.clone(),
            favourite: change.favourite,
        })
    }

    /// Removes an entry.
    ///
    /// # Errors
    ///
    /// Returns an error when the keyholder refuses.
    pub fn remove(&mut self, name: &str) -> Result<()> {
        self.done(Request::Remove {
            name: name.to_owned(),
        })
    }

    /// What needs the person, as `txc vault status` shows it.
    ///
    /// # Errors
    ///
    /// Returns an error when the keyholder fails.
    pub fn status(&mut self) -> Result<Vec<String>> {
        match self.ask(Request::Status)? {
            Response::Lines(lines) => Ok(lines),
            Response::Failed(message) => Err(anyhow!("{message}")),
            _ => bail!("the keyholder answered out of turn"),
        }
    }

    /// Each entry's class, by name, for entries that are not normal:
    /// `protected` or `operation-only`.
    ///
    /// # Errors
    ///
    /// Returns an error when the keyholder fails.
    pub fn classes(&mut self) -> Result<Vec<(String, String)>> {
        match self.ask(Request::Classes)? {
            Response::Classes(classes) => Ok(classes),
            Response::Failed(message) => Err(anyhow!("{message}")),
            _ => bail!("the keyholder answered out of turn"),
        }
    }

    /// Reads what other devices wrote.
    ///
    /// # Errors
    ///
    /// Returns an error when the keyholder fails.
    pub fn sync(&mut self) -> Result<()> {
        self.done(Request::Sync)
    }
}
