//! Putting a secret on the clipboard, and taking it off again.
//!
//! Unlike the interface's ordinary copy, this never falls back to asking the
//! terminal. That route would send the secret through the terminal's own
//! stream, through tmux, and possibly into a scrollback log. When no clipboard
//! can be reached the copy fails, and says to use `--print` instead.
//!
//! The secret is marked so clipboard managers leave it out of their history:
//! the KDE password manager hint on Linux, which the common managers honour;
//! the concealed type from nspasteboard.org on macOS; and on Windows the
//! format that keeps it out of clipboard history, the cloud clipboard and
//! clipboard monitors.
//!
//! On Linux the clipboard holds only what a program keeps serving. That is
//! done from a thread of this process. The other way, a forked child, would
//! carry a copy of all of this process's memory, unlocked identity included,
//! for as long as the clipboard kept the secret.

// The only arithmetic here adds a few seconds to `Instant::now()` for a
// deadline, which cannot overflow on any real clock.
#![allow(clippy::arithmetic_side_effects)]

use std::thread;
use std::time::{Duration, Instant};

use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Result, anyhow, bail};
use zeroize::Zeroizing;

use crate::vault::crypto;

/// How long a copied secret stays on the clipboard unless asked otherwise.
pub const DEFAULT_CLEAR_SECONDS: u64 = 20;

/// The longest a copied secret may stay on the clipboard.
pub const MAX_CLEAR_SECONDS: u64 = 300;

/// A secret this process put on the clipboard.
pub struct Held {
    digest: [u8; 32],
    server: platform::Server,
}

/// Puts a secret on the clipboard, and confirms it arrived by reading it back.
///
/// # Errors
///
/// Returns an error when there is no clipboard to reach, or when it did not
/// take the secret.
pub fn copy(secret: &SecretString) -> Result<Held> {
    let digest = crypto::sha256(&[secret.expose_secret().as_bytes()]);
    let mut server = platform::put(secret)?;

    // A clipboard can refuse without saying so, so only reading the text back
    // proves it arrived.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if current_digest() == Some(digest) {
            return Ok(Held { digest, server });
        }
        if let Some(problem) = server.failed() {
            bail!("could not copy to the clipboard: {problem}");
        }
        if Instant::now() >= deadline {
            server.finish();
            bail!("the clipboard did not take the secret");
        }
        thread::sleep(Duration::from_millis(50));
    }
}

impl Held {
    /// Whether the clipboard still holds the secret, rather than something
    /// copied since.
    #[must_use]
    pub fn still_held(&self) -> bool {
        current_digest() == Some(self.digest)
    }

    /// Whether something else is known to have taken the clipboard over.
    ///
    /// Only Linux can tell without reading the clipboard, because only there
    /// does this process serve it; elsewhere this is always false.
    #[must_use]
    // On every platform but Linux the answer is a constant, so clippy asks
    // there for a const fn that Linux, which really looks, cannot provide.
    #[allow(clippy::missing_const_for_fn)]
    pub fn taken_over(&self) -> bool {
        self.server.done()
    }

    /// Takes the secret off the clipboard, if it is still there. Something
    /// copied since is left alone. Returns whether the secret was there.
    ///
    /// # Errors
    ///
    /// Returns an error when the clipboard held the secret but could not be
    /// cleared.
    pub fn clear(self) -> Result<bool> {
        let held = self.still_held();
        if held {
            arboard::Clipboard::new()
                .and_then(|mut clipboard| clipboard.clear())
                .map_err(|error| anyhow!("could not clear the clipboard: {error}"))?;
        }
        self.server.finish();
        Ok(held)
    }
}

/// A hash of what the clipboard holds now. The text itself is wiped as soon
/// as it is hashed.
fn current_digest() -> Option<[u8; 32]> {
    let mut clipboard = arboard::Clipboard::new().ok()?;
    let text = Zeroizing::new(clipboard.get_text().ok()?);
    Some(crypto::sha256(&[text.as_bytes()]))
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
))]
mod platform {
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use age::secrecy::{ExposeSecret, SecretString};
    use anyhow::{Context, Result};
    use arboard::SetExtLinux;
    use zeroize::Zeroizing;

    /// The thread serving the clipboard. It returns once something else
    /// takes the clipboard over, or it is cleared.
    pub struct Server(Option<JoinHandle<Result<(), arboard::Error>>>);

    pub fn put(secret: &SecretString) -> Result<Server> {
        let text = Zeroizing::new(secret.expose_secret().to_owned());
        let handle = thread::Builder::new()
            .name("txc-clipboard".to_string())
            .spawn(move || {
                let mut clipboard = arboard::Clipboard::new()?;
                clipboard
                    .set()
                    .exclude_from_history()
                    .wait()
                    .text(text.as_str())
            })
            .context("cannot start serving the clipboard")?;
        Ok(Server(Some(handle)))
    }

    impl Server {
        /// Whether serving has stopped, which means the clipboard no longer
        /// holds the secret.
        pub fn done(&self) -> bool {
            self.0.as_ref().is_none_or(JoinHandle::is_finished)
        }

        /// Why serving stopped, if it already has. Stopping this early means
        /// the clipboard never took the secret.
        pub fn failed(&mut self) -> Option<String> {
            if !self.0.as_ref()?.is_finished() {
                return None;
            }
            let handle = self.0.take()?;
            Some(match handle.join() {
                Ok(Err(error)) => error.to_string(),
                _ => "the clipboard was taken over at once".to_string(),
            })
        }

        /// Stops serving, clearing the clipboard if this thread still owns
        /// it, and waits a moment for the thread to end.
        pub fn finish(mut self) {
            let Some(handle) = self.0.take() else {
                return;
            };
            if !handle.is_finished() {
                arboard::Clipboard::new()
                    .and_then(|mut clipboard| clipboard.clear())
                    .ok();
            }
            let deadline = Instant::now() + Duration::from_secs(2);
            while !handle.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            if handle.is_finished() {
                handle.join().ok();
            }
        }
    }
}

#[cfg(not(all(
    unix,
    not(any(target_os = "macos", target_os = "android", target_os = "emscripten"))
)))]
mod platform {
    use age::secrecy::{ExposeSecret, SecretString};
    use anyhow::{Result, anyhow};

    /// Nothing to serve: the system keeps the clipboard itself.
    pub struct Server;

    pub fn put(secret: &SecretString) -> Result<Server> {
        let mut clipboard = arboard::Clipboard::new()
            .map_err(|error| anyhow!("cannot reach the clipboard: {error}"))?;
        let set = clipboard.set();

        #[cfg(target_os = "macos")]
        let set = {
            use arboard::SetExtApple;
            set.exclude_from_history()
        };

        #[cfg(windows)]
        let set = {
            use arboard::SetExtWindows;
            // Covers clipboard history, the cloud clipboard and monitors.
            set.exclude_from_monitoring()
        };

        set.text(secret.expose_secret())
            .map_err(|error| anyhow!("cannot copy to the clipboard: {error}"))?;
        Ok(Server)
    }

    impl Server {
        #[allow(clippy::unused_self)]
        pub const fn done(&self) -> bool {
            false
        }

        #[allow(clippy::unused_self)]
        pub const fn failed(&mut self) -> Option<String> {
            None
        }

        // Takes the server by value as the Linux one does, which has a thread
        // to stop; here there is nothing to do.
        #[allow(clippy::unused_self)]
        pub const fn finish(self) {}
    }
}
