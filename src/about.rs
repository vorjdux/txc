//! Who wrote this, and under what terms.
//!
//! Everything here comes from the package metadata, so the answer cannot drift
//! away from what is actually published.

use std::fmt::Write;

use crate::registry::{self, Category};

/// The crate name, which is also the name of the binary.
pub const NAME: &str = env!("CARGO_PKG_NAME");
/// The published version, as `txc --version` reports it.
///
/// ```
/// assert!(txc::about::VERSION.split('.').count() >= 3);
/// ```
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The one line description from the manifest.
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
/// The licence expression the crate is published under.
///
/// ```
/// assert_eq!(txc::about::LICENSE, "MIT OR Apache-2.0");
/// ```
pub const LICENSE: &str = env!("CARGO_PKG_LICENSE");
/// Where the source lives.
pub const REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// The year the project started, for the copyright line.
pub const SINCE: &str = "2022";

/// The authors, one per entry. Cargo separates them with colons.
///
/// ```
/// assert!(!txc::about::authors().is_empty());
/// ```
#[must_use]
pub fn authors() -> Vec<&'static str> {
    env!("CARGO_PKG_AUTHORS")
        .split(':')
        .filter(|author| !author.is_empty())
        .collect()
}

/// The author line as it should be read, without the address.
///
/// ```
/// // The email address is dropped; the name is kept.
/// assert!(!txc::about::author_names().contains('<'));
/// ```
#[must_use]
pub fn author_names() -> String {
    authors()
        .iter()
        .map(|author| author.split('<').next().unwrap_or(author).trim())
        .collect::<Vec<_>>()
        .join(", ")
}

/// How many operations are registered, and across how many categories.
///
/// ```
/// let (operations, categories) = txc::about::catalogue();
/// assert!(operations > 100);
/// assert_eq!(categories, 10);
/// ```
#[must_use]
pub fn catalogue() -> (usize, usize) {
    (registry::all().len(), Category::ALL.len())
}

/// The label rows shown in the About view and by `txc about`.
///
/// ```
/// let rows = txc::about::rows();
/// assert!(rows.iter().any(|(label, _)| *label == "Version"));
/// assert!(rows.iter().all(|(_, value)| !value.is_empty()));
/// ```
#[must_use]
pub fn rows() -> Vec<(&'static str, String)> {
    let (operations, categories) = catalogue();
    let mut rows = vec![
        ("Version", VERSION.to_string()),
        (
            "Operations",
            format!("{operations} in {categories} categories"),
        ),
    ];
    for (index, author) in authors().iter().enumerate() {
        rows.push((
            if index == 0 { "Author" } else { "" },
            (*author).to_string(),
        ));
    }
    rows.push(("Repository", REPOSITORY.to_string()));
    rows.push(("License", LICENSE.to_string()));
    rows.push(("Copyright", format!("{SINCE} {}", author_names())));
    rows
}

/// The whole thing as text, for `txc about`.
///
/// ```
/// let report = txc::about::report();
/// assert!(report.contains(txc::about::VERSION));
/// assert!(report.contains("MIT OR Apache-2.0"));
/// ```
#[must_use]
pub fn report() -> String {
    let width = rows()
        .iter()
        .map(|(label, _)| label.len())
        .max()
        .unwrap_or(0);

    let mut out = format!("{NAME} — {DESCRIPTION}\n\n");
    for (label, value) in rows() {
        if label.is_empty() {
            let _ = writeln!(out, "{:width$}  {value}", "");
        } else {
            let _ = writeln!(out, "{label:width$}  {value}");
        }
    }
    out.push_str(
        "\nYour text never leaves this machine: txc makes no network requests.\n\
         Licensed under either of Apache-2.0 or MIT, at your option.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_author_is_named() {
        assert!(!authors().is_empty(), "the package declares no author");
        assert!(authors()[0].contains("Matheus Santos"), "{:?}", authors());
        assert_eq!(author_names(), "Matheus Santos");
    }

    #[test]
    fn the_details_come_from_the_package() {
        assert_eq!(NAME, "txc");
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(LICENSE, "MIT OR Apache-2.0");
        assert!(REPOSITORY.starts_with("https://"), "{REPOSITORY}");
    }

    #[test]
    fn the_catalogue_count_is_the_real_one() {
        let (operations, categories) = catalogue();
        assert_eq!(operations, registry::all().len());
        assert_eq!(categories, Category::ALL.len());
    }

    #[test]
    fn the_report_names_everything_that_matters() {
        let report = report();
        for expected in [
            "txc",
            "Matheus Santos",
            "vorj.dux@gmail.com",
            "MIT OR Apache-2.0",
            "github.com/vorjdux/txc",
            "never leaves this machine",
        ] {
            assert!(
                report.contains(expected),
                "{expected:?} missing from:\n{report}"
            );
        }
    }
}
