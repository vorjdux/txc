//! `txc` command line entry point.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap_complete::Shell;

use txc::cli;
use txc::input::Source;
use txc::registry::{self, Category};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("txc: {error}");
            for cause in error.chain().skip(1) {
                eprintln!("  caused by: {cause}");
            }
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let mut command = cli::build();

    // With no arguments at all, open the interactive interface when there is a
    // terminal to draw on, and fall back to the help text otherwise.
    if std::env::args_os().len() == 1 {
        return if std::io::stdout().is_terminal() && std::io::stdin().is_terminal() {
            txc::tui::run()
        } else {
            command.print_help()?;
            println!();
            Ok(())
        };
    }

    let matches = command.clone().get_matches();

    let Some((name, sub_matches)) = matches.subcommand() else {
        command.print_help()?;
        println!();
        return Ok(());
    };

    match name {
        "list" => {
            let category = sub_matches
                .get_one::<String>("category")
                .map(String::as_str);
            print!("{}", listing(category, sub_matches.get_flag("names"))?);
            Ok(())
        }
        "completions" => {
            let shell = *sub_matches
                .get_one::<Shell>("shell")
                .expect("shell is required");
            // Generating into a buffer first keeps `txc completions bash | head`
            // from failing on the closed pipe.
            let mut script = Vec::new();
            clap_complete::generate(shell, &mut command, "txc", &mut script);
            txc::input::write(&String::from_utf8(script)?, None, false)
        }
        "tui" => txc::tui::run(),
        _ => {
            let op = registry::find(name)
                .ok_or_else(|| anyhow::anyhow!("unknown operation {name:?}"))?;

            // Generators declare no INPUT argument, so it must not be read.
            let text = if op.feed == registry::Feed::None {
                String::new()
            } else {
                Source {
                    args: sub_matches
                        .try_get_many::<String>("INPUT")
                        .ok()
                        .flatten()
                        .map(|values| values.cloned().collect())
                        .unwrap_or_default(),
                    file: value(sub_matches, "file").map(PathBuf::from),
                    raw: flag(sub_matches, "raw"),
                }
                .read()?
            };

            let line_mode = match (flag(sub_matches, "lines"), flag(sub_matches, "whole")) {
                (true, false) => Some(true),
                (false, true) => Some(false),
                _ => None,
            };

            let params = cli::params_from(op, sub_matches);
            let result = op.apply(&text, &params, line_mode)?;

            let destination = value(sub_matches, "out").map(PathBuf::from);
            txc::input::write(
                &result,
                destination.as_deref(),
                !flag(sub_matches, "no-newline"),
            )
        }
    }
}

/// Reads a switch that the matched operation may not declare.
///
/// Generators have no input options, so asking for one by name has to be a
/// question rather than an assertion.
fn flag(matches: &clap::ArgMatches, name: &str) -> bool {
    matches
        .try_get_one::<bool>(name)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}

/// Reads a value that the matched operation may not declare.
fn value<'a>(matches: &'a clap::ArgMatches, name: &str) -> Option<&'a String> {
    matches.try_get_one::<String>(name).ok().flatten()
}

/// Renders `txc list`.
fn listing(category: Option<&str>, names_only: bool) -> Result<String> {
    let selected = match category {
        Some(name) => {
            let category = Category::from_id(name).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown category {name:?}; try one of: {}",
                    Category::ALL
                        .iter()
                        .map(|c| c.id())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
            vec![category]
        }
        None => Category::ALL.to_vec(),
    };

    let mut out = String::new();

    if names_only {
        for category in selected {
            for op in registry::in_category(category) {
                out.push_str(op.name);
                out.push('\n');
            }
        }
        return Ok(out);
    }

    let width = registry::all()
        .iter()
        .map(|op| op.name.len())
        .max()
        .unwrap_or(20);

    for category in selected {
        out.push_str(&format!(
            "{} — {}\n",
            category.title().to_uppercase(),
            category.about()
        ));
        for op in registry::in_category(category) {
            out.push_str(&format!("  {:width$}  {}\n", op.name, op.about));
            if !op.aliases.is_empty() {
                out.push_str(&format!(
                    "  {:width$}  also: {}\n",
                    "",
                    op.aliases.join(", ")
                ));
            }
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "{} operations in {} categories. Run txc <operation> --help for details.\n",
        registry::all().len(),
        Category::ALL.len()
    ));
    Ok(out)
}
