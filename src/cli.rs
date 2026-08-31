//! Command line surface, generated from the operation registry.

use clap::{Arg, ArgAction, Command};

use crate::params::Params;
use crate::registry::{self, Feed, Op, ParamKind};

/// Global options are reserved so no operation may claim these short flags.
pub const RESERVED_SHORTS: &[char] = &['f', 'n', 'o', 'h', 'V'];

/// Builds the whole command tree.
pub fn build() -> Command {
    let mut cmd = Command::new("txc")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Offline text utilities for the terminal")
        .long_about(
            "Offline text utilities for the terminal.\n\n\
             Every operation takes its text as arguments, from --file, or over a pipe.\n\
             Run txc with no arguments to open the interactive interface, and\n\
             txc list to see everything available.",
        )
        .subcommand_required(false)
        .arg_required_else_help(false)
        .infer_subcommands(true)
        .max_term_width(100);

    for op in registry::all() {
        cmd = cmd.subcommand(subcommand_for(op));
    }

    cmd.subcommand(
        Command::new("list")
            .about("List every operation, optionally filtered by category")
            .arg(
                Arg::new("category")
                    .short('c')
                    .long("category")
                    .value_name("NAME")
                    .help("Show only one category"),
            )
            .arg(
                Arg::new("names")
                    .long("names")
                    .action(ArgAction::SetTrue)
                    .help("Print bare operation names, one per line"),
            ),
    )
    .subcommand(
        Command::new("completions")
            .about("Print a shell completion script")
            .long_about(
                "Print a shell completion script.\n\n\
                 bash: txc completions bash > ~/.local/share/bash-completion/completions/txc\n\
                 zsh:  txc completions zsh > \"${fpath[1]}/_txc\"\n\
                 fish: txc completions fish > ~/.config/fish/completions/txc.fish",
            )
            .arg(
                Arg::new("shell")
                    .required(true)
                    .value_parser(clap::builder::EnumValueParser::<clap_complete::Shell>::new())
                    .help("Shell to generate for"),
            ),
    )
    .subcommand(Command::new("tui").about("Open the interactive interface"))
}

fn subcommand_for(op: &'static Op) -> Command {
    let mut sub = Command::new(op.name)
        .about(op.about)
        .aliases(op.aliases.iter().copied())
        .display_order(op.category as usize)
        // Only the top level reports the version, which leaves --version free
        // for operations such as `uuid --version 5`.
        .disable_version_flag(true);

    // Input and output options are attached to each operation rather than made
    // global, so a generator is not offered flags about reading input.
    let reads_input = op.feed != Feed::None;
    if reads_input {
        sub = sub
            .arg(
                Arg::new("file")
                    .short('f')
                    .long("file")
                    .value_name("PATH")
                    .display_order(100)
                    .help("Read input from a file instead of arguments or standard input"),
            )
            .arg(
                Arg::new("raw")
                    .long("raw")
                    .action(ArgAction::SetTrue)
                    .display_order(103)
                    .help("Keep piped input exactly as read, including its trailing newline"),
            )
            .arg(
                Arg::new("lines")
                    .long("lines")
                    .action(ArgAction::SetTrue)
                    .conflicts_with("whole")
                    .display_order(104)
                    .help("Apply the operation to each line separately"),
            )
            .arg(
                Arg::new("whole")
                    .long("whole")
                    .action(ArgAction::SetTrue)
                    .display_order(105)
                    .help("Apply the operation to the whole input at once"),
            );
    }

    sub = sub
        .arg(
            Arg::new("out")
                .short('o')
                .long("out")
                .value_name("PATH")
                .display_order(101)
                .help("Write the result to a file instead of standard output"),
        )
        .arg(
            Arg::new("no-newline")
                .short('n')
                .long("no-newline")
                .action(ArgAction::SetTrue)
                .display_order(102)
                .help("Do not append a trailing newline to the result"),
        );

    if !op.examples.is_empty() {
        let examples = op
            .examples
            .iter()
            .map(|e| format!("  {e}"))
            .collect::<Vec<_>>()
            .join("\n");
        sub = sub.after_help(format!("Examples:\n{examples}"));
    }

    for (order, param) in op.params.iter().enumerate() {
        let mut arg = Arg::new(param.name)
            .long(param.name)
            .display_order(order)
            .help(param.help);
        if let Some(short) = param.short {
            debug_assert!(
                !RESERVED_SHORTS.contains(&short),
                "operation {} uses reserved short flag -{short}",
                op.name
            );
            arg = arg.short(short);
        }
        arg = match param.kind {
            ParamKind::Flag => arg.action(ArgAction::SetTrue),
            ParamKind::Value {
                placeholder,
                default,
            } => {
                let arg = arg.value_name(placeholder).action(ArgAction::Set);
                match default {
                    Some(d) => arg.default_value(d),
                    None => arg,
                }
            }
        };
        sub = sub.arg(arg);
    }

    if reads_input {
        sub = sub.arg(Arg::new("INPUT").num_args(0..).help(
            "Text to process; omit to read standard input, or -- for text starting with a dash",
        ));
    }

    sub
}

/// Collects the parameter values clap parsed for `op`.
pub fn params_from(op: &'static Op, matches: &clap::ArgMatches) -> Params {
    let mut params = Params::for_op(op);
    for param in op.params {
        match param.kind {
            ParamKind::Flag => {
                if matches.get_flag(param.name) {
                    params.enable(param.name);
                }
            }
            ParamKind::Value { .. } => {
                if let Some(value) = matches.get_one::<String>(param.name) {
                    params.set(param.name, value.clone());
                }
            }
        }
    }
    params
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_tree_is_well_formed() {
        // Catches duplicate operation names, clashing aliases and short flags
        // that collide with the global options.
        build().debug_assert();
    }

    #[test]
    fn no_operation_claims_a_reserved_short_flag() {
        for op in registry::all() {
            for param in op.params {
                if let Some(short) = param.short {
                    assert!(
                        !RESERVED_SHORTS.contains(&short),
                        "{} declares reserved short -{short} for --{}",
                        op.name,
                        param.name
                    );
                }
            }
        }
    }
}
