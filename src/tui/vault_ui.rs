//! Drawing the vault screen.
//!
//! Nothing secret is ever put into a cell of the screen buffer: sealed values
//! are drawn as a fixed mask that says nothing about their length, and typed
//! secrets as one dot per character.

use std::time::Instant;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, List, ListItem, ListState, Paragraph, Wrap};

use crate::tui::ui::{ACCENT, ERROR, HINTS_NEED_ROWS, MUTED, panel, window};
use crate::tui::vault::{Dialog, EntryForm, FormRow, Pane, SecretInput, VaultScreen};
use crate::vault::command::MASK;

/// Draws the whole vault screen.
pub fn draw(frame: &mut Frame, screen: &VaultScreen) {
    let area = frame.area();
    let hint = if area.height >= HINTS_NEED_ROWS {
        screen.command_hint()
    } else {
        None
    };
    let footer_height = if hint.is_some() { 4 } else { 1 };

    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(footer_height),
    ])
    .areas(area);

    draw_header(frame, header, screen);
    if let Some(error) = screen.home_error() {
        frame.render_widget(
            Paragraph::new(error)
                .style(Style::default().fg(ERROR))
                .wrap(Wrap { trim: false })
                .block(panel("Vault", false)),
            body,
        );
    } else if screen.is_unlocked() {
        draw_unlocked(frame, body, screen);
    } else {
        draw_locked(frame, body, screen);
    }
    draw_footer(frame, footer, screen, hint);

    if let Some(dialog) = &screen.dialog {
        draw_dialog(frame, area, screen, dialog);
    }
}

fn draw_header(frame: &mut Frame, area: Rect, screen: &VaultScreen) {
    let state = if screen.is_unlocked() {
        screen
            .selected_vault()
            .map_or_else(|| "unlocked".to_string(), str::to_string)
    } else {
        "locked".to_string()
    };
    let line = Line::from(vec![
        Span::styled(
            " txc ",
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} ", env!("CARGO_PKG_VERSION")),
            Style::default().fg(MUTED),
        ),
        Span::styled("Vault ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(state, Style::default().fg(MUTED)),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_vault_list(frame: &mut Frame, area: Rect, screen: &VaultScreen, focused: bool) {
    let items: Vec<ListItem> = screen
        .vaults()
        .iter()
        .map(|name| ListItem::new(name.as_str()))
        .collect();
    let mut state = ListState::default();
    if !screen.vaults().is_empty() {
        *state.selected_mut() = Some(screen.vault_index());
    }
    frame.render_stateful_widget(
        List::new(items)
            .block(panel("Vaults", focused))
            .highlight_style(Style::default().fg(Color::Black).bg(ACCENT)),
        area,
        &mut state,
    );
}

fn draw_locked(frame: &mut Frame, area: Rect, screen: &VaultScreen) {
    let [left, right] =
        Layout::horizontal([Constraint::Length(18), Constraint::Min(20)]).areas(area);
    draw_vault_list(frame, left, screen, false);

    let (lead, detail, action) = if screen.has_identity() {
        (
            "The vaults are locked.",
            "Everything in them is encrypted to your identity, which your passphrase unlocks. \
             They lock again after five minutes without a key.",
            "unlock",
        )
    } else {
        (
            "There is no identity yet.",
            "Your identity is a private key protected by a passphrase you choose. Vaults are \
             encrypted to it, and nothing in them can be opened without both.",
            "create it",
        )
    };
    let text = vec![
        Line::raw(""),
        Line::styled(
            format!(" {lead}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
        Line::styled(format!(" {detail}"), Style::default().fg(MUTED)),
        Line::raw(""),
        Line::from(vec![
            Span::styled(
                " enter ",
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(action, Style::default().fg(MUTED)),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(panel("Vault", true)),
        right,
    );
}

fn draw_unlocked(frame: &mut Frame, area: Rect, screen: &VaultScreen) {
    let [left, middle, right] = Layout::horizontal([
        Constraint::Length(18),
        Constraint::Length(34),
        Constraint::Min(20),
    ])
    .areas(area);

    draw_vault_list(frame, left, screen, screen.pane == Pane::Vaults);

    let [search, list] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(3)]).areas(middle);
    let search_text = if screen.search.is_empty() && !screen.searching {
        Span::styled("/ to filter", Style::default().fg(MUTED))
    } else {
        Span::raw(screen.search.as_str())
    };
    frame.render_widget(
        Paragraph::new(Line::from(search_text)).block(panel("Search", screen.searching)),
        search,
    );
    if screen.searching {
        frame.set_cursor_position(Position::new(
            search.x + 1 + screen.search.chars().count() as u16,
            search.y + 1,
        ));
    }

    let entries = screen.entries();
    let items: Vec<ListItem> = entries
        .iter()
        .map(|entry| {
            ListItem::new(Line::from(vec![
                Span::raw(entry.name.as_str()),
                Span::styled(format!("  {}", entry.kind), Style::default().fg(MUTED)),
            ]))
        })
        .collect();
    let mut state = ListState::default();
    if !entries.is_empty() {
        *state.selected_mut() = Some(screen.entry_index());
    }
    frame.render_stateful_widget(
        List::new(items)
            .block(panel(
                &format!("Entries ({})", entries.len()),
                screen.pane == Pane::Entries && !screen.searching,
            ))
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
        list,
        &mut state,
    );

    draw_details(frame, right, screen);
}

fn draw_details(frame: &mut Frame, area: Rect, screen: &VaultScreen) {
    let focused = screen.pane == Pane::Fields;

    if let Some(problem) = screen.problem() {
        let mut text = vec![
            Line::raw(""),
            Line::styled(format!(" {problem}"), Style::default().fg(ERROR)),
        ];
        if screen.untrusted() {
            text.push(Line::raw(""));
            text.push(Line::from(vec![
                Span::styled(
                    " t ",
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
                Span::styled("see what differs, and trust it", Style::default().fg(MUTED)),
            ]));
        }
        frame.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: false })
                .block(panel("Not opened", focused)),
            area,
        );
        return;
    }

    let Some(entry) = screen.selected_entry() else {
        let message = if screen.search.is_empty() {
            " No entries yet. Press a to add one."
        } else {
            " Nothing matches the search."
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::raw(""),
                Line::styled(message, Style::default().fg(MUTED)),
            ])
            .block(panel("Entry", focused)),
            area,
        );
        return;
    };

    let width = entry
        .fields
        .iter()
        .map(|field| field.name.chars().count())
        .chain([4])
        .max()
        .unwrap_or(4);

    let mut text = vec![Line::from(vec![
        Span::styled(format!("  {:width$}  ", "kind"), Style::default().fg(MUTED)),
        Span::raw(entry.kind.id()),
    ])];
    for (index, field) in entry.fields.iter().enumerate() {
        let selected = focused && index == screen.field_index();
        let label = Style::default().fg(if selected { ACCENT } else { MUTED });
        let value = match entry.plain(&field.name) {
            Some(plain) => Span::styled(
                plain,
                if selected {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            ),
            None => Span::styled(MASK, Style::default().fg(MUTED)),
        };
        text.push(Line::from(vec![
            Span::styled(if selected { "> " } else { "  " }, label),
            Span::styled(format!("{:width$}  ", field.name), label),
            value,
        ]));
    }
    text.push(Line::raw(""));
    if !entry.tags.is_empty() {
        text.push(Line::styled(
            format!("  {:width$}  {}", "tags", entry.tags.join(", ")),
            Style::default().fg(MUTED),
        ));
    }
    text.push(Line::styled(
        format!("  {:width$}  {}", "updated", entry.updated),
        Style::default().fg(MUTED),
    ));

    frame.render_widget(
        Paragraph::new(text).block(panel(&entry.name, focused)),
        area,
    );
}

fn draw_footer(frame: &mut Frame, area: Rect, screen: &VaultScreen, hint: Option<String>) {
    let [hint_area, keys_area] = Layout::vertical([
        Constraint::Length(area.height.saturating_sub(1)),
        Constraint::Length(1),
    ])
    .areas(area);

    if let Some(hint) = hint {
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    "cmd   ",
                    Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
                ),
                Span::styled(hint, Style::default().fg(ACCENT)),
            ]))
            .block(panel("Command line", false)),
            hint_area,
        );
    }

    let countdown = screen
        .clears_in(Instant::now())
        .map(|seconds| format!("clipboard clears in {seconds}s"));

    let line = if screen.status.is_empty() {
        let keys: &[(&str, &str)] = if !screen.is_unlocked() {
            &[("enter", "unlock"), ("F3", "text tools"), ("^c", "quit")]
        } else if screen.searching {
            &[("type", "filter"), ("enter", "done"), ("esc", "clear")]
        } else {
            match screen.pane {
                Pane::Vaults => &[
                    ("tab", "panel"),
                    ("n", "new vault"),
                    ("l", "lock"),
                    ("F3", "text tools"),
                    ("^c", "quit"),
                ],
                Pane::Entries => &[
                    ("c", "copy"),
                    ("u", "user"),
                    ("a", "add"),
                    ("e", "edit"),
                    ("d", "remove"),
                    ("/", "search"),
                    ("l", "lock"),
                    ("F3", "text tools"),
                ],
                Pane::Fields => &[
                    ("c", "copy field"),
                    ("tab", "panel"),
                    ("l", "lock"),
                    ("F3", "text tools"),
                    ("^c", "quit"),
                ],
            }
        };
        let mut spans: Vec<Span> = keys
            .iter()
            .flat_map(|(key, label)| {
                [
                    Span::styled(
                        format!(" {key} "),
                        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(format!("{label}  "), Style::default().fg(MUTED)),
                ]
            })
            .collect();
        if let Some(countdown) = countdown {
            spans.push(Span::styled(countdown, Style::default().fg(ACCENT)));
        }
        Line::from(spans)
    } else {
        let mut text = format!(" {}", screen.status);
        if let Some(countdown) = countdown
            && !screen.status.contains("clears in")
        {
            text.push_str("  ");
            text.push_str(&countdown);
        }
        Line::styled(text, Style::default().fg(ACCENT))
    };
    frame.render_widget(Paragraph::new(line), keys_area);
}

fn draw_dialog(frame: &mut Frame, area: Rect, screen: &VaultScreen, dialog: &Dialog) {
    match dialog {
        Dialog::Unlock { passphrase, error } => {
            let lines = vec![
                Line::raw(""),
                masked_row("Passphrase", passphrase, 10, true),
                Line::raw(""),
                note(error.as_deref(), "enter to unlock, esc to cancel"),
            ];
            let popup = show(frame, area, "Unlock", 64, lines);
            place_cursor(frame, popup, 1, 2 + 10 + 2, passphrase);
        }

        Dialog::CreateIdentity {
            passphrase,
            again,
            on_again,
            error,
        } => {
            let columns = 70;
            let mut lines = vec![Line::raw("")];
            for line in textwrap::wrap(
                "Choose a passphrase of at least 12 characters. Nothing in the vaults can be \
                 opened without it, and it cannot be recovered.",
                usize::from(columns) - 4,
            ) {
                lines.push(Line::styled(format!(" {line}"), Style::default().fg(MUTED)));
            }
            lines.push(Line::raw(""));
            let first_row = lines.len();
            lines.push(masked_row("Passphrase", passphrase, 10, !on_again));
            lines.push(masked_row("Again", again, 10, *on_again));
            lines.push(Line::raw(""));
            lines.push(note(
                error.as_deref(),
                "tab to switch, enter to continue, esc to cancel",
            ));
            let popup = show(frame, area, "Create your identity", columns, lines);
            let (row, input) = if *on_again {
                (first_row + 1, again)
            } else {
                (first_row, passphrase)
            };
            place_cursor(frame, popup, row, 2 + 10 + 2, input);
        }

        Dialog::NewVault { name, error } => {
            let lines = vec![
                Line::raw(""),
                Line::from(vec![
                    Span::styled(" Name  ", Style::default().fg(MUTED)),
                    Span::raw(name.text()),
                ]),
                Line::raw(""),
                note(
                    error.as_deref(),
                    "lowercase letters, digits, - and _; enter to create",
                ),
            ];
            let popup = show(frame, area, "New vault", 64, lines);
            frame.set_cursor_position(Position::new(
                popup.x + 1 + 7 + name.cursor().1 as u16,
                popup.y + 2,
            ));
        }

        Dialog::Entry(form) => draw_form(frame, area, form),

        Dialog::Delete { entry } => {
            let lines = vec![
                Line::raw(""),
                Line::styled(
                    format!(" Remove {entry}?"),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::styled(
                    " y to remove it, any other key to keep it",
                    Style::default().fg(MUTED),
                ),
            ];
            show(frame, area, "Remove", 56, lines);
        }

        Dialog::Trust(inspection) => {
            let columns: u16 = 84;
            let vault = inspection.vault();
            let mut lines = vec![Line::raw("")];
            for line in textwrap::wrap(
                &inspection.standing().describe(vault.name()),
                usize::from(columns) - 4,
            ) {
                lines.push(Line::styled(
                    format!(" {line}"),
                    Style::default().add_modifier(Modifier::BOLD),
                ));
            }
            lines.push(Line::raw(""));
            for (label, value) in [
                ("generation", vault.generation().to_string()),
                ("entries", vault.entries().len().to_string()),
                ("updated", vault.updated().to_string()),
            ] {
                lines.push(Line::from(vec![
                    Span::styled(format!(" {label:12}"), Style::default().fg(MUTED)),
                    Span::raw(value),
                ]));
            }
            lines.push(Line::styled(" encrypted to", Style::default().fg(MUTED)));
            let own = screen.public_key().unwrap_or_default();
            for key in vault.recipients() {
                let marker = if *key == own { "  (you)" } else { "" };
                lines.push(Line::raw(format!("   {key}{marker}")));
            }
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                " y to trust it as it is now, any other key to cancel",
                Style::default().fg(MUTED),
            ));
            show(frame, area, "Trust this vault?", columns, lines);
        }
    }
}

fn draw_form(frame: &mut Frame, area: Rect, form: &EntryForm) {
    const LABEL: usize = 9;
    let primary = form.kind.primary();
    let title = form
        .editing
        .as_ref()
        .map_or_else(|| "Add an entry".to_string(), |name| format!("Edit {name}"));

    let mut lines = vec![Line::raw("")];
    let mut cursor = None;
    for row in form.rows() {
        let selected = row == form.row;
        let label_style = Style::default().fg(if selected { ACCENT } else { MUTED });
        let marker = Span::styled(if selected { ">" } else { " " }, label_style);
        let (label, value) = match row {
            FormRow::Name => ("name", Span::raw(form.name.text())),
            FormRow::Kind => ("kind", Span::raw(format!("< {} >", form.kind))),
            FormRow::Username => ("username", Span::raw(form.username.text())),
            FormRow::Url => ("url", Span::raw(form.url.text())),
            FormRow::Secret => {
                let shown = if form.secret.is_empty() && form.editing.is_some() {
                    Span::styled("unchanged; type to replace", Style::default().fg(MUTED))
                } else if form.generated {
                    Span::styled(
                        format!("{}  generated", fit(&form.secret, 40)),
                        Style::default().fg(MUTED),
                    )
                } else {
                    Span::raw(fit(&form.secret, 48))
                };
                (primary, shown)
            }
        };
        if selected {
            let column = match row {
                FormRow::Name => Some(form.name.cursor().1),
                FormRow::Username => Some(form.username.cursor().1),
                FormRow::Url => Some(form.url.cursor().1),
                FormRow::Secret if !form.generated => Some(form.secret.chars().min(48)),
                _ => None,
            };
            cursor = column.map(|column| (lines.len(), column));
        }
        lines.push(Line::from(vec![
            marker,
            Span::styled(format!("{label:LABEL$} "), label_style),
            value,
        ]));
    }
    lines.push(Line::raw(""));
    lines.push(note(
        form.error.as_deref(),
        "tab next, ctrl+g generate, ctrl+s save, esc cancel",
    ));

    let popup = show(frame, area, &title, 72, lines);
    if let Some((row, column)) = cursor {
        frame.set_cursor_position(Position::new(
            popup.x + 1 + 1 + LABEL as u16 + 1 + column as u16,
            popup.y + 1 + row as u16,
        ));
    }
}

/// A masked field with its label, marked when selected.
fn masked_row(label: &str, input: &SecretInput, width: usize, selected: bool) -> Line<'static> {
    let style = Style::default().fg(if selected { ACCENT } else { MUTED });
    Line::from(vec![
        Span::styled(if selected { " >" } else { "  " }, style),
        Span::styled(format!("{label:width$}  "), style),
        Span::raw(fit(input, 40)),
    ])
}

/// The dots for a secret, trimmed to the last `columns` when long.
fn fit(input: &SecretInput, columns: usize) -> String {
    "•".repeat(input.chars().min(columns))
}

/// The error when there is one, otherwise the hint.
fn note(error: Option<&str>, hint: &str) -> Line<'static> {
    match error {
        Some(error) => Line::styled(format!(" {error}"), Style::default().fg(ERROR)),
        None => Line::styled(format!(" {hint}"), Style::default().fg(MUTED)),
    }
}

/// Draws a window sized to its lines, and returns where it went.
fn show(frame: &mut Frame, area: Rect, title: &str, columns: u16, lines: Vec<Line>) -> Rect {
    let popup = window(area, columns, lines.len() as u16 + 3);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel(title, true)),
        popup,
    );
    popup
}

fn place_cursor(frame: &mut Frame, popup: Rect, row: usize, column: usize, input: &SecretInput) {
    frame.set_cursor_position(Position::new(
        popup.x + 1 + (column + input.chars().min(40)) as u16,
        popup.y + 1 + row as u16,
    ));
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::tui::vault::tests::{add_login, locked, press, type_text, unlocked};
    use crossterm::event::KeyCode;

    fn render(screen: &VaultScreen, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal.draw(|frame| draw(frame, screen)).expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(width as usize)
            .map(|row| {
                row.iter()
                    .map(ratatui::buffer::Cell::symbol)
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_locked_screen_says_how_to_unlock() {
        let (_scratch, mut screen) = locked("ui-locked");
        screen.enter();
        screen.dialog = None;
        let shown = render(&screen, 100, 30);
        assert!(shown.contains("The vaults are locked"), "{shown}");
        assert!(shown.contains("personal"), "{shown}");
        assert!(shown.contains("unlock"), "{shown}");
    }

    #[test]
    fn a_typed_passphrase_is_drawn_as_dots() {
        let (_scratch, mut screen) = locked("ui-passphrase");
        screen.enter();
        type_text(&mut screen, "hunter2hunter2");
        let shown = render(&screen, 100, 30);
        assert!(shown.contains("Unlock"), "{shown}");
        assert!(shown.contains(&"•".repeat(14)), "{shown}");
        assert!(!shown.contains("hunter2"), "{shown}");
    }

    #[test]
    fn no_secret_ever_reaches_the_screen() {
        let (_scratch, mut screen) = unlocked("ui-secret");

        press(&mut screen, KeyCode::Char('a'));
        type_text(&mut screen, "site");
        for _ in 0..4 {
            press(&mut screen, KeyCode::Tab);
        }
        type_text(&mut screen, "correct-horse-secret");
        let form = render(&screen, 100, 30);
        assert!(!form.contains("correct-horse-secret"), "{form}");
        press(&mut screen, KeyCode::Enter);
        assert!(screen.dialog.is_none(), "{}", screen.status);

        for pane in [Pane::Vaults, Pane::Entries, Pane::Fields] {
            screen.pane = pane;
            let shown = render(&screen, 100, 30);
            assert!(!shown.contains("correct-horse-secret"), "{shown}");
            assert!(shown.contains(MASK), "{shown}");
        }
    }

    #[test]
    fn the_entry_panel_shows_plain_fields_and_masks_sealed_ones() {
        let (_scratch, mut screen) = unlocked("ui-entry");
        add_login(&mut screen, "GitHub", "octocat", "hunter2");
        let shown = render(&screen, 110, 30);
        assert!(shown.contains("GitHub"), "{shown}");
        assert!(shown.contains("octocat"), "{shown}");
        assert!(shown.contains("password"), "{shown}");
        assert!(shown.contains(MASK), "{shown}");
        assert!(shown.contains("txc vault copy personal/GitHub"), "{shown}");
    }

    #[test]
    fn every_dialog_draws_and_survives_a_small_terminal() {
        let (_scratch, mut screen) = unlocked("ui-dialogs");
        add_login(&mut screen, "site", "u", "p");

        let dialogs: [&dyn Fn(&mut VaultScreen); 4] = [
            &|s| press(s, KeyCode::Char('a')),
            &|s| press(s, KeyCode::Char('e')),
            &|s| press(s, KeyCode::Char('d')),
            &|s| press(s, KeyCode::Char('n')),
        ];
        for open in dialogs {
            open(&mut screen);
            assert!(screen.dialog.is_some());
            render(&screen, 100, 30);
            render(&screen, 30, 10);
            render(&screen, 8, 4);
            screen.dialog = None;
        }
        render(&screen, 8, 4);
    }
}
