//! Drawing the vault screen.
//!
//! A sealed value is drawn as a fixed mask that says nothing about its
//! length, and a typed secret as one dot per character. The only secrets that
//! reach the screen are one revealed on request, for a few seconds, and a
//! note that has been opened. Both go through [`displayable`] first, so they
//! cannot carry anything a terminal would act on.

use std::time::Instant;

use age::secrecy::ExposeSecret;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, List, ListItem, ListState, Paragraph, Wrap};

use crate::tui::ui::{ACCENT, ERROR, HINTS_NEED_ROWS, MUTED, panel, window};
use crate::tui::vault::form::{EntryForm, Input, Row, SecretInput};
use crate::tui::vault::{Busy, Dialog, NoteView, Pane, Section, SidebarRow, VaultScreen};
use crate::vault::ago;
use crate::vault::command::MASK;
use crate::vault::model::{Kind, Sensitivity, Value, displayable};

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn muted() -> Style {
    Style::default().fg(MUTED)
}

fn accent() -> Style {
    Style::default().fg(ACCENT)
}

fn key_style() -> Style {
    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
}

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
    if let Some(busy) = screen.busy() {
        draw_busy(frame, area, busy);
    }
}

fn draw_header(frame: &mut Frame, area: Rect, screen: &VaultScreen) {
    let state = if screen.is_unlocked() {
        let vaults = screen.vaults().len();
        let entries = screen.count(Section::All);
        format!(
            "unlocked · {entries} {} in {vaults} {}",
            if entries == 1 { "entry" } else { "entries" },
            if vaults == 1 { "vault" } else { "vaults" }
        )
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
        Span::styled(format!(" {} ", env!("CARGO_PKG_VERSION")), muted()),
        Span::styled("Vault ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(state, muted()),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_locked(frame: &mut Frame, area: Rect, screen: &VaultScreen) {
    let [left, right] =
        Layout::horizontal([Constraint::Length(26), Constraint::Min(20)]).areas(area);
    let names: Vec<ListItem> = screen
        .locked_names()
        .iter()
        .map(|name| ListItem::new(format!(" {name}")))
        .collect();
    frame.render_widget(List::new(names).block(panel("Vaults", false)), left);

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
    // Wrapped here rather than by the paragraph, which would drop the indent
    // from every line after the first.
    let width = usize::from(right.width.saturating_sub(4)).max(10);
    let mut text = vec![
        Line::raw(""),
        Line::styled(
            format!(" {lead}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Line::raw(""),
    ];
    for line in textwrap::wrap(detail, width) {
        text.push(Line::styled(format!(" {line}"), muted()));
    }
    text.push(Line::raw(""));
    text.push(Line::from(vec![
        Span::styled(" enter ", key_style()),
        Span::styled(action, muted()),
    ]));
    frame.render_widget(Paragraph::new(text).block(panel("Vault", true)), right);
}

fn draw_unlocked(frame: &mut Frame, area: Rect, screen: &VaultScreen) {
    let [left, middle, right] = Layout::horizontal([
        Constraint::Length(26),
        Constraint::Length(40),
        Constraint::Min(24),
    ])
    .areas(area);
    draw_sidebar(frame, left, screen);

    let [search, list] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(3)]).areas(middle);
    draw_search(frame, search, screen);
    draw_items(frame, list, screen);
    draw_details(frame, right, screen);
}

fn section_label(screen: &VaultScreen, section: Section) -> String {
    match section {
        Section::Favourites => "★ Favourites".to_string(),
        Section::Recent => "◷ Recently used".to_string(),
        Section::All => "▤ All items".to_string(),
        Section::Kind(kind) => format!("  {}", kind.plural()),
        Section::Vault(index) => {
            let vault = &screen.vaults()[index];
            let marker = if vault.problem.is_some() { " !" } else { "" };
            format!("  {}{marker}", vault.name)
        }
    }
}

fn draw_sidebar(frame: &mut Frame, area: Rect, screen: &VaultScreen) {
    let rows = screen.sidebar();
    let width = usize::from(area.width.saturating_sub(2));
    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| match row {
            SidebarRow::Heading(text) => ListItem::new(Line::styled(
                format!(" {text}"),
                muted().add_modifier(Modifier::BOLD),
            )),
            SidebarRow::Section(section) => {
                let label = section_label(screen, *section);
                let count = screen.count(*section).to_string();
                let pad = width.saturating_sub(label.chars().count() + count.len() + 1);
                ListItem::new(format!("{label}{}{count} ", " ".repeat(pad)))
            }
        })
        .collect();

    let mut state = ListState::default();
    *state.selected_mut() = rows
        .iter()
        .position(|row| *row == SidebarRow::Section(screen.section));
    frame.render_stateful_widget(
        List::new(items)
            .block(panel("Browse", screen.pane == Pane::Sidebar))
            .highlight_style(Style::default().fg(Color::Black).bg(ACCENT)),
        area,
        &mut state,
    );
}

fn draw_search(frame: &mut Frame, area: Rect, screen: &VaultScreen) {
    let text = if screen.search.is_empty() && !screen.searching {
        Span::styled("/ to search", muted())
    } else {
        Span::raw(screen.search.as_str())
    };
    frame.render_widget(
        Paragraph::new(Line::from(text)).block(panel("Search", screen.searching)),
        area,
    );
    if screen.searching {
        frame.set_cursor_position(Position::new(
            area.x + 1 + screen.search.chars().count() as u16,
            area.y + 1,
        ));
    }
}

fn empty_message(screen: &VaultScreen) -> &'static str {
    if !screen.search.is_empty() {
        return "Nothing matches the search.";
    }
    match screen.section {
        Section::Favourites => {
            "No favourites yet. Select an entry and press f to star it, and it will wait here."
        }
        Section::Recent => {
            "Nothing used yet on this device. What you copy or reveal shows up here, newest first."
        }
        _ if screen.problem().is_some() => "This vault is not open.",
        _ => "Nothing here yet. Press a to add an entry.",
    }
}

/// Text cut to `max` characters, with an ellipsis when it was cut.
fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let mut cut: String = text.chars().take(max.saturating_sub(1)).collect();
        cut.push('…');
        cut
    }
}

fn draw_items(frame: &mut Frame, area: Rect, screen: &VaultScreen) {
    let items = screen.items();
    let focused = screen.pane == Pane::Items && !screen.searching;
    let title = format!("{} ({})", screen.section_title(screen.section), items.len());

    if items.is_empty() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::raw(""),
                Line::styled(format!(" {}", empty_message(screen)), muted()),
            ])
            .wrap(Wrap { trim: false })
            .block(panel(&title, focused)),
            area,
        );
        return;
    }

    let width = usize::from(area.width.saturating_sub(2));
    let several = screen.vaults().len() > 1;
    let rows: Vec<ListItem> = items
        .iter()
        .map(|item| {
            let Some(entry) = screen.entry_of(item) else {
                return ListItem::new("");
            };
            let star = if entry.favourite { "★ " } else { "  " };
            let detail = match &item.used {
                Some(at) => ago(at),
                None if several => format!(
                    "{} · {}",
                    screen.vaults()[item.vault].name,
                    entry.kind.label()
                ),
                None => entry.kind.label().to_string(),
            };
            let detail = truncate(&detail, width / 2);
            let name = truncate(
                &entry.name,
                width.saturating_sub(detail.chars().count() + 4),
            );
            let pad = width.saturating_sub(2 + name.chars().count() + detail.chars().count());
            ListItem::new(Line::from(vec![
                Span::styled(star, accent()),
                Span::raw(name),
                Span::raw(" ".repeat(pad)),
                Span::styled(detail, muted()),
            ]))
        })
        .collect();

    let mut state = ListState::default();
    *state.selected_mut() = Some(screen.item_index());
    frame.render_stateful_widget(
        List::new(rows)
            .block(panel(&title, focused))
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(ACCENT)
                    .add_modifier(Modifier::BOLD),
            ),
        area,
        &mut state,
    );
}

fn draw_details(frame: &mut Frame, area: Rect, screen: &VaultScreen) {
    let focused = screen.pane == Pane::Details;

    if let Some((_, vault)) = screen.problem() {
        let mut text = vec![
            Line::raw(""),
            Line::styled(
                format!(" {}", vault.problem.as_deref().unwrap_or_default()),
                Style::default().fg(ERROR),
            ),
        ];
        if vault.untrusted {
            text.push(Line::raw(""));
            text.push(Line::from(vec![
                Span::styled(" t ", key_style()),
                Span::styled("see what differs, and trust it", muted()),
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

    let Some((vault, entry)) = screen.selected() else {
        let tips = [
            ("a", "add an entry"),
            ("1 2 3", "favourites, recent, all"),
            ("/", "search"),
            ("n", "new vault"),
            ("l", "lock"),
        ];
        let mut text = vec![Line::raw("")];
        for (key, label) in tips {
            text.push(Line::from(vec![
                Span::styled(format!(" {key:6}"), key_style()),
                Span::styled(label, muted()),
            ]));
        }
        frame.render_widget(Paragraph::new(text).block(panel("Entry", focused)), area);
        return;
    };

    let now = Instant::now();
    let width = entry
        .fields
        .iter()
        .map(|field| entry.label(&field.name).chars().count())
        .chain([7])
        .max()
        .unwrap_or(7);

    let mut header = vec![Span::styled(
        format!(" {} · {}", entry.kind.label(), screen.vaults()[vault].name),
        muted(),
    )];
    if entry.favourite {
        header.push(Span::styled("  ★ favourite", accent()));
    }
    let mut lines = vec![Line::from(header), Line::raw("")];

    for (index, field) in entry.fields.iter().enumerate() {
        let selected = focused && index == screen.field_index();
        let label_style = if selected { accent() } else { muted() };
        let marker = if selected { "> " } else { "  " };
        let label = format!("{:width$}  ", entry.label(&field.name));
        let head = vec![
            Span::styled(marker, label_style),
            Span::styled(label, label_style),
        ];

        match (entry.sensitivity(&field.name), &field.value) {
            (_, Value::Plain(value)) => {
                let style = if selected {
                    Style::default().add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                lines.push(Line::from(
                    [head, vec![Span::styled(value.clone(), style)]].concat(),
                ));
            }
            (Sensitivity::Private, _) => {
                lines.push(Line::from(
                    [head, vec![Span::styled("enter or r to read", muted())]].concat(),
                ));
            }
            (_, Value::Sealed(_)) => match screen.shown_secret(vault, &entry.name, &field.name) {
                Some(secret) => {
                    let left = screen.reveal_left(now).unwrap_or(0);
                    let mut first = true;
                    for part in secret.expose_secret().split('\n') {
                        let lead = if first {
                            head.clone()
                        } else {
                            vec![Span::raw(" ".repeat(width + 4))]
                        };
                        let mut spans = lead;
                        spans.push(Span::styled(displayable(part), accent()));
                        if first {
                            spans.push(Span::styled(format!("  hides in {left}s"), muted()));
                        }
                        lines.push(Line::from(spans));
                        first = false;
                    }
                }
                None => lines.push(Line::from(
                    [head, vec![Span::styled(MASK, muted())]].concat(),
                )),
            },
        }
    }

    lines.push(Line::raw(""));
    if !entry.tags.is_empty() {
        lines.push(Line::styled(
            format!("  {:width$}  {}", "Tags", entry.tags.join(", ")),
            muted(),
        ));
    }
    let updated = entry.updated.replace('T', " ");
    lines.push(Line::styled(
        format!(
            "  {:width$}  {}",
            "Updated",
            updated.get(..16).unwrap_or(&updated)
        ),
        muted(),
    ));

    frame.render_widget(
        Paragraph::new(lines).block(panel(&entry.name, focused)),
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
                Span::styled("cmd   ", muted().add_modifier(Modifier::BOLD)),
                Span::styled(hint, accent()),
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
            &[("type", "search"), ("enter", "done"), ("esc", "clear")]
        } else {
            match screen.pane {
                Pane::Sidebar => &[
                    ("↑↓", "section"),
                    ("→", "list"),
                    ("a", "add"),
                    ("n", "new vault"),
                    ("l", "lock"),
                    ("F3", "text tools"),
                ],
                Pane::Items => &[
                    ("c", "copy"),
                    ("u", "user"),
                    ("r", "reveal"),
                    ("f", "star"),
                    ("a", "add"),
                    ("e", "edit"),
                    ("d", "delete"),
                    ("/", "search"),
                    ("1 2 3", "jump"),
                    ("l", "lock"),
                ],
                Pane::Details => &[
                    ("↑↓", "field"),
                    ("c", "copy"),
                    ("r", "reveal or read"),
                    ("e", "edit"),
                    ("f", "star"),
                    ("←", "back"),
                ],
            }
        };
        let mut spans: Vec<Span> = keys
            .iter()
            .flat_map(|(key, label)| {
                [
                    Span::styled(format!(" {key} "), key_style()),
                    Span::styled(format!("{label}  "), muted()),
                ]
            })
            .collect();
        if let Some(countdown) = countdown {
            spans.push(Span::styled(countdown, accent()));
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
        Line::styled(text, accent())
    };
    frame.render_widget(Paragraph::new(line), keys_area);
}

fn draw_dialog(frame: &mut Frame, area: Rect, screen: &VaultScreen, dialog: &Dialog) {
    match dialog {
        Dialog::Unlock { passphrase, error } => {
            let lines = vec![
                Line::raw(""),
                masked_row("Passphrase", passphrase, true),
                Line::raw(""),
                note(error.as_deref(), "enter to unlock, esc to cancel"),
            ];
            let popup = show(frame, area, "Unlock", 64, lines);
            place_cursor(frame, popup, 1, passphrase);
        }

        Dialog::CreateIdentity {
            passphrase,
            again,
            on_again,
            error,
        } => {
            let columns: u16 = 70;
            let mut lines = vec![Line::raw("")];
            for line in textwrap::wrap(
                "Choose a passphrase of at least 12 characters. Nothing in the vaults can be \
                 opened without it, and it cannot be recovered.",
                usize::from(columns) - 4,
            ) {
                lines.push(Line::styled(format!(" {line}"), muted()));
            }
            lines.push(Line::raw(""));
            let first_row = lines.len();
            lines.push(masked_row("Passphrase", passphrase, !on_again));
            lines.push(masked_row("Again", again, *on_again));
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
            place_cursor(frame, popup, row, input);
        }

        Dialog::NewVault { name, error } => {
            let lines = vec![
                Line::raw(""),
                Line::from(vec![
                    Span::styled(" Name  ", muted()),
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

        Dialog::PickKind { index } => {
            let mut lines = vec![Line::raw("")];
            for (position, kind) in Kind::ALL.iter().enumerate() {
                let selected = position == *index;
                let style = if selected {
                    key_style()
                } else {
                    Style::default()
                };
                lines.push(Line::from(vec![
                    Span::styled(if selected { " > " } else { "   " }, style),
                    Span::styled(format!("{:18}", kind.label()), style),
                    Span::styled(kind.about(), muted()),
                ]));
            }
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                " ↑↓ choose · enter continue · a letter jumps · esc cancel",
                muted(),
            ));
            show(frame, area, "What are you adding?", 76, lines);
        }

        Dialog::Entry(form) => draw_form(frame, area, form),

        Dialog::Note(view) => draw_note(frame, area, view),

        Dialog::Delete { entry, .. } => {
            let lines = vec![
                Line::raw(""),
                Line::styled(
                    format!(" Remove {entry}?"),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::styled(" y to remove it, any other key to keep it", muted()),
            ];
            show(frame, area, "Remove", 56, lines);
        }

        Dialog::Trust(boxed) => {
            let (_, inspection) = boxed.as_ref();
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
                    Span::styled(format!(" {label:12}"), muted()),
                    Span::raw(value),
                ]));
            }
            lines.push(Line::styled(" encrypted to", muted()));
            let own = screen.public_key().unwrap_or_default();
            for key in vault.recipients() {
                let marker = if *key == own { "  (you)" } else { "" };
                lines.push(Line::raw(format!("   {key}{marker}")));
            }
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                " y to trust it as it is now, any other key to cancel",
                muted(),
            ));
            show(frame, area, "Trust this vault?", columns, lines);
        }
    }
}

fn form_hint(form: &EntryForm) -> String {
    let mut parts = vec!["tab next field"];
    if form.row == Row::Vault {
        parts.push("←→ choose the vault");
    }
    if let Some(field) = form.focused() {
        match field.input {
            Input::Note(_) => parts.push("enter new line"),
            Input::Secret(_) => {
                if field.generator.is_some() {
                    parts.push("ctrl+g generate");
                }
                parts.push(if form.reveal {
                    "ctrl+r hide"
                } else {
                    "ctrl+r show"
                });
            }
            Input::Text(_) => {}
        }
    }
    parts.extend(["ctrl+s save", "esc cancel"]);
    parts.join(" · ")
}

/// The value, or its hint in grey while it is empty.
fn value_or_hint(value: &str, hint: &str) -> Span<'static> {
    if value.is_empty() {
        Span::styled(hint.to_string(), muted())
    } else {
        Span::raw(value.to_string())
    }
}

fn draw_form(frame: &mut Frame, area: Rect, form: &EntryForm) {
    const LABEL: usize = 16;
    const NOTE_ROWS: usize = 6;
    let columns = area.width.saturating_sub(4).min(92);
    let value_width = usize::from(columns).saturating_sub(LABEL + 6);
    let title = form.editing.as_ref().map_or_else(
        || format!("New {}", form.kind.label().to_lowercase()),
        |name| format!("Edit {name}"),
    );

    let mut lines = vec![
        Line::styled(
            format!(" {} in the vault {}", form.kind.label(), form.vault_name()),
            muted(),
        ),
        Line::raw(""),
    ];
    let mut cursor: Option<(usize, usize)> = None;

    for row in form.rows() {
        let selected = row == form.row;
        let style = if selected { accent() } else { muted() };
        let prefix = |label: &str| -> Vec<Span<'static>> {
            vec![
                Span::styled(if selected { ">" } else { " " }, style),
                Span::styled(format!("{:LABEL$} ", truncate(label, LABEL)), style),
            ]
        };

        match row {
            Row::Name => {
                let text = form.name.text();
                if selected {
                    cursor = Some((lines.len(), form.name.cursor().1));
                }
                let value = value_or_hint(&text, "such as GitHub or Everyday card");
                lines.push(Line::from([prefix("Name"), vec![value]].concat()));
            }
            Row::Vault => {
                lines.push(Line::from(
                    [
                        prefix("Vault"),
                        vec![Span::raw(format!("< {} >", form.vault_name()))],
                    ]
                    .concat(),
                ));
            }
            Row::Tags => {
                let text = form.tags.text();
                if selected {
                    cursor = Some((lines.len(), form.tags.cursor().1));
                }
                let value = value_or_hint(&text, "optional, such as work, banking");
                lines.push(Line::from([prefix("Tags"), vec![value]].concat()));
            }
            Row::Field(index) => {
                let field = &form.fields[index];
                match &field.input {
                    Input::Text(text) => {
                        let value = text.text();
                        if selected {
                            cursor = Some((lines.len(), text.cursor().1));
                        }
                        lines.push(Line::from(
                            [
                                prefix(&field.label),
                                vec![value_or_hint(&value, field.hint)],
                            ]
                            .concat(),
                        ));
                    }
                    Input::Secret(secret) => {
                        let dots = value_width.saturating_sub(14);
                        let shown: Vec<Span<'static>> = if secret.is_empty() {
                            let hint = if field.has_value {
                                "unchanged; type or paste to replace"
                            } else if field.generator.is_some() {
                                "type or paste, or ctrl+g to generate"
                            } else {
                                "type or paste"
                            };
                            vec![Span::styled(hint, muted())]
                        } else if selected && form.reveal {
                            vec![Span::styled(
                                truncate(&secret.shown(), value_width),
                                accent(),
                            )]
                        } else {
                            let mut spans = vec![Span::raw(secret.masked(dots))];
                            if field.generated {
                                spans.push(Span::styled("  generated", muted()));
                            } else if secret.lines() > 1 {
                                spans.push(Span::styled(
                                    format!("  {} lines", secret.lines()),
                                    muted(),
                                ));
                            }
                            spans
                        };
                        if selected && !form.reveal {
                            cursor = Some((lines.len(), secret.chars().min(dots)));
                        }
                        lines.push(Line::from([prefix(&field.label), shown].concat()));
                    }
                    Input::Note(text) => {
                        if text.is_empty() {
                            if selected {
                                cursor = Some((lines.len(), 0));
                            }
                            let hint = value_or_hint("", "type here; enter starts a new line");
                            lines.push(Line::from([prefix(&field.label), vec![hint]].concat()));
                            continue;
                        }
                        let all = text.lines();
                        let (cursor_row, cursor_column) = text.cursor();
                        let rows = if selected { NOTE_ROWS } else { 2 };
                        let offset = if selected {
                            cursor_row.saturating_sub(rows - 1)
                        } else {
                            0
                        };
                        let visible = all.iter().skip(offset).take(rows);
                        for (position, line) in visible.enumerate() {
                            let head = if position == 0 {
                                prefix(&field.label)
                            } else {
                                vec![Span::raw(" ".repeat(LABEL + 2))]
                            };
                            if selected && offset + position == cursor_row {
                                cursor = Some((lines.len(), cursor_column));
                            }
                            lines.push(Line::from(
                                [
                                    head,
                                    vec![Span::raw(truncate(&displayable(line), value_width))],
                                ]
                                .concat(),
                            ));
                        }
                        let hidden = all.len().saturating_sub(offset + rows);
                        if hidden > 0 {
                            lines.push(Line::styled(
                                format!("{}… {hidden} more", " ".repeat(LABEL + 2)),
                                muted(),
                            ));
                        }
                    }
                }
            }
        }
    }

    lines.push(Line::raw(""));
    lines.push(note(form.error.as_deref(), &form_hint(form)));

    let popup = show(frame, area, &title, columns, lines);
    if let Some((line, column)) = cursor {
        let y = popup.y + 1 + line as u16;
        if y + 1 < popup.y + popup.height {
            frame.set_cursor_position(Position::new(
                popup.x + 1 + LABEL as u16 + 2 + column as u16,
                y,
            ));
        }
    }
}

fn draw_note(frame: &mut Frame, area: Rect, view: &NoteView) {
    let columns = area.width.saturating_sub(6).min(100);
    let rows = area.height.saturating_sub(4);
    let popup = window(area, columns, rows);
    let width = usize::from(columns.saturating_sub(4)).max(10);

    let mut lines: Vec<Line> = Vec::new();
    for raw in view.text.expose_secret().split('\n') {
        let shown = displayable(raw.trim_end_matches('\r'));
        for wrapped in textwrap::wrap(&shown, width) {
            lines.push(Line::raw(format!(" {wrapped}")));
        }
    }

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(lines).scroll((view.scroll, 0)).block(
            panel(&view.title, true).title_bottom(Line::styled(
                " ↑↓ scroll · c copy · e edit · esc close ",
                muted(),
            )),
        ),
        popup,
    );
}

fn draw_busy(frame: &mut Frame, area: Rect, busy: &Busy) {
    const COLUMNS: u16 = 66;
    let elapsed = busy.started.elapsed();
    let spin = SPINNER[(elapsed.as_millis() / 100) as usize % SPINNER.len()];
    let mut lines = vec![
        Line::raw(""),
        Line::from(vec![
            Span::styled(format!(" {spin} "), key_style()),
            Span::raw(format!("{}... {}s", busy.message, elapsed.as_secs())),
        ]),
        Line::raw(""),
    ];
    for line in textwrap::wrap(
        "This takes a moment on purpose: the same work makes every guess at your \
         passphrase just as slow for anyone trying to find it.",
        usize::from(COLUMNS) - 4,
    ) {
        lines.push(Line::styled(format!(" {line}"), muted()));
    }
    show(frame, area, busy.title, COLUMNS, lines);
}

/// A masked field with its label, marked when selected.
fn masked_row(label: &str, input: &SecretInput, selected: bool) -> Line<'static> {
    let style = if selected { accent() } else { muted() };
    Line::from(vec![
        Span::styled(if selected { " >" } else { "  " }, style),
        Span::styled(format!("{label:10}  "), style),
        Span::raw(input.masked(40)),
    ])
}

/// The error when there is one, otherwise the hint.
fn note(error: Option<&str>, hint: &str) -> Line<'static> {
    match error {
        Some(error) => Line::styled(format!(" {error}"), Style::default().fg(ERROR)),
        None => Line::styled(format!(" {hint}"), muted()),
    }
}

/// Draws a window sized to its lines, and returns where it went. Lines are
/// not wrapped, so a cursor placed by line number stays on its line.
fn show(frame: &mut Frame, area: Rect, title: &str, columns: u16, lines: Vec<Line>) -> Rect {
    let popup = window(area, columns, lines.len() as u16 + 3);
    frame.render_widget(Clear, popup);
    frame.render_widget(Paragraph::new(lines).block(panel(title, true)), popup);
    popup
}

fn place_cursor(frame: &mut Frame, popup: Rect, row: usize, input: &SecretInput) {
    frame.set_cursor_position(Position::new(
        popup.x + 1 + 14 + input.chars().min(40) as u16,
        popup.y + 1 + row as u16,
    ));
}

#[cfg(test)]
mod tests {
    use crossterm::event::KeyCode;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::tui::vault::REVEAL_FOR;
    use crate::tui::vault::tests::{add_login, locked, press, press_ctrl, type_text, unlocked};

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
        let shown = render(&screen, 110, 30);
        assert!(shown.contains("The vaults are locked"), "{shown}");
        assert!(shown.contains("personal"), "{shown}");
        assert!(shown.contains("unlock"), "{shown}");
    }

    #[test]
    fn a_typed_passphrase_is_drawn_as_dots_and_the_wait_is_explained() {
        let (_scratch, mut screen) = locked("ui-passphrase");
        screen.enter();
        type_text(&mut screen, "hunter2hunter2");
        let shown = render(&screen, 110, 30);
        assert!(shown.contains(&"•".repeat(14)), "{shown}");
        assert!(!shown.contains("hunter2"), "{shown}");

        press(&mut screen, KeyCode::Enter);
        let waiting = render(&screen, 110, 30);
        assert!(waiting.contains("Unlocking"), "{waiting}");
        assert!(waiting.contains("Checking your passphrase"), "{waiting}");
        assert!(waiting.contains("on purpose"), "{waiting}");
        crate::tui::vault::tests::settle(&mut screen);
    }

    #[test]
    fn the_sidebar_lists_the_ways_in_with_counts() {
        let (_scratch, mut screen) = unlocked("ui-sidebar");
        add_login(&mut screen, "GitHub", "octocat", "p");
        let shown = render(&screen, 120, 30);
        for text in [
            "Favourites",
            "Recently used",
            "All items",
            "Logins",
            "personal",
        ] {
            assert!(shown.contains(text), "{text} is missing:\n{shown}");
        }
        assert!(shown.contains("unlocked · 1 entry in 1 vault"), "{shown}");
    }

    #[test]
    fn no_secret_reaches_the_screen_until_it_is_revealed() {
        let (_scratch, mut screen) = unlocked("ui-secret");

        press(&mut screen, KeyCode::Char('a'));
        press(&mut screen, KeyCode::Enter);
        type_text(&mut screen, "site");
        press(&mut screen, KeyCode::Tab);
        press(&mut screen, KeyCode::Tab);
        type_text(&mut screen, "correct-horse-secret");
        let form = render(&screen, 120, 34);
        assert!(!form.contains("correct-horse-secret"), "{form}");
        press_ctrl(&mut screen, KeyCode::Char('s'));
        assert!(screen.dialog.is_none(), "{}", screen.status);

        for pane in [Pane::Sidebar, Pane::Items, Pane::Details] {
            screen.pane = pane;
            let shown = render(&screen, 120, 30);
            assert!(!shown.contains("correct-horse-secret"), "{shown}");
            assert!(shown.contains(MASK), "{shown}");
        }

        screen.pane = Pane::Items;
        press(&mut screen, KeyCode::Char('r'));
        let revealed = render(&screen, 120, 30);
        assert!(revealed.contains("correct-horse-secret"), "{revealed}");
        assert!(revealed.contains("hides in"), "{revealed}");

        screen.tick(Instant::now() + REVEAL_FOR);
        let hidden = render(&screen, 120, 30);
        assert!(!hidden.contains("correct-horse-secret"), "{hidden}");
    }

    #[test]
    fn a_card_form_shows_a_cards_fields() {
        let (_scratch, mut screen) = unlocked("ui-card-form");
        press(&mut screen, KeyCode::Char('a'));
        let picker = render(&screen, 120, 34);
        assert!(picker.contains("What are you adding?"), "{picker}");
        assert!(picker.contains("Payment card"), "{picker}");

        type_text(&mut screen, "p");
        press(&mut screen, KeyCode::Enter);
        let form = render(&screen, 120, 34);
        for label in [
            "Cardholder",
            "Card number",
            "Expiry",
            "Security code",
            "PIN",
            "Notes",
        ] {
            assert!(form.contains(label), "{label} is missing:\n{form}");
        }
        assert!(form.contains("MM/YY"), "{form}");
    }

    #[test]
    fn an_opened_note_is_shown_and_cannot_carry_escape_sequences() {
        let (_scratch, mut screen) = unlocked("ui-note");
        press(&mut screen, KeyCode::Char('a'));
        type_text(&mut screen, "s");
        press(&mut screen, KeyCode::Enter);
        type_text(&mut screen, "codes");
        press(&mut screen, KeyCode::Tab);
        screen.handle_paste("first line\nsecond \x1b[2J line");
        press_ctrl(&mut screen, KeyCode::Char('s'));
        assert!(screen.dialog.is_none(), "{}", screen.status);

        press(&mut screen, KeyCode::Char('r'));
        let shown = render(&screen, 120, 30);
        assert!(shown.contains("first line"), "{shown}");
        assert!(shown.contains("second"), "{shown}");
        assert!(!shown.contains('\x1b'), "{shown:?}");
    }

    #[test]
    fn every_dialog_draws_and_survives_a_small_terminal() {
        let (_scratch, mut screen) = unlocked("ui-dialogs");
        add_login(&mut screen, "site", "u", "p");

        let dialogs: [&dyn Fn(&mut VaultScreen); 5] = [
            &|s| press(s, KeyCode::Char('a')),
            &|s| {
                press(s, KeyCode::Char('a'));
                press(s, KeyCode::Enter);
            },
            &|s| press(s, KeyCode::Char('e')),
            &|s| press(s, KeyCode::Char('d')),
            &|s| press(s, KeyCode::Char('n')),
        ];
        for open in dialogs {
            open(&mut screen);
            assert!(screen.dialog.is_some());
            render(&screen, 120, 34);
            render(&screen, 40, 12);
            render(&screen, 8, 4);
            screen.dialog = None;
        }
        for section in [Section::Favourites, Section::Recent, Section::All] {
            screen.section = section;
            render(&screen, 120, 34);
            render(&screen, 8, 4);
        }
    }
}
