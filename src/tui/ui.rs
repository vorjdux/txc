//! Drawing the interactive interface.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Clear, List, ListItem, ListState, Padding, Paragraph, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Wrap,
};

use crate::about;
use crate::registry::Feed;
use crate::tui::app::{App, Focus};

const ACCENT: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;
const ERROR: Color = Color::Red;
/// Sample text is dimmed, so it reads as a starting point rather than input
/// the reader typed.
const SAMPLE: Color = Color::Gray;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(6),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_header(frame, header, app);

    let [left, middle, right] = Layout::horizontal([
        Constraint::Length(16),
        Constraint::Length(28),
        Constraint::Min(30),
    ])
    .areas(body);

    draw_categories(frame, left, app);

    let [search_area, list_area] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(3)]).areas(middle);
    draw_search(frame, search_area, app);
    draw_operations(frame, list_area, app);

    draw_right_column(frame, right, app);

    draw_footer(frame, footer, app);

    if app.show_help {
        draw_help(frame, frame.area());
    }

    if app.show_about {
        draw_about(frame, frame.area());
    }

    if app.prompt.is_some() {
        draw_prompt(frame, frame.area(), app);
    }
}

/// Draws the small window that asks where to save the output.
fn draw_prompt(frame: &mut Frame, area: Rect, app: &App) {
    let Some(prompt) = app.prompt.as_ref() else {
        return;
    };

    let width = 64.min(area.width.saturating_sub(4));
    let height = 5.min(area.height);
    let window = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };

    frame.render_widget(Clear, window);
    frame.render_widget(
        Paragraph::new(vec![
            Line::raw(prompt.input.text()),
            Line::styled(prompt.hint.clone(), Style::default().fg(MUTED)),
        ])
        .block(panel(&prompt.title, true)),
        window,
    );

    frame.set_cursor_position(Position::new(
        content_x(window) + prompt.input.cursor().1 as u16,
        window.y + 1,
    ));
}

/// Lays out the right hand column, leaving out the panels the selected
/// operation has no use for: a generator gets no input panel, and an operation
/// without parameters gets no options panel. The output takes the space back.
fn draw_right_column(frame: &mut Frame, area: Rect, app: &App) {
    let shows_input = app.shows_input();
    let shows_options = app.shows_options();

    let mut constraints = Vec::new();
    if shows_input {
        constraints.push(Constraint::Percentage(35));
    }
    if shows_options {
        // One line per parameter, plus the border.
        constraints.push(Constraint::Length(app.options.len() as u16 + 2));
    }
    constraints.push(Constraint::Min(3));

    let areas = Layout::vertical(constraints).split(area);
    let mut next = areas.iter();

    if shows_input {
        draw_input(frame, *next.next().expect("input area"), app);
    }
    if shows_options {
        draw_options(frame, *next.next().expect("options area"), app);
    }
    draw_output(frame, *next.next().expect("output area"), app);
}

/// Every panel indents its contents by this much, so text never sits against
/// the border. The cursor positions below are offset by the same amount.
const PAD: u16 = 2;

fn panel(title: &str, focused: bool) -> Block<'_> {
    let style = if focused {
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(MUTED)
    };
    Block::bordered()
        .border_type(if focused {
            BorderType::Thick
        } else {
            BorderType::Rounded
        })
        .border_style(style)
        .padding(Padding::horizontal(PAD))
        .title(Span::styled(format!(" {title} "), style))
}

/// Where the first character of a panel's contents is drawn.
const fn content_x(area: Rect) -> u16 {
    area.x + 1 + PAD
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let operation = app
        .selected_operation()
        .map(|op| op.about)
        .unwrap_or("no operation matches the search");

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
        Span::styled(operation, Style::default().add_modifier(Modifier::BOLD)),
    ]);
    frame.render_widget(Paragraph::new(line), area);
}

fn draw_categories(frame: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .categories
        .iter()
        .map(|category| {
            ListItem::new(match category {
                Some(c) => c.title(),
                None => "All",
            })
        })
        .collect();

    let mut state = ListState::default();
    *state.selected_mut() = Some(app.category_index);

    let list = List::new(items)
        .block(panel("Categories", app.focus == Focus::Categories))
        .highlight_style(Style::default().fg(Color::Black).bg(ACCENT))
        .highlight_symbol("");
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_search(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Search;
    let text = if app.search.is_empty() && !focused {
        Span::styled("type to filter", Style::default().fg(MUTED))
    } else {
        Span::raw(app.search.as_str())
    };
    frame.render_widget(
        Paragraph::new(Line::from(text)).block(panel("Search", focused)),
        area,
    );
    if focused {
        frame.set_cursor_position(Position::new(
            content_x(area) + app.search.chars().count() as u16,
            area.y + 1,
        ));
    }
}

fn draw_operations(frame: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .operations
        .iter()
        .map(|op| {
            ListItem::new(Line::from(vec![
                Span::raw(op.name),
                Span::styled(
                    if op.feed == Feed::None { "  gen" } else { "" },
                    Style::default().fg(MUTED),
                ),
            ]))
        })
        .collect();

    let title = format!("Operations ({})", app.operations.len());
    let mut state = ListState::default();
    if !app.operations.is_empty() {
        *state.selected_mut() = Some(app.operation_index);
    }

    let list = List::new(items)
        .block(panel(&title, app.focus == Focus::Operations))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("");
    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_input(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Input;
    let sample = app.input_is_sample;

    let title = if sample {
        format!(
            "Input ({} characters, sample)",
            app.input.text().chars().count()
        )
    } else {
        format!("Input ({} characters)", app.input.text().chars().count())
    };

    // Scroll just enough to keep the cursor line on screen.
    let (row, column) = app.input.cursor();
    let height = area.height.saturating_sub(2) as usize;
    let offset = row.saturating_sub(height.saturating_sub(1));

    let lines: Vec<Line> = app
        .input
        .lines()
        .iter()
        .map(|line| Line::raw(line.as_str()))
        .collect();

    let style = if sample {
        Style::default().fg(SAMPLE)
    } else {
        Style::default()
    };
    frame.render_widget(
        Paragraph::new(lines)
            .style(style)
            .scroll((offset as u16, 0))
            .block(panel(&title, focused)),
        area,
    );

    if focused {
        let width = area.width.saturating_sub(2 + PAD * 2) as usize;
        frame.set_cursor_position(Position::new(
            content_x(area) + column.min(width) as u16,
            area.y + 1 + (row - offset) as u16,
        ));
    }
}

/// Draws one line per parameter, with its current value, so the panel shows
/// what the operation is about to do instead of an empty box.
fn draw_options(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Options;
    let fields = app.options.fields();

    let width = fields
        .iter()
        .map(|field| field.param.name.chars().count())
        .max()
        .unwrap_or(0);

    let lines: Vec<Line> = fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let selected = focused && index == app.options.selected();
            // The selected row is marked by weight rather than by a symbol,
            // so every panel indents its contents by the same amount.
            let label = if selected {
                Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(MUTED)
            };
            let value = if selected {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Line::from(vec![
                Span::styled(format!("{:width$}  ", field.param.name), label),
                Span::styled(field.display(), value),
            ])
        })
        .collect();

    let title = fields
        .get(app.options.selected())
        .filter(|_| focused)
        .map(|field| format!("Options: {}", field.param.help))
        .unwrap_or_else(|| "Options".to_string());

    frame.render_widget(Paragraph::new(lines).block(panel(&title, focused)), area);

    // The cursor belongs in the value of the selected field, and only when
    // that field is something to type into.
    if focused && !app.options.selected_is_flag() {
        // Past the name column and the two spaces after it.
        let column = width + 2 + app.options.cursor();
        frame.set_cursor_position(Position::new(
            content_x(area) + column as u16,
            area.y + 1 + app.options.selected() as u16,
        ));
    }
}

fn draw_output(frame: &mut Frame, area: Rect, app: &App) {
    let failed = app.outcome.is_error();
    let text = app.outcome.text();
    let title = if failed {
        "Output (error)".to_string()
    } else if app.varies() {
        format!(
            "Output ({} characters, ^n for another)",
            text.chars().count()
        )
    } else {
        format!("Output ({} characters)", text.chars().count())
    };

    let block = panel(&title, false);
    let style = if failed {
        Style::default().fg(ERROR)
    } else {
        Style::default()
    };

    frame.render_widget(
        Paragraph::new(text)
            .style(style)
            .wrap(Wrap { trim: false })
            .scroll((app.output_scroll, 0))
            .block(block),
        area,
    );

    let total = text.lines().count();
    let visible = area.height.saturating_sub(2) as usize;
    if total > visible {
        let mut state =
            ScrollbarState::new(total.saturating_sub(visible)).position(app.output_scroll as usize);
        frame.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight),
            area,
            &mut state,
        );
    }
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let keys: Vec<(&str, &str)> = if app.status.is_empty() {
        let mut keys = vec![("tab", "panel"), ("^up/^down", "op")];
        if app.varies() {
            keys.push(("^n", "new"));
        }
        keys.extend([
            ("^y", "copy"),
            ("^s", "save"),
            ("?", "help"),
            ("F2", "about"),
            ("^c", "quit"),
        ]);
        keys
    } else {
        vec![]
    };

    let line = if keys.is_empty() {
        Line::from(Span::styled(
            format!(" {}", app.status),
            Style::default().fg(ACCENT),
        ))
    } else {
        Line::from(
            keys.into_iter()
                .flat_map(|(key, label)| {
                    [
                        Span::styled(
                            format!(" {key} "),
                            Style::default().fg(Color::Black).bg(MUTED),
                        ),
                        Span::styled(format!(" {label}  "), Style::default().fg(MUTED)),
                    ]
                })
                .collect::<Vec<_>>(),
        )
    };
    frame.render_widget(Paragraph::new(line), area);
}

/// A window in the middle of the screen, sized to its contents.
fn window(area: Rect, columns: u16, rows: u16) -> Rect {
    let width = columns.min(area.width.saturating_sub(4));
    let height = rows.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    }
}

/// Draws the About view: what this is, who wrote it, and under what terms.
fn draw_about(frame: &mut Frame, area: Rect) {
    const COLUMNS: u16 = 72;
    let rows = about::rows();
    let label_width = rows.iter().map(|(label, _)| label.len()).max().unwrap_or(0);

    let mut text = vec![
        Line::raw(""),
        Line::styled(
            about::NAME,
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
    ];

    // The description is a full sentence, so it is wrapped rather than cut.
    let inner = area.width.min(COLUMNS).saturating_sub(2 + PAD * 2).max(20) as usize;
    for line in textwrap::wrap(about::DESCRIPTION, inner) {
        text.push(Line::styled(line.into_owned(), Style::default().fg(MUTED)));
    }
    text.push(Line::raw(""));

    for (label, value) in rows {
        text.push(Line::from(vec![
            Span::styled(
                format!("{label:label_width$}  "),
                Style::default().fg(MUTED),
            ),
            Span::raw(value),
        ]));
    }

    text.push(Line::raw(""));
    for line in textwrap::wrap(
        "Your text never leaves this machine: txc makes no network requests.",
        inner.max(20),
    ) {
        text.push(Line::styled(
            format!("  {line}"),
            Style::default().fg(ACCENT),
        ));
    }
    text.push(Line::raw(""));
    text.push(Line::styled("any key to close", Style::default().fg(MUTED)));

    let height = text.len() as u16 + 2;
    let popup = window(area, COLUMNS, height);
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Left)
            .block(panel("About", true)),
        popup,
    );
}

fn draw_help(frame: &mut Frame, area: Rect) {
    let popup = window(area, 64, 25);

    let text = vec![
        Line::raw(""),
        Line::raw("tab / shift+tab      move between panels"),
        Line::raw("up / down            move inside a list or between options"),
        Line::raw("ctrl+up / ctrl+down  change operation from anywhere"),
        Line::raw("ctrl+left/right      change category"),
        Line::raw("/                    jump to the search box"),
        Line::raw(""),
        Line::raw("Options panel"),
        Line::raw("type               edit the selected value"),
        Line::raw("space              turn the selected switch on or off"),
        Line::raw("ctrl+l             empty the selected value"),
        Line::raw("ctrl+u             put every option back to its default"),
        Line::raw(""),
        Line::raw("ctrl+n               run the operation again, for the random ones"),
        Line::raw("ctrl+y               copy the output to the clipboard"),
        Line::raw("ctrl+s               save the output, asking where"),
        Line::raw("ctrl+p               move the output into the input"),
        Line::raw("ctrl+r               bring back the sample text"),
        Line::raw("ctrl+l               clear the input"),
        Line::raw("page up / page down  scroll the output"),
        Line::raw(""),
        Line::raw("F2  about txc, its author and licence"),
        Line::raw("?   close this help             ctrl+c  quit"),
    ];

    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Left)
            .block(panel("Keys", true)),
        popup,
    );
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::registry;

    fn render(app: &mut App, width: u16, height: u16) -> String {
        render_with_cursor(app, width, height).0
    }

    /// Renders and also reports where the cursor was left, which is the part
    /// of the padding that a screenshot cannot show.
    fn render_with_cursor(app: &mut App, width: u16, height: u16) -> (String, (u16, u16)) {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal.draw(|frame| draw(frame, app)).expect("draw");
        let cursor = terminal.get_cursor_position().expect("cursor position");
        let screen = terminal
            .backend()
            .buffer()
            .content()
            .chunks(width as usize)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        (screen, (cursor.x, cursor.y))
    }

    /// Where a piece of text sits on screen, as a column and a row.
    ///
    /// The columns are counted in characters, not bytes: the borders are
    /// multi byte, so a byte offset would not be a screen position.
    fn find(screen: &str, needle: &str) -> (u16, u16) {
        for (row, line) in screen.lines().enumerate() {
            if let Some(byte) = line.find(needle) {
                let column = line[..byte].chars().count();
                return (column as u16, row as u16);
            }
        }
        panic!("{needle:?} is not on screen:\n{screen}");
    }

    #[test]
    #[ignore = "prints the layout used in the README"]
    fn screenshot() {
        let mut app = App::new();
        app.search = std::env::var("TXC_SHOT").unwrap_or_else(|_| "base64".into());
        app.refresh_operations();
        app.load_operation();
        if std::env::var("TXC_SHOT_SAVE").is_ok() {
            app.begin_save();
        }
        if std::env::var("TXC_SHOT_ABOUT").is_ok() {
            app.show_about = true;
        }
        let width = 92;
        let mut terminal = Terminal::new(TestBackend::new(width, 22)).expect("terminal");
        terminal.draw(|frame| draw(frame, &mut app)).expect("draw");
        let screen = terminal
            .backend()
            .buffer()
            .content()
            .chunks(width as usize)
            .map(|row| {
                row.iter()
                    .map(|cell| cell.symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        println!("{screen}");
    }

    #[test]
    fn draws_every_panel() {
        let mut app = App::new();
        app.search = "caesar".to_string();
        app.refresh_operations();
        app.load_operation();
        app.input = crate::tui::textarea::TextArea::from_text("hello");
        app.recompute();

        let screen = render(&mut app, 100, 30);
        assert!(screen.contains("txc"), "{screen}");
        assert!(screen.contains("Categories"), "{screen}");
        assert!(screen.contains("Operations"), "{screen}");
        assert!(screen.contains("Input"), "{screen}");
        assert!(screen.contains("Options"), "{screen}");
        assert!(screen.contains("Output"), "{screen}");
        // The parameter and its value are both shown, ready to edit.
        assert!(screen.contains("shift"), "{screen}");
        assert!(screen.contains("khoor"), "{screen}");
    }

    #[test]
    fn an_operation_without_options_gets_no_options_panel() {
        let mut app = App::new();
        app.search = "upper".to_string();
        app.refresh_operations();
        app.load_operation();
        let screen = render(&mut app, 100, 30);
        assert!(screen.contains("Input"), "{screen}");
        assert!(!screen.contains("Options"), "{screen}");
    }

    #[test]
    fn a_generator_gets_no_input_panel() {
        let mut app = App::new();
        app.search = "password".to_string();
        app.refresh_operations();
        app.load_operation();
        let screen = render(&mut app, 100, 30);
        assert!(!screen.contains("Input"), "{screen}");
        assert!(screen.contains("Options"), "{screen}");
        assert!(screen.contains("length"), "{screen}");
    }

    #[test]
    fn the_about_view_names_the_author_and_the_terms() {
        let mut app = App::new();
        app.show_about = true;
        let screen = render(&mut app, 100, 30);
        assert!(screen.contains("About"), "{screen}");
        assert!(screen.contains("Matheus Santos"), "{screen}");
        assert!(screen.contains("vorj.dux@gmail.com"), "{screen}");
        assert!(screen.contains("MIT OR Apache-2.0"), "{screen}");
        assert!(screen.contains(env!("CARGO_PKG_VERSION")), "{screen}");
        assert!(screen.contains("143 in 10 categories"), "{screen}");
        assert!(screen.contains("never leaves this machine"), "{screen}");
    }

    #[test]
    fn the_about_view_fits_a_small_terminal() {
        let mut app = App::new();
        app.show_about = true;
        render(&mut app, 40, 12);
        render(&mut app, 20, 6);
    }

    #[test]
    fn every_panel_indents_its_contents_by_the_same_amount() {
        let mut app = App::new();
        app.search = "caesar".to_string();
        app.refresh_operations();
        app.load_operation();
        let screen = render(&mut app, 100, 30);

        // The category list, the search box, the operation list, the input,
        // the options and the output all start at the same offset from their
        // own border.
        for (content, border) in [
            ("All", '\u{256d}'),
            ("caesar", '\u{256d}'),
            ("The quick", '\u{256d}'),
            ("shift", '\u{256d}'),
            ("Wkh txlfn", '\u{256d}'),
        ] {
            let (column, row) = find(&screen, content);
            let line: Vec<char> = screen.lines().nth(row as usize).unwrap().chars().collect();
            let indent = (0..column)
                .rev()
                .take_while(|i| line[*i as usize] == ' ')
                .count();
            assert_eq!(
                indent, PAD as usize,
                "{content:?} is indented {indent} rather than {PAD}, border {border:?}"
            );
        }
    }

    #[test]
    fn the_input_cursor_sits_after_the_padding() {
        let mut app = App::new();
        app.search = "upper".to_string();
        app.refresh_operations();
        app.load_operation();
        app.input = crate::tui::textarea::TextArea::from_text("abc");
        app.focus = Focus::Input;
        app.recompute();

        let (screen, cursor) = render_with_cursor(&mut app, 100, 30);
        let (column, row) = find(&screen, "abc");
        // Three characters typed, so the cursor stands just past them.
        assert_eq!(cursor, (column + 3, row));
    }

    #[test]
    fn the_search_cursor_sits_after_the_padding() {
        let mut app = App::new();
        app.focus = Focus::Search;
        app.search = "up".to_string();
        app.refresh_operations();
        let (screen, cursor) = render_with_cursor(&mut app, 100, 30);
        let (column, row) = find(&screen, "up");
        assert_eq!(cursor, (column + 2, row));
    }

    #[test]
    fn the_options_cursor_sits_in_the_value() {
        let mut app = App::new();
        app.search = "caesar".to_string();
        app.refresh_operations();
        app.load_operation();
        app.focus = Focus::Options;

        let (screen, cursor) = render_with_cursor(&mut app, 100, 30);
        // The value is a single character, and the cursor follows it.
        let (column, row) = find(&screen, "shift  3");
        assert_eq!(cursor, (column + "shift  3".len() as u16, row));
    }

    #[test]
    fn the_save_question_puts_the_cursor_in_the_path() {
        let mut app = App::new();
        app.search = "uuid".to_string();
        app.refresh_operations();
        app.load_operation();
        app.begin_save();
        let (screen, cursor) = render_with_cursor(&mut app, 100, 30);
        let (column, row) = find(&screen, "uuid.txt");
        assert_eq!(cursor, (column + "uuid.txt".len() as u16, row));
    }

    #[test]
    fn draws_the_help_overlay() {
        let mut app = App::new();
        app.show_help = true;
        let screen = render(&mut app, 100, 30);
        assert!(screen.contains("Keys"), "{screen}");
        assert!(screen.contains("quit"), "{screen}");
    }

    #[test]
    fn survives_a_very_small_terminal() {
        let mut app = App::new();
        // Narrow enough that several panels have no room at all.
        render(&mut app, 20, 8);
        render(&mut app, 10, 4);
    }

    #[test]
    fn draws_every_operation_without_panicking() {
        let mut app = App::new();
        for index in 0..registry::all().len() {
            app.operation_index = index;
            app.load_operation();
            render(&mut app, 90, 26);
            // The options panel is only focusable when it is on screen.
            app.focus = crate::tui::app::Focus::Options;
            render(&mut app, 90, 26);
            app.focus = crate::tui::app::Focus::Operations;
        }
    }

    #[test]
    fn draws_the_save_question_over_the_interface() {
        let mut app = App::new();
        app.search = "uuid".to_string();
        app.refresh_operations();
        app.load_operation();
        app.begin_save();
        let screen = render(&mut app, 100, 30);
        assert!(screen.contains("Save the output as"), "{screen}");
        assert!(screen.contains("uuid.txt"), "{screen}");
        assert!(screen.contains("esc to cancel"), "{screen}");
    }

    #[test]
    fn the_output_panel_offers_another_run_only_where_it_would_differ() {
        let mut app = App::new();
        app.search = "password".to_string();
        app.refresh_operations();
        app.load_operation();
        assert!(render(&mut app, 100, 30).contains("^n for another"));

        app.search = "upper".to_string();
        app.refresh_operations();
        app.load_operation();
        assert!(!render(&mut app, 100, 30).contains("^n for another"));
    }

    #[test]
    fn shows_errors_in_the_output_panel() {
        let mut app = App::new();
        app.search = "url-decode".to_string();
        app.refresh_operations();
        app.input = crate::tui::textarea::TextArea::from_text("%FF");
        app.recompute();
        let screen = render(&mut app, 100, 30);
        assert!(screen.contains("error"), "{screen}");
    }
}
