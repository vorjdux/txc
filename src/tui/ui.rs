//! Drawing the interactive interface.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Clear, List, ListItem, ListState, Paragraph, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Wrap,
};

use crate::registry::Feed;
use crate::tui::app::{App, Focus};

const ACCENT: Color = Color::Cyan;
const MUTED: Color = Color::DarkGray;
const ERROR: Color = Color::Red;

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

    let [input_area, options_area, output_area] = Layout::vertical([
        Constraint::Percentage(35),
        Constraint::Length(3),
        Constraint::Min(5),
    ])
    .areas(right);
    draw_input(frame, input_area, app);
    draw_options(frame, options_area, app);
    draw_output(frame, output_area, app);

    draw_footer(frame, footer, app);

    if app.show_help {
        draw_help(frame, frame.area());
    }
}

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
        .title(Span::styled(format!(" {title} "), style))
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
            area.x + 1 + app.search.chars().count() as u16,
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
    let generator = app
        .selected_operation()
        .is_some_and(|op| op.feed == Feed::None);

    let title = if generator {
        "Input (not used by this operation)".to_string()
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

    let style = if generator {
        Style::default().fg(MUTED)
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

    if focused && !generator {
        let width = area.width.saturating_sub(2) as usize;
        frame.set_cursor_position(Position::new(
            area.x + 1 + column.min(width) as u16,
            area.y + 1 + (row - offset) as u16,
        ));
    }
}

fn draw_options(frame: &mut Frame, area: Rect, app: &App) {
    let focused = app.focus == Focus::Options;
    let op = app.selected_operation();

    let hint = op
        .map(|op| {
            if op.params.is_empty() {
                "this operation takes no options".to_string()
            } else {
                op.params
                    .iter()
                    .map(|p| {
                        if p.is_flag() {
                            p.name.to_string()
                        } else {
                            format!("{}=", p.name)
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(" ")
            }
        })
        .unwrap_or_default();

    let text = if app.options.is_empty() && !focused {
        Line::from(Span::styled(hint, Style::default().fg(MUTED)))
    } else {
        Line::raw(app.options.text())
    };

    frame.render_widget(Paragraph::new(text).block(panel("Options", focused)), area);
    if focused {
        frame.set_cursor_position(Position::new(
            area.x + 1 + app.options.cursor().1 as u16,
            area.y + 1,
        ));
    }
}

fn draw_output(frame: &mut Frame, area: Rect, app: &App) {
    let failed = app.outcome.is_error();
    let text = app.outcome.text();
    let title = if failed {
        "Output (error)".to_string()
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
    let keys = if app.status.is_empty() {
        vec![
            ("tab", "panel"),
            ("^up/^down", "operation"),
            ("^p", "pipe output to input"),
            ("^s", "save"),
            ("?", "help"),
            ("^c", "quit"),
        ]
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

fn draw_help(frame: &mut Frame, area: Rect) {
    let width = 62.min(area.width.saturating_sub(4));
    let height = 20.min(area.height.saturating_sub(2));
    let popup = Rect {
        x: area.x + (area.width - width) / 2,
        y: area.y + (area.height - height) / 2,
        width,
        height,
    };

    let text = vec![
        Line::raw(""),
        Line::raw("  tab / shift+tab    move between panels"),
        Line::raw("  up / down          move inside a list"),
        Line::raw("  ctrl+up / ctrl+down  change operation from anywhere"),
        Line::raw("  ctrl+left / ctrl+right  change category"),
        Line::raw("  page up / page down  scroll the output"),
        Line::raw(""),
        Line::raw("  ctrl+p             move the output into the input"),
        Line::raw("  ctrl+s             save the output to txc-output.txt"),
        Line::raw("  ctrl+l             clear the input"),
        Line::raw("  ctrl+w             delete the word before the cursor"),
        Line::raw(""),
        Line::raw("  Options accept key=value pairs and bare switches,"),
        Line::raw("  for example: width=40 upper"),
        Line::raw(""),
        Line::raw("  ?  close this help          ctrl+c  quit"),
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
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal.draw(|frame| draw(frame, app)).expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(width as usize)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    #[ignore = "prints the layout used in the README"]
    fn screenshot() {
        let mut app = App::new();
        app.search = "base64".to_string();
        app.refresh_operations();
        app.input = crate::tui::textarea::TextArea::from_text("offline text tools");
        app.recompute();
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
        app.search = "upper".to_string();
        app.refresh_operations();
        app.input = crate::tui::textarea::TextArea::from_text("hello");
        app.recompute();

        let screen = render(&mut app, 100, 30);
        assert!(screen.contains("txc"), "{screen}");
        assert!(screen.contains("Categories"), "{screen}");
        assert!(screen.contains("Operations"), "{screen}");
        assert!(screen.contains("Input"), "{screen}");
        assert!(screen.contains("Options"), "{screen}");
        assert!(screen.contains("Output"), "{screen}");
        assert!(screen.contains("HELLO"), "{screen}");
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
            app.recompute();
            render(&mut app, 90, 26);
        }
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
