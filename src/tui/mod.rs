//! The interactive interface, shown when `txc` is run with no arguments.

pub mod app;
pub(crate) mod textarea;
mod ui;

use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::tui::app::{App, Focus};

/// Opens the interface and runs until the user quits.
///
/// Reports a plain error when there is no terminal to draw on, such as when
/// `txc tui` is run from a script or a pipeline.
pub fn run() -> Result<()> {
    let mut terminal = ratatui::try_init()
        .context("the interactive interface needs a terminal; run txc <operation> instead")?;
    let result = event_loop(&mut terminal);
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
    let mut app = App::new();

    while app.running {
        terminal.draw(|frame| ui::draw(frame, &mut app))?;

        // Waking up regularly keeps the interface responsive to resizes even
        // when no key is pressed.
        if !event::poll(Duration::from_millis(200))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                handle_key(&mut app, key);
            }
        }
    }
    Ok(())
}

fn handle_key(app: &mut App, key: KeyEvent) {
    // Any keystroke clears a message left over from the previous action.
    app.status.clear();

    let control = key.modifiers.contains(KeyModifiers::CONTROL);

    if app.show_help {
        // While the help is open every key closes it again.
        app.show_help = false;
        if matches!(key.code, KeyCode::Char('c')) && control {
            app.running = false;
        }
        return;
    }

    // Keys that work the same in every panel.
    match (key.code, control) {
        (KeyCode::Char('c'), true) => {
            app.running = false;
            return;
        }
        (KeyCode::Char('p'), true) => {
            app.pipe_output_into_input();
            return;
        }
        (KeyCode::Char('s'), true) => {
            app.save_output();
            return;
        }
        (KeyCode::Up, true) => {
            app.select_previous_operation();
            return;
        }
        (KeyCode::Down, true) => {
            app.select_next_operation();
            return;
        }
        (KeyCode::Left, true) => {
            app.select_previous_category();
            return;
        }
        (KeyCode::Right, true) => {
            app.select_next_category();
            return;
        }
        (KeyCode::Tab, _) => {
            app.focus = app.focus.next();
            return;
        }
        (KeyCode::BackTab, _) => {
            app.focus = app.focus.previous();
            return;
        }
        (KeyCode::PageUp, _) => {
            app.output_scroll = app.output_scroll.saturating_sub(5);
            return;
        }
        (KeyCode::PageDown, _) => {
            app.output_scroll = app.output_scroll.saturating_add(5);
            return;
        }
        (KeyCode::F(1), _) => {
            app.show_help = true;
            return;
        }
        _ => {}
    }

    match app.focus {
        Focus::Search => search_key(app, key, control),
        Focus::Categories => category_key(app, key),
        Focus::Operations => operation_key(app, key),
        Focus::Input => text_key(app, key, control, true),
        Focus::Options => text_key(app, key, control, false),
    }
}

fn search_key(app: &mut App, key: KeyEvent, control: bool) {
    match key.code {
        KeyCode::Char('w') if control => {
            app.search.clear();
            app.refresh_operations();
            app.recompute();
        }
        KeyCode::Char(ch) => {
            app.search.push(ch);
            app.refresh_operations();
            app.recompute();
        }
        KeyCode::Backspace => {
            app.search.pop();
            app.refresh_operations();
            app.recompute();
        }
        KeyCode::Esc => {
            app.search.clear();
            app.refresh_operations();
            app.recompute();
        }
        KeyCode::Enter | KeyCode::Down => app.focus = Focus::Operations,
        _ => {}
    }
}

fn category_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Down | KeyCode::Char('j') => app.select_next_category(),
        KeyCode::Up | KeyCode::Char('k') => app.select_previous_category(),
        KeyCode::Enter | KeyCode::Right => app.focus = Focus::Operations,
        KeyCode::Char('/') => app.focus = Focus::Search,
        KeyCode::Char('?') => app.show_help = true,
        KeyCode::Char('q') => app.running = false,
        _ => {}
    }
}

fn operation_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Down | KeyCode::Char('j') => app.select_next_operation(),
        KeyCode::Up | KeyCode::Char('k') => app.select_previous_operation(),
        KeyCode::Home => {
            app.operation_index = 0;
            app.recompute();
        }
        KeyCode::End => {
            app.operation_index = app.operations.len().saturating_sub(1);
            app.recompute();
        }
        KeyCode::Enter | KeyCode::Right => app.focus = Focus::Input,
        KeyCode::Left => app.focus = Focus::Categories,
        KeyCode::Char('/') => app.focus = Focus::Search,
        KeyCode::Char('?') => app.show_help = true,
        KeyCode::Char('q') => app.running = false,
        _ => {}
    }
}

/// Editing keys for the input and options panels.
fn text_key(app: &mut App, key: KeyEvent, control: bool, multiline: bool) {
    let area = if multiline {
        &mut app.input
    } else {
        &mut app.options
    };

    match (key.code, control) {
        (KeyCode::Char('l'), true) => area.clear(),
        (KeyCode::Char('w'), true) => area.delete_word(),
        (KeyCode::Char(ch), false) => area.insert(ch),
        (KeyCode::Backspace, _) => area.backspace(),
        (KeyCode::Delete, _) => area.delete(),
        (KeyCode::Enter, _) if multiline => area.newline(),
        (KeyCode::Enter, _) => {
            app.focus = Focus::Operations;
            return;
        }
        (KeyCode::Left, _) => {
            area.move_left();
            return;
        }
        (KeyCode::Right, _) => {
            area.move_right();
            return;
        }
        (KeyCode::Up, _) => {
            area.move_up();
            return;
        }
        (KeyCode::Down, _) => {
            area.move_down();
            return;
        }
        (KeyCode::Home, _) => {
            area.move_home();
            return;
        }
        (KeyCode::End, _) => {
            area.move_end();
            return;
        }
        (KeyCode::Esc, _) => {
            app.focus = Focus::Operations;
            return;
        }
        _ => return,
    }

    // Only edits change the result, so movement returns early above.
    app.recompute();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn press(app: &mut App, code: KeyCode) {
        handle_key(app, KeyEvent::new(code, KeyModifiers::NONE));
    }

    fn press_ctrl(app: &mut App, code: KeyCode) {
        handle_key(app, KeyEvent::new(code, KeyModifiers::CONTROL));
    }

    #[test]
    fn control_c_quits() {
        let mut app = App::new();
        assert!(app.running);
        press_ctrl(&mut app, KeyCode::Char('c'));
        assert!(!app.running);
    }

    #[test]
    fn tab_moves_between_panels() {
        let mut app = App::new();
        app.focus = Focus::Search;
        press(&mut app, KeyCode::Tab);
        assert_eq!(app.focus, Focus::Categories);
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE),
        );
        assert_eq!(app.focus, Focus::Search);
    }

    #[test]
    fn typing_in_the_search_filters_operations() {
        let mut app = App::new();
        app.focus = Focus::Search;
        for ch in "sha256".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        assert_eq!(app.selected_operation().unwrap().name, "sha256");
        press(&mut app, KeyCode::Backspace);
        assert_eq!(app.search, "sha25");
    }

    #[test]
    fn typing_in_the_input_updates_the_output_immediately() {
        let mut app = App::new();
        app.focus = Focus::Search;
        for ch in "upper".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        app.focus = Focus::Input;
        press_ctrl(&mut app, KeyCode::Char('l'));
        for ch in "abc".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        assert_eq!(app.input.text(), "abc");
        assert_eq!(app.outcome.text(), "ABC");
    }

    #[test]
    fn options_are_applied_as_they_are_typed() {
        let mut app = App::new();
        app.focus = Focus::Search;
        for ch in "caesar".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        app.focus = Focus::Input;
        press_ctrl(&mut app, KeyCode::Char('l'));
        for ch in "abc".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        assert_eq!(app.outcome.text(), "def");

        app.focus = Focus::Options;
        for ch in "shift=1".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        assert_eq!(app.outcome.text(), "bcd");
    }

    #[test]
    fn control_p_chains_operations() {
        let mut app = App::new();
        app.focus = Focus::Search;
        for ch in "upper".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        app.focus = Focus::Input;
        press_ctrl(&mut app, KeyCode::Char('l'));
        for ch in "hi".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        press_ctrl(&mut app, KeyCode::Char('p'));
        assert_eq!(app.input.text(), "HI");
    }

    #[test]
    fn help_opens_and_the_next_key_closes_it() {
        let mut app = App::new();
        app.focus = Focus::Operations;
        press(&mut app, KeyCode::Char('?'));
        assert!(app.show_help);
        press(&mut app, KeyCode::Char('x'));
        assert!(!app.show_help);
        assert!(app.running);
    }

    #[test]
    fn letters_edit_text_rather_than_acting_as_shortcuts() {
        let mut app = App::new();
        app.focus = Focus::Input;
        press_ctrl(&mut app, KeyCode::Char('l'));
        press(&mut app, KeyCode::Char('q'));
        assert!(app.running, "q must not quit while typing");
        assert_eq!(app.input.text(), "q");
    }

    #[test]
    fn arrow_keys_move_through_operations_from_any_panel() {
        let mut app = App::new();
        app.focus = Focus::Input;
        let first = app.selected_operation().unwrap().name;
        press_ctrl(&mut app, KeyCode::Down);
        assert_ne!(app.selected_operation().unwrap().name, first);
        press_ctrl(&mut app, KeyCode::Up);
        assert_eq!(app.selected_operation().unwrap().name, first);
    }
}
