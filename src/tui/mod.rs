//! The interactive interface, shown when `txc` is run with no arguments.

pub mod app;
pub mod options;
pub mod textarea;
mod ui;

use std::io::Write;
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
        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            handle_key(&mut app, key);
        }

        if let Some(text) = app.pending_clipboard.take() {
            send_to_clipboard(&text)?;
        }
    }
    Ok(())
}

/// Puts text on the system clipboard by asking the terminal to do it.
///
/// This is the OSC 52 sequence. It needs no library and no display server, and
/// it works over ssh and inside tmux, because the copying is done by whatever
/// terminal the reader is sitting in front of. A terminal that does not
/// support the sequence ignores it, so the status line says the output was
/// copied rather than proving it arrived.
fn send_to_clipboard(text: &str) -> Result<()> {
    let mut stdout = std::io::stdout();
    stdout
        .write_all(clipboard_sequence(text).as_bytes())
        .context("cannot reach the terminal")?;
    stdout.flush().context("cannot reach the terminal")?;
    Ok(())
}

/// The OSC 52 sequence that carries `text` to the clipboard.
fn clipboard_sequence(text: &str) -> String {
    format!(
        "\x1b]52;c;{}\x07",
        data_encoding::BASE64.encode(text.as_bytes())
    )
}

fn handle_key(app: &mut App, key: KeyEvent) {
    // Any keystroke clears a message left over from the previous action.
    app.status.clear();

    let control = key.modifiers.contains(KeyModifiers::CONTROL);

    if app.prompt.is_some() {
        if matches!(key.code, KeyCode::Char('c')) && control {
            app.running = false;
        } else {
            prompt_key(app, key, control);
        }
        return;
    }

    if app.overlay_is_open() {
        // While a window is open every key closes it again.
        app.close_overlay();
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
            app.begin_save();
            return;
        }
        (KeyCode::Char('y'), true) => {
            app.copy_output();
            return;
        }
        (KeyCode::Char('n'), true) => {
            app.run_again();
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
            app.focus_next();
            return;
        }
        (KeyCode::BackTab, _) => {
            app.focus_previous();
            return;
        }
        (KeyCode::Char('r'), true) => {
            app.reset_input();
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
        (KeyCode::F(2), _) => {
            app.show_about = true;
            return;
        }
        _ => {}
    }

    match app.focus {
        Focus::Search => search_key(app, key, control),
        Focus::Categories => category_key(app, key),
        Focus::Operations => operation_key(app, key),
        Focus::Input => input_key(app, key, control),
        Focus::Options => options_key(app, key, control),
    }
}

fn search_key(app: &mut App, key: KeyEvent, control: bool) {
    match key.code {
        KeyCode::Char('w') if control => {
            app.search.clear();
            app.refresh_operations();
            app.load_operation();
        }
        KeyCode::Char(ch) => {
            app.search.push(ch);
            app.refresh_operations();
            app.load_operation();
        }
        KeyCode::Backspace => {
            app.search.pop();
            app.refresh_operations();
            app.load_operation();
        }
        KeyCode::Esc => {
            app.search.clear();
            app.refresh_operations();
            app.load_operation();
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
            app.load_operation();
        }
        KeyCode::End => {
            app.operation_index = app.operations.len().saturating_sub(1);
            app.load_operation();
        }
        KeyCode::Enter | KeyCode::Right => {
            app.focus = if app.shows_input() {
                Focus::Input
            } else if app.shows_options() {
                Focus::Options
            } else {
                Focus::Operations
            }
        }
        KeyCode::Left => app.focus = Focus::Categories,
        KeyCode::Char('/') => app.focus = Focus::Search,
        KeyCode::Char('?') => app.show_help = true,
        KeyCode::Char('q') => app.running = false,
        _ => {}
    }
}

/// Keys for the small window that asks where to save the output.
fn prompt_key(app: &mut App, key: KeyEvent, control: bool) {
    let Some(prompt) = app.prompt.as_mut() else {
        return;
    };
    match (key.code, control) {
        (KeyCode::Enter, _) => app.confirm_prompt(),
        (KeyCode::Esc, _) => app.cancel_prompt(),
        (KeyCode::Char('u'), true) => prompt.input.clear(),
        (KeyCode::Char('w'), true) => prompt.input.delete_word(),
        (KeyCode::Char(ch), false) => prompt.input.insert(ch),
        (KeyCode::Backspace, _) => prompt.input.backspace(),
        (KeyCode::Delete, _) => prompt.input.delete(),
        (KeyCode::Left, _) => prompt.input.move_left(),
        (KeyCode::Right, _) => prompt.input.move_right(),
        (KeyCode::Home, _) => prompt.input.move_home(),
        (KeyCode::End, _) => prompt.input.move_end(),
        _ => {}
    }
}

/// Editing keys for the input panel.
fn input_key(app: &mut App, key: KeyEvent, control: bool) {
    let edited = match (key.code, control) {
        (KeyCode::Char('l'), true) => {
            app.input.clear();
            true
        }
        (KeyCode::Char('w'), true) => {
            app.input.delete_word();
            true
        }
        (KeyCode::Char(ch), false) => {
            app.input.insert(ch);
            true
        }
        (KeyCode::Backspace, _) => {
            app.input.backspace();
            true
        }
        (KeyCode::Delete, _) => {
            app.input.delete();
            true
        }
        (KeyCode::Enter, _) => {
            app.input.newline();
            true
        }
        (KeyCode::Left, _) => {
            app.input.move_left();
            false
        }
        (KeyCode::Right, _) => {
            app.input.move_right();
            false
        }
        (KeyCode::Up, _) => {
            app.input.move_up();
            false
        }
        (KeyCode::Down, _) => {
            app.input.move_down();
            false
        }
        (KeyCode::Home, _) => {
            app.input.move_home();
            false
        }
        (KeyCode::End, _) => {
            app.input.move_end();
            false
        }
        (KeyCode::Esc, _) => {
            app.focus = Focus::Operations;
            false
        }
        _ => return,
    };

    // Only an edit changes the result, and only an edit makes the text the
    // reader's own rather than the operation's sample.
    if edited {
        app.mark_input_edited();
        app.recompute();
    }
}

/// Editing keys for the options panel.
///
/// Values are typed into, switches are toggled with space or enter, and the
/// arrow keys move between the parameters.
fn options_key(app: &mut App, key: KeyEvent, control: bool) {
    let changed = match (key.code, control) {
        (KeyCode::Up, _) => {
            app.options.select_previous();
            false
        }
        (KeyCode::Down, _) => {
            app.options.select_next();
            false
        }
        (KeyCode::Enter, _) => {
            if !app.options.toggle() {
                app.options.select_next();
                return;
            }
            true
        }
        (KeyCode::Char(' '), false) if app.options.selected_is_flag() => {
            app.options.toggle();
            true
        }
        (KeyCode::Char('l'), true) => {
            app.options.clear_selected();
            true
        }
        (KeyCode::Char('u'), true) => {
            app.options.reset();
            app.status = "options reset".to_string();
            true
        }
        (KeyCode::Char(ch), false) => {
            app.options.insert(ch);
            true
        }
        (KeyCode::Backspace, _) => {
            app.options.backspace();
            true
        }
        (KeyCode::Delete, _) => {
            app.options.delete();
            true
        }
        (KeyCode::Left, _) => {
            app.options.move_left();
            false
        }
        (KeyCode::Right, _) => {
            app.options.move_right();
            false
        }
        (KeyCode::Home, _) => {
            app.options.move_home();
            false
        }
        (KeyCode::End, _) => {
            app.options.move_end();
            false
        }
        (KeyCode::Esc, _) => {
            app.focus = Focus::Operations;
            false
        }
        _ => return,
    };

    if changed {
        app.recompute();
    }
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
    fn options_start_filled_in_and_react_to_editing() {
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
        // The declared default of 3 is already in the panel and already applied.
        assert_eq!(app.options.fields()[0].value, "3");
        assert_eq!(app.outcome.text(), "def");

        // Editing the field is ordinary typing, with no key=value syntax.
        app.focus = Focus::Options;
        press_ctrl(&mut app, KeyCode::Char('l'));
        press(&mut app, KeyCode::Char('1'));
        assert_eq!(app.outcome.text(), "bcd");
    }

    #[test]
    fn switches_are_toggled_with_space() {
        let mut app = App::new();
        app.search = "sort".to_string();
        app.refresh_operations();
        app.load_operation();
        app.focus = Focus::Input;
        press_ctrl(&mut app, KeyCode::Char('l'));
        for ch in "b".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        press(&mut app, KeyCode::Enter);
        press(&mut app, KeyCode::Char('a'));
        assert_eq!(app.outcome.text(), "a\nb");

        app.focus = Focus::Options;
        assert_eq!(app.options.fields()[0].param.name, "reverse");
        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.outcome.text(), "b\na");
    }

    #[test]
    fn control_r_restores_the_sample_text() {
        let mut app = App::new();
        app.focus = Focus::Input;
        press_ctrl(&mut app, KeyCode::Char('l'));
        press(&mut app, KeyCode::Char('x'));
        assert!(!app.input_is_sample);
        press_ctrl(&mut app, KeyCode::Char('r'));
        assert!(app.input_is_sample);
        assert!(app.input.text().contains("quick brown fox"));
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
    fn f2_opens_the_about_view_and_the_next_key_closes_it() {
        let mut app = App::new();
        press(&mut app, KeyCode::F(2));
        assert!(app.show_about);
        // While it is open, keys close it rather than reaching the panels.
        let before = app.input.text();
        press(&mut app, KeyCode::Char('x'));
        assert!(!app.show_about);
        assert_eq!(app.input.text(), before);
        assert!(app.running);
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
    fn control_n_runs_a_random_operation_again() {
        let mut app = App::new();
        app.search = "password".to_string();
        app.refresh_operations();
        app.load_operation();
        let first = app.outcome.text().to_string();
        press_ctrl(&mut app, KeyCode::Char('n'));
        assert_ne!(app.outcome.text(), first);
    }

    #[test]
    fn control_y_queues_the_output_for_the_clipboard() {
        let mut app = App::new();
        app.search = "upper".to_string();
        app.refresh_operations();
        app.load_operation();
        press_ctrl(&mut app, KeyCode::Char('y'));
        assert!(app.pending_clipboard.is_some());
    }

    #[test]
    fn control_s_opens_a_question_that_takes_every_key() {
        let mut app = App::new();
        app.focus = Focus::Input;
        press_ctrl(&mut app, KeyCode::Char('s'));
        assert!(app.prompt.is_some());

        // While it is open, typing edits the path rather than the input.
        let before = app.input.text();
        press_ctrl(&mut app, KeyCode::Char('u'));
        for ch in "out.txt".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        assert_eq!(app.prompt.as_ref().unwrap().input.text(), "out.txt");
        assert_eq!(app.input.text(), before);

        press(&mut app, KeyCode::Esc);
        assert!(app.prompt.is_none());
    }

    #[test]
    fn control_c_still_quits_while_a_question_is_open() {
        let mut app = App::new();
        press_ctrl(&mut app, KeyCode::Char('s'));
        assert!(app.prompt.is_some());
        press_ctrl(&mut app, KeyCode::Char('c'));
        assert!(!app.running);
    }

    #[test]
    fn the_clipboard_sequence_is_well_formed() {
        // The terminal is asked to do the copying, so the sequence has to be
        // exactly OSC 52 with the text base64 encoded inside it.
        assert_eq!(clipboard_sequence("hello"), "\x1b]52;c;aGVsbG8=\x07");
        // Text with newlines and accents travels intact.
        let text = "line one\ncaf\u{e9}";
        let sequence = clipboard_sequence(text);
        let payload = sequence
            .trim_start_matches("\x1b]52;c;")
            .trim_end_matches('\x07');
        assert_eq!(
            String::from_utf8(data_encoding::BASE64.decode(payload.as_bytes()).unwrap()).unwrap(),
            text
        );
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
