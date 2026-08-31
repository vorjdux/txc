//! State of the interactive interface.

use crate::registry::{self, Category, Feed, Op};
use crate::tui::options::OptionsEditor;
use crate::tui::textarea::TextArea;

/// Which panel keystrokes are going to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Focus {
    Search,
    Categories,
    Operations,
    Input,
    Options,
}

impl Focus {
    const ORDER: [Focus; 5] = [
        Focus::Search,
        Focus::Categories,
        Focus::Operations,
        Focus::Input,
        Focus::Options,
    ];
}

/// The result of running the selected operation over the current input.
#[derive(Clone, Debug)]
pub enum Outcome {
    Ready(String),
    Failed(String),
}

impl Outcome {
    pub fn text(&self) -> &str {
        match self {
            Outcome::Ready(text) | Outcome::Failed(text) => text,
        }
    }

    pub fn is_error(&self) -> bool {
        matches!(self, Outcome::Failed(_))
    }
}

pub struct App {
    /// `None` stands for the entry that shows every category at once.
    pub categories: Vec<Option<Category>>,
    pub category_index: usize,
    pub operations: Vec<&'static Op>,
    pub operation_index: usize,
    pub search: String,
    pub input: TextArea,
    pub options: OptionsEditor,
    /// True while the input still holds the sample loaded for the selected
    /// operation, which is what makes it safe to replace on the next change.
    pub input_is_sample: bool,
    pub outcome: Outcome,
    pub focus: Focus,
    pub output_scroll: u16,
    pub show_help: bool,
    pub status: String,
    pub running: bool,
}

impl Default for App {
    fn default() -> Self {
        App::new()
    }
}

impl App {
    /// Builds the interface state, with a sample sentence in the input so the
    /// output panel shows something useful straight away.
    pub fn new() -> App {
        let mut categories = vec![None];
        categories.extend(Category::ALL.iter().copied().map(Some));

        let mut app = App {
            categories,
            category_index: 0,
            operations: Vec::new(),
            operation_index: 0,
            search: String::new(),
            input: TextArea::default(),
            options: OptionsEditor::default(),
            input_is_sample: true,
            outcome: Outcome::Ready(String::new()),
            focus: Focus::Operations,
            output_scroll: 0,
            show_help: false,
            status: String::new(),
            running: true,
        };
        app.refresh_operations();
        app.load_operation();
        app
    }

    /// Panels the current operation actually shows, in tab order.
    ///
    /// A generator has no input to edit and an operation without parameters
    /// has no options, so neither panel is drawn nor focused.
    pub fn focus_order(&self) -> Vec<Focus> {
        Focus::ORDER
            .iter()
            .copied()
            .filter(|focus| match focus {
                Focus::Input => self.shows_input(),
                Focus::Options => self.shows_options(),
                _ => true,
            })
            .collect()
    }

    /// Whether the selected operation reads any input.
    pub fn shows_input(&self) -> bool {
        self.selected_operation()
            .is_some_and(|op| op.feed != Feed::None)
    }

    /// Whether the selected operation has any options to set.
    pub fn shows_options(&self) -> bool {
        !self.options.is_empty()
    }

    pub fn focus_next(&mut self) {
        let order = self.focus_order();
        let index = order.iter().position(|f| *f == self.focus).unwrap_or(0);
        self.focus = order[(index + 1) % order.len()];
    }

    pub fn focus_previous(&mut self) {
        let order = self.focus_order();
        let index = order.iter().position(|f| *f == self.focus).unwrap_or(0);
        self.focus = order[(index + order.len() - 1) % order.len()];
    }

    /// Moves focus off a panel the current operation does not show.
    fn settle_focus(&mut self) {
        let order = self.focus_order();
        if !order.contains(&self.focus) {
            self.focus = Focus::Operations;
        }
    }

    /// Prepares the panels for the selected operation: fresh options, and the
    /// operation's own sample text unless the reader has typed their own.
    pub fn load_operation(&mut self) {
        let Some(op) = self.selected_operation() else {
            self.options = OptionsEditor::default();
            self.outcome = Outcome::Ready(String::new());
            return;
        };

        self.options = OptionsEditor::for_op(op);
        if self.input_is_sample {
            self.input = TextArea::from_text(op.sample_input());
        }
        self.settle_focus();
        self.recompute();
    }

    /// Puts the sample text back, discarding whatever was typed.
    pub fn reset_input(&mut self) {
        if let Some(op) = self.selected_operation() {
            self.input = TextArea::from_text(op.sample_input());
            self.input_is_sample = true;
            self.status = "sample text restored".to_string();
            self.recompute();
        }
    }

    /// Records that the reader edited the input, so it is theirs to keep.
    pub fn mark_input_edited(&mut self) {
        self.input_is_sample = false;
    }

    /// How well an operation answers the search, lower being better.
    ///
    /// Ranking matters because a substring search alone would offer
    /// `hmac-sha256` ahead of `sha256`.
    fn rank(op: &Op, needle: &str) -> Option<u8> {
        let name = op.name.to_lowercase();
        if name == needle {
            return Some(0);
        }
        if op.aliases.iter().any(|a| a.eq_ignore_ascii_case(needle)) {
            return Some(1);
        }
        if name.starts_with(needle) {
            return Some(2);
        }
        if op
            .aliases
            .iter()
            .any(|a| a.to_lowercase().starts_with(needle))
        {
            return Some(3);
        }
        if name.contains(needle) {
            return Some(4);
        }
        if op.aliases.iter().any(|a| a.to_lowercase().contains(needle)) {
            return Some(5);
        }
        if op.about.to_lowercase().contains(needle) {
            return Some(6);
        }
        None
    }

    pub fn selected_operation(&self) -> Option<&'static Op> {
        self.operations.get(self.operation_index).copied()
    }

    pub fn selected_category(&self) -> Option<Category> {
        self.categories.get(self.category_index).copied().flatten()
    }

    /// Rebuilds the operation list from the chosen category and search text.
    ///
    /// The selected operation is kept when it survives the new filter, so
    /// typing in the search box does not jump the selection around.
    pub fn refresh_operations(&mut self) {
        let previous = self.selected_operation().map(|op| op.name);
        let needle = self.search.trim().to_lowercase();
        let category = self.selected_category();

        let mut matches: Vec<(u8, &'static Op)> = registry::all()
            .iter()
            .filter(|op| category.is_none_or(|c| op.category == c))
            .filter_map(|op| match_score(op, &needle).map(|score| (score, op)))
            .collect();

        // Registry order is category then name, which `sort_by_key` keeps for
        // equal scores because it is stable.
        matches.sort_by_key(|(score, _)| *score);
        self.operations = matches.into_iter().map(|(_, op)| op).collect();

        self.operation_index = previous
            .and_then(|name| self.operations.iter().position(|op| op.name == name))
            .unwrap_or(0);
    }

    /// Runs the selected operation and stores the result for display.
    pub fn recompute(&mut self) {
        self.output_scroll = 0;
        let Some(op) = self.selected_operation() else {
            self.outcome = Outcome::Ready(String::new());
            return;
        };

        let params = self.options.params(op);

        let text = if op.feed == Feed::None {
            String::new()
        } else {
            self.input.text()
        };

        self.outcome = match op.apply(&text, &params, None) {
            Ok(result) => Outcome::Ready(result),
            Err(error) => {
                let mut message = error.to_string();
                for cause in error.chain().skip(1) {
                    message.push_str(&format!("\n  caused by: {cause}"));
                }
                Outcome::Failed(message)
            }
        };
    }

    pub fn select_next_operation(&mut self) {
        if self.operations.is_empty() {
            return;
        }
        self.operation_index = (self.operation_index + 1) % self.operations.len();
        self.load_operation();
    }

    pub fn select_previous_operation(&mut self) {
        if self.operations.is_empty() {
            return;
        }
        self.operation_index =
            (self.operation_index + self.operations.len() - 1) % self.operations.len();
        self.load_operation();
    }

    pub fn select_next_category(&mut self) {
        self.category_index = (self.category_index + 1) % self.categories.len();
        self.operation_index = 0;
        self.refresh_operations();
        self.load_operation();
    }

    pub fn select_previous_category(&mut self) {
        self.category_index =
            (self.category_index + self.categories.len() - 1) % self.categories.len();
        self.operation_index = 0;
        self.refresh_operations();
        self.load_operation();
    }

    /// Swaps the output into the input, so operations can be chained by hand.
    pub fn pipe_output_into_input(&mut self) {
        if self.outcome.is_error() {
            self.status = "there is nothing to pipe: the operation failed".to_string();
            return;
        }
        self.input = TextArea::from_text(self.outcome.text());
        self.input_is_sample = false;
        self.status = "output moved into the input".to_string();
        self.recompute();
    }

    /// Writes the current output next to the working directory.
    pub fn save_output(&mut self) {
        let path = std::path::Path::new("txc-output.txt");
        match std::fs::write(path, self.outcome.text()) {
            Ok(()) => self.status = format!("saved to {}", path.display()),
            Err(error) => self.status = format!("could not save: {error}"),
        }
    }
}

/// Scores an operation against the search, treating an empty search as a
/// match for everything.
fn match_score(op: &Op, needle: &str) -> Option<u8> {
    if needle.is_empty() {
        return Some(0);
    }
    App::rank(op, needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app_showing(name: &str) -> App {
        let mut app = App::new();
        app.search = name.to_string();
        app.refresh_operations();
        app.load_operation();
        assert_eq!(app.selected_operation().unwrap().name, name);
        app
    }

    #[test]
    fn focus_order_skips_panels_the_operation_does_not_show() {
        // A generator reads no input.
        let app = app_showing("uuid");
        assert!(!app.focus_order().contains(&Focus::Input));
        assert!(app.focus_order().contains(&Focus::Options));

        // An operation with no parameters has no options.
        let app = app_showing("upper");
        assert!(app.focus_order().contains(&Focus::Input));
        assert!(!app.focus_order().contains(&Focus::Options));

        // And one with neither shows only the three left hand panels.
        let app = app_showing("reverse");
        assert_eq!(
            app.focus_order(),
            vec![
                Focus::Search,
                Focus::Categories,
                Focus::Operations,
                Focus::Input
            ]
        );
    }

    #[test]
    fn tab_never_lands_on_a_hidden_panel() {
        let mut app = app_showing("uuid");
        for _ in 0..12 {
            app.focus_next();
            assert_ne!(app.focus, Focus::Input, "focused a panel that is not drawn");
        }
        let mut app = app_showing("upper");
        for _ in 0..12 {
            app.focus_previous();
            assert_ne!(
                app.focus,
                Focus::Options,
                "focused a panel that is not drawn"
            );
        }
    }

    #[test]
    fn focus_moves_off_a_panel_that_disappears() {
        let mut app = app_showing("upper");
        app.focus = Focus::Input;
        app.search = "uuid".to_string();
        app.refresh_operations();
        app.load_operation();
        assert_ne!(app.focus, Focus::Input);
    }

    #[test]
    fn starts_on_a_working_operation() {
        let app = App::new();
        assert!(app.selected_operation().is_some());
        assert!(!app.outcome.is_error());
        assert!(!app.operations.is_empty());
    }

    #[test]
    fn each_operation_loads_its_own_sample_text() {
        assert_eq!(app_showing("from-timestamp").input.text(), "1700000000");
        assert_eq!(app_showing("roman-decode").input.text(), "MMXXIV");
        assert_eq!(app_showing("spell").input.text(), "2024");
        assert!(app_showing("json-format").input.text().starts_with('{'));
        assert!(app_showing("sort").input.text().contains('\n'));
    }

    #[test]
    fn every_operation_produces_a_result_from_its_own_sample() {
        // This is the whole point of the samples: selecting an operation shows
        // it working, never an error about the previous operation's text.
        let mut app = App::new();
        for index in 0..registry::all().len() {
            app.search.clear();
            app.category_index = 0;
            app.refresh_operations();
            app.operation_index = index;
            app.input_is_sample = true;
            app.load_operation();
            let op = app.selected_operation().unwrap();
            assert!(
                !app.outcome.is_error(),
                "{} showed an error on its own sample: {}",
                op.name,
                app.outcome.text()
            );
        }
    }

    #[test]
    fn text_the_reader_typed_survives_changing_operation() {
        let mut app = app_showing("upper");
        app.input = TextArea::from_text("keep me");
        app.mark_input_edited();

        app.search = "lower".to_string();
        app.refresh_operations();
        app.load_operation();
        assert_eq!(app.input.text(), "keep me");
        assert_eq!(app.outcome.text(), "keep me");
    }

    #[test]
    fn the_sample_can_be_brought_back() {
        let mut app = app_showing("upper");
        app.input = TextArea::from_text("mine");
        app.mark_input_edited();
        app.reset_input();
        assert!(app.input_is_sample);
        assert_eq!(
            app.input.text(),
            "The quick brown fox jumps over the lazy dog"
        );
    }

    #[test]
    fn searching_narrows_the_list_and_ranks_exact_names_first() {
        let mut app = App::new();
        app.search = "b64d".to_string();
        app.refresh_operations();
        assert_eq!(app.selected_operation().unwrap().name, "base64-decode");

        app.search = "sha256".to_string();
        app.refresh_operations();
        assert_eq!(app.selected_operation().unwrap().name, "sha256");

        app.search = "roman".to_string();
        app.refresh_operations();
        assert_eq!(app.selected_operation().unwrap().name, "roman-encode");
    }

    #[test]
    fn choosing_a_category_filters_the_list() {
        let mut app = App::new();
        app.select_next_category();
        let category = app.selected_category().expect("a real category");
        assert!(app.operations.iter().all(|op| op.category == category));
    }

    #[test]
    fn options_start_pre_filled_and_can_be_changed() {
        let mut app = app_showing("caesar");
        assert_eq!(app.options.fields()[0].value, "3");
        assert_eq!(
            app.outcome.text(),
            "Wkh txlfn eurzq ira mxpsv ryhu wkh odcb grj"
        );

        app.options.clear_selected();
        app.options.insert('1');
        app.recompute();
        assert_eq!(
            app.outcome.text(),
            "Uif rvjdl cspxo gpy kvnqt pwfs uif mbaz eph"
        );
    }

    #[test]
    fn required_options_are_pre_filled_so_nothing_starts_broken() {
        for name in ["replace", "extract", "filter", "hmac-sha256"] {
            let app = app_showing(name);
            assert!(
                !app.outcome.is_error(),
                "{name} started with an error: {}",
                app.outcome.text()
            );
        }
    }

    #[test]
    fn switching_operation_resets_the_options() {
        let mut app = app_showing("sort");
        app.options.toggle();
        app.recompute();
        app.search = "sort".to_string();
        app.refresh_operations();
        app.load_operation();
        assert!(app.options.fields().iter().all(|f| !f.enabled));
    }

    #[test]
    fn generators_ignore_the_input_text() {
        let app = app_showing("uuid");
        assert!(!app.shows_input());
        assert!(!app.outcome.is_error());
        assert_eq!(app.outcome.text().len(), 36);
    }

    #[test]
    fn piping_moves_the_output_into_the_input() {
        let mut app = app_showing("upper");
        app.input = TextArea::from_text("hello");
        app.mark_input_edited();
        app.recompute();
        app.pipe_output_into_input();
        assert_eq!(app.input.text(), "HELLO");
        // The piped text is the reader's, so the next operation keeps it.
        assert!(!app.input_is_sample);
    }
}
