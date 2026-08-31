//! State of the interactive interface.

use crate::params::Params;
use crate::registry::{self, Category, Feed, Op};
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

    pub fn next(self) -> Focus {
        let index = Self::ORDER.iter().position(|f| *f == self).unwrap_or(0);
        Self::ORDER[(index + 1) % Self::ORDER.len()]
    }

    pub fn previous(self) -> Focus {
        let index = Self::ORDER.iter().position(|f| *f == self).unwrap_or(0);
        Self::ORDER[(index + Self::ORDER.len() - 1) % Self::ORDER.len()]
    }
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
    pub options: TextArea,
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
            input: TextArea::from_text("The quick brown fox jumps over the lazy dog"),
            options: TextArea::default(),
            outcome: Outcome::Ready(String::new()),
            focus: Focus::Operations,
            output_scroll: 0,
            show_help: false,
            status: String::new(),
            running: true,
        };
        app.refresh_operations();
        app.recompute();
        app
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

        let params = match Params::parse_kv(op, &self.options.text()) {
            Ok(params) => params,
            Err(error) => {
                self.outcome = Outcome::Failed(error.to_string());
                return;
            }
        };

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
        self.recompute();
    }

    pub fn select_previous_operation(&mut self) {
        if self.operations.is_empty() {
            return;
        }
        self.operation_index =
            (self.operation_index + self.operations.len() - 1) % self.operations.len();
        self.recompute();
    }

    pub fn select_next_category(&mut self) {
        self.category_index = (self.category_index + 1) % self.categories.len();
        self.operation_index = 0;
        self.refresh_operations();
        self.recompute();
    }

    pub fn select_previous_category(&mut self) {
        self.category_index =
            (self.category_index + self.categories.len() - 1) % self.categories.len();
        self.operation_index = 0;
        self.refresh_operations();
        self.recompute();
    }

    /// Swaps the output into the input, so operations can be chained by hand.
    pub fn pipe_output_into_input(&mut self) {
        if self.outcome.is_error() {
            self.status = "there is nothing to pipe: the operation failed".to_string();
            return;
        }
        self.input = TextArea::from_text(self.outcome.text());
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

    #[test]
    fn focus_cycles_in_both_directions() {
        assert_eq!(Focus::Search.next(), Focus::Categories);
        assert_eq!(Focus::Options.next(), Focus::Search);
        assert_eq!(Focus::Search.previous(), Focus::Options);
    }

    #[test]
    fn starts_on_a_working_operation() {
        let app = App::new();
        assert!(app.selected_operation().is_some());
        assert!(!app.outcome.is_error());
        assert!(!app.operations.is_empty());
    }

    #[test]
    fn searching_narrows_the_list_and_keeps_the_selection() {
        let mut app = App::new();
        app.search = "base64".to_string();
        app.refresh_operations();
        assert!(app.operations.iter().all(|op| {
            op.name.contains("base64")
                || op.about.to_lowercase().contains("base64")
                || op.aliases.iter().any(|a| a.contains("b64"))
        }));
        assert!(!app.operations.is_empty());

        // Searching by alias finds the operation too.
        app.search = "b64d".to_string();
        app.refresh_operations();
        assert_eq!(app.selected_operation().unwrap().name, "base64-decode");

        // An exact name beats a longer operation that merely contains it.
        app.search = "sha256".to_string();
        app.refresh_operations();
        assert_eq!(app.selected_operation().unwrap().name, "sha256");

        // A description match still shows up, just further down.
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
    fn output_follows_the_selected_operation() {
        let mut app = App::new();
        app.search = "upper".to_string();
        app.refresh_operations();
        app.input = TextArea::from_text("hello");
        app.recompute();
        assert_eq!(app.outcome.text(), "HELLO");
    }

    #[test]
    fn bad_options_are_reported_rather_than_thrown_away() {
        let mut app = App::new();
        app.search = "caesar".to_string();
        app.refresh_operations();
        app.options = TextArea::from_text("nonsense=1");
        app.recompute();
        assert!(app.outcome.is_error());
        assert!(app.outcome.text().contains("no option named"));
    }

    #[test]
    fn generators_ignore_the_input_text() {
        let mut app = App::new();
        app.search = "uuid".to_string();
        app.refresh_operations();
        app.input = TextArea::from_text("ignored");
        app.recompute();
        assert!(!app.outcome.is_error());
        assert_eq!(app.outcome.text().len(), 36);
    }

    #[test]
    fn piping_moves_the_output_into_the_input() {
        let mut app = App::new();
        app.search = "upper".to_string();
        app.refresh_operations();
        app.input = TextArea::from_text("hello");
        app.recompute();
        app.pipe_output_into_input();
        assert_eq!(app.input.text(), "HELLO");
    }

    #[test]
    fn every_operation_runs_on_the_sample_text_without_panicking() {
        let mut app = App::new();
        for index in 0..registry::all().len() {
            app.search.clear();
            app.category_index = 0;
            app.refresh_operations();
            app.operation_index = index;
            // A failure is fine here, a panic is not.
            app.recompute();
        }
    }
}
