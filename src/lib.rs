//! Offline text utilities.
//!
//! The crate exposes the same operation registry the `txc` binary is built
//! from, so the operations can also be used as a library. Nothing here opens
//! a socket: every operation runs on the text it is handed.
//!
//! # Running an operation
//!
//! Look the operation up by name or alias with [`find`], then [`apply`] it.
//! [`Params::for_op`] starts from the operation's declared defaults, which is
//! what you want unless you are overriding something.
//!
//! ```
//! use txc::{Params, find};
//!
//! let op = find("slugify").expect("slugify is registered");
//! let text = op.apply("Hello, World!", &Params::for_op(op), None)?;
//! assert_eq!(text, "hello-world");
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! # Passing parameters
//!
//! Set values by the parameter's long name. What each operation accepts is on
//! its [`Op::params`] field.
//!
//! ```
//! use txc::{Params, find};
//!
//! let op = find("caesar").expect("caesar is registered");
//! let mut params = Params::for_op(op);
//! params.set("shift", "3");
//!
//! assert_eq!(op.apply("abc", &params, None)?, "def");
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! # Chaining
//!
//! Operations take text and return text, so they compose directly.
//!
//! ```
//! use txc::{Params, find};
//!
//! let mut text = "userFirstName".to_string();
//! for name in ["snake", "upper"] {
//!     let op = find(name).expect("registered");
//!     text = op.apply(&text, &Params::for_op(op), None)?;
//! }
//! assert_eq!(text, "USER_FIRST_NAME");
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! # Browsing the catalogue
//!
//! [`all`] returns every operation, and [`in_category`] narrows it to one
//! [`Category`].
//!
//! ```
//! use txc::{Category, all, in_category};
//!
//! assert!(all().len() > 100);
//!
//! for op in in_category(Category::Hash) {
//!     assert_eq!(op.category, Category::Hash);
//! }
//! ```
//!
//! # Errors
//!
//! [`apply`] returns [`OpResult`], an [`anyhow::Result<String>`]. Input an
//! operation cannot make sense of comes back as an error rather than a panic.
//!
//! ```
//! use txc::{Params, find};
//!
//! let op = find("roman-encode").expect("roman-encode is registered");
//! assert!(op.apply("not a number", &Params::for_op(op), None).is_err());
//! ```
//!
//! [`apply`]: Op::apply
//! [`anyhow::Result<String>`]: https://docs.rs/anyhow/latest/anyhow/type.Result.html

#![warn(missing_docs)]

pub mod about;
pub mod cli;
pub mod input;
pub mod ops;
pub mod params;
pub mod registry;
pub mod tui;

pub use params::Params;
pub use registry::{Category, Feed, Op, OpFn, OpResult, Param, ParamKind, all, find, in_category};
