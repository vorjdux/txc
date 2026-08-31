//! Offline text utilities.
//!
//! The crate exposes the same operation registry the `txc` binary is built
//! from, so the operations can also be used as a library.

pub mod about;
pub mod cli;
pub mod input;
pub mod ops;
pub mod params;
pub mod registry;
pub mod tui;

pub use params::Params;
pub use registry::{Category, Feed, Op, OpResult, Param, all, find, in_category};
