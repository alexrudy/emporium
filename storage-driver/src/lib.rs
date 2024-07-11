//! Traits for storage drivers.
//!
//! This module defines the traits that storage drivers must implement to be used
//! with the storage crate.

mod driver;
mod error;

pub use driver::Driver;
pub use driver::DriverUri;
pub use driver::Metadata;
pub use driver::Reader;
pub use driver::Writer;
pub use error::StorageError;
