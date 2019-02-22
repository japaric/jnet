//! `uJSON`: JSON (de)serialization for memory constrained devices
//!
//! # References
//!
//! - [RFC8259 The JavaScript Object Notation (JSON) Data Interchange Format][rfc8259]
//!
//! [rfc8259]: https://tools.ietf.org/html/rfc8259

#![deny(missing_docs)]
#![deny(rust_2018_compatibility)]
#![deny(rust_2018_idioms)]
#![deny(warnings)]
#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

pub use ujson_macros::{uDeserialize, uSerialize};

#[macro_use]
mod macros;

#[doc(hidden)]
pub mod de;
#[doc(hidden)]
pub mod ser;

mod traits;

#[doc(inline)]
pub use de::{from_bytes, Deserialize};
#[doc(inline)]
pub use ser::{write, Serialize};
