//! Formatting helpers

use core::fmt;

pub struct Hex(pub u16);

impl fmt::Debug for Hex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:04x}", self.0)
    }
}
