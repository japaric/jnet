//! IPv6: Internet Protocol v6
//!
//! # References
//!
//! - [RFC 4291 IP Version 6 Addressing Architecture][rfc]
//!
//! [rfc]: https://tools.ietf.org/html/rfc4291

use core::fmt;

use byteorder::{ByteOrder, NetworkEndian as NE};
use hash32_derive::Hash32;

pub use crate::ipv4::Protocol as NextHeader;

/// IPv6 address
#[derive(Clone, Copy, Debug, Eq, Hash32, PartialEq)]
pub struct Addr(pub [u8; 16]);

impl Addr {
    // Section 2.5.2
    /// Unspecified address
    pub const UNSPECIFIED: Self = Addr([0; 16]);

    // Section 2.5.3
    /// Loopback address
    pub const LOOPBACK: Self = Addr([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    /// Loopback address
    pub const LINK_LOCAL_ALL_NODES: Self =
        Addr([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    // Section 2.5.6
    /// Is this a link local address?
    pub fn is_link_local(&self) -> bool {
        self.0[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0]
    }

    /// Is this the loopback address?
    pub fn is_loopback(&self) -> bool {
        *self == Self::LOOPBACK
    }

    // Section 2.7
    /// Is this a multicast address?
    pub fn is_multicast(&self) -> bool {
        self.0[0] == 0xff
    }

    /// Is this a solicited node multicast address?
    pub fn is_solicited_node(&self) -> bool {
        self.0[..13] == [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]
    }

    /// Is this the unspecified address?
    pub fn is_unspecified(&self) -> bool {
        *self == Self::UNSPECIFIED
    }

    /// Turns this unicast or anycast address into a solicited node multicast address
    ///
    /// # Panics
    ///
    /// This function panics if `self` is a multicast address
    pub fn into_solicited_node(mut self) -> Self {
        assert!(!self.is_multicast());

        self.0[..13].copy_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff]);
        self
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut is_first = true;

        for chunk in self.0.chunks(2) {
            if is_first {
                is_first = false;
            } else {
                f.write_str(":")?;
            }

            write!(f, "{:x}", NE::read_u16(chunk))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::Addr;

    #[test]
    fn solicited_node() {
        let unicast = Addr([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xec, 0x0b, 0xfb, 0x0f, 0x76, 0xb9, 0xf3, 0x93,
        ]);

        assert_eq!(
            unicast.into_solicited_node(),
            Addr([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xb9, 0xf3, 0x93])
        );
    }
}
