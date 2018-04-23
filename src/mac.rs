//! MAC: Medium Access Control

use core::fmt;

/// MAC address
#[derive(Clone, Copy, Eq, Hash32, PartialEq)]
pub struct Addr(pub [u8; 6]);

impl Addr {
    /// Broadcast address
    pub const BROADCAST: Self = Addr([0xff; 6]);

    /// Checks if this is the broadcast address
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Checks if this is a multicast address
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 1 == 1
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct Hex<'a>(&'a [u8; 6]);

        impl<'a> fmt::Debug for Hex<'a> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                use core::fmt::Write;

                let mut is_first = true;

                f.write_char('[')?;
                for byte in self.0.iter() {
                    if is_first {
                        is_first = false;
                    } else {
                        f.write_str(", ")?;
                    }

                    write!(f, "0x{:02x}", byte)?;
                }
                f.write_char(']')?;

                Ok(())
            }
        }

        f.debug_tuple("mac::Addr").field(&Hex(&self.0)).finish()
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut is_first = true;
        for byte in &self.0 {
            if is_first {
                is_first = false;
            } else {
                f.write_str(":")?;
            }

            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}
