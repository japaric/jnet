//! MAC: Medium Access Control

use core::fmt;

use hash32_derive::Hash32;

use crate::ipv6;

/// MAC address
#[derive(Clone, Copy, Eq, Hash32, PartialEq)]
pub struct Addr(pub [u8; 6]);

impl Addr {
    /// Broadcast address
    pub const BROADCAST: Self = Addr([0xff; 6]);

    /// Is this a unicast address?
    pub fn is_unicast(&self) -> bool {
        !self.is_broadcast() && !self.is_multicast()
    }

    /// Is this the broadcast address?
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    /// Is this a multicast address?
    ///
    /// NOTE `Addr::BROADCAST.is_multicast()` returns `false`
    pub fn is_multicast(&self) -> bool {
        !self.is_broadcast() && self.0[0] & 1 == 1
    }

    /// Is this an IPv4 multicast address?
    pub fn is_ipv4_multicast(&self) -> bool {
        self.0[0] == 0x01 && self.0[1] == 0x00 && self.0[2] == 0x5e && self.0[3] >> 7 == 0
    }

    /// Is this an IPv6 multicast address?
    pub fn is_ipv6_multicast(&self) -> bool {
        self.0[0] == 0x33 && self.0[1] == 0x33
    }

    /// Converts this MAC address into a link-local IPv6 address using the EUI-64 format (see
    /// RFC2464)
    pub fn into_link_local_address(self) -> ipv6::Addr {
        let mut bytes = [0; 16];

        bytes[0] = 0xfe;
        bytes[1] = 0x80;

        bytes[8..].copy_from_slice(&self.eui_64());

        ipv6::Addr(bytes)
    }

    fn eui_64(self) -> [u8; 8] {
        let mut bytes = [0; 8];

        bytes[..3].copy_from_slice(&self.0[..3]);
        // toggle the Universal/Local (U/L) bit
        bytes[0] ^= 1 << 1;

        bytes[3] = 0xff;
        bytes[4] = 0xfe;

        bytes[5..].copy_from_slice(&self.0[3..]);

        bytes
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Hex<'a>(&'a [u8; 6]);

        impl<'a> fmt::Debug for Hex<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

#[cfg(test)]
mod tests {
    use super::Addr;

    #[test]
    fn eui_64() {
        assert_eq!(
            Addr([0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE]).eui_64(),
            [0x36, 0x56, 0x78, 0xFF, 0xFE, 0x9A, 0xBC, 0xDE]
        );
    }
}
