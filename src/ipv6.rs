//! IPv6: Internet Protocol v6
//!
//! # References
//!
//! - [RFC 4291 IP Version 6 Addressing Architecture][rfc]
//!
//! [rfc]: https://tools.ietf.org/html/rfc4291

use core::{
    fmt,
    ops::{Range, RangeFrom, RangeTo},
};

use as_slice::AsSlice;
use byteorder::{ByteOrder, NetworkEndian as NE};
use cast::usize;
use hash32_derive::Hash32;

pub use crate::ipv4::Protocol as NextHeader;
use crate::traits::UncheckedIndex;

/* Packet structure */
const V_TC_FL: RangeTo<usize> = ..4;
mod fl {
    pub const MASK: u32 = (1 << SIZE) - 1;
    pub const OFFSET: usize = 0;
    pub const SIZE: usize = 20;
}

mod tc {
    pub const MASK: u32 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::fl::OFFSET + super::fl::SIZE;
    pub const SIZE: usize = 8;
}

mod v {
    pub const MASK: u32 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::tc::OFFSET + super::tc::SIZE;
    pub const SIZE: usize = 4;
}

const LENGTH: Range<usize> = 4..6;
const NEXT_HEADER: usize = 6;
const HOP_LIMIT: usize = 7;
const SOURCE: Range<usize> = 8..24;
const DESTINATION: Range<usize> = 24..40;
const PAYLOAD: RangeFrom<usize> = 40..;

/// Fixed header size, in bytes
pub const HEADER_SIZE: u8 = DESTINATION.end as u8;

/// IPv6 packet
pub struct Packet<BUFFER>
where
    BUFFER: AsSlice<Element = u8>,
{
    buffer: BUFFER,
}

impl<B> Packet<B>
where
    B: AsSlice<Element = u8>,
{
    /* Constructors */
    /// Parses bytes into an IPv6 packet
    pub fn parse(bytes: B) -> Result<Self, ()> {
        if bytes.as_slice().len() < usize(HEADER_SIZE) {
            // smaller than header
            return Err(());
        }

        let p = Packet { buffer: bytes };

        if get!(NE::read_u32(&p.header()[V_TC_FL]), v) != 6 {
            // version is not `6`
            return Err(());
        }

        if p.get_next_header().is_ipv6_extension_header() {
            // currently unsupported
            return Err(());
        }

        Ok(p)
    }

    /* Accessors */
    /// Reads the 'Version' field
    ///
    /// This always returns `6`
    pub fn get_version(&self) -> u8 {
        debug_assert_eq!(get!(NE::read_u32(&self.header()[V_TC_FL]), v), 6);

        6
    }

    /// Reads the 'Traffic Class' field
    pub fn get_traffic_class(&self) -> u8 {
        get!(NE::read_u32(&self.header()[V_TC_FL]), tc) as u8
    }

    /// Reads the 'Flow Label' field (20 bits)
    pub fn get_flow_label(&self) -> u32 {
        get!(NE::read_u32(&self.header()[V_TC_FL]), fl)
    }

    /// Reads the 'Payload length' field
    pub fn get_length(&self) -> u16 {
        NE::read_u16(&self.header()[LENGTH])
    }

    /// Reads the 'Next Header' field
    pub fn get_next_header(&self) -> NextHeader {
        self.header()[NEXT_HEADER].into()
    }

    /// Reads the 'Hop Limit' field
    pub fn get_hop_limit(&self) -> u8 {
        self.header()[HOP_LIMIT]
    }

    /// Reads the 'Source Address' field
    pub fn get_source(&self) -> Addr {
        unsafe { Addr(*(self.as_slice().as_ptr().add(SOURCE.start) as *const _)) }
    }

    /// Reads the 'Destination Address' field
    pub fn get_destination(&self) -> Addr {
        unsafe { Addr(*(self.as_slice().as_ptr().add(DESTINATION.start) as *const _)) }
    }

    /// Immutable view into the payload
    pub fn payload(&self) -> &[u8] {
        // NOTE we reject packets that contain extension headers in `parse`
        unsafe { self.as_slice().rf(PAYLOAD) }
    }

    /* Private */
    fn header(&self) -> &[u8; HEADER_SIZE as usize] {
        debug_assert!(self.as_slice().len() >= usize(HEADER_SIZE));

        unsafe { &*(self.as_slice().as_ptr() as *const _) }
    }

    fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }
}

impl<B> fmt::Debug for Packet<B>
where
    B: AsSlice<Element = u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ipv6::Packet")
            .field("version", &self.get_version())
            .field("traffic_class", &self.get_traffic_class())
            .field("flow_label", &self.get_flow_label())
            .field("length", &self.get_length())
            .field("next_header", &self.get_next_header())
            .field("hop_limit", &self.get_hop_limit())
            .field("source", &self.get_source())
            .field("destination", &self.get_destination())
            // .field("payload", &self.payload())
            .finish()
    }
}

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

    /// All link-local nodes multicast address
    pub const ALL_NODES: Self = Addr([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    /// All link-local routers multicast address
    pub const ALL_ROUTERS: Self = Addr([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

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
