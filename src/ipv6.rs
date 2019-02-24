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
    u16,
};

use as_slice::{AsMutSlice, AsSlice};
use byteorder::{ByteOrder, NetworkEndian as NE};
use cast::{u16, u32, usize};
use hash32_derive::Hash32;
use owning_slice::Truncate;

pub use crate::ipv4::Protocol as NextHeader;
use crate::{fmt::Quoted, icmpv6, mac, traits::UncheckedIndex, udp};

/* Packet structure */
const V: usize = 0;
mod v {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = 4;
    pub const SIZE: usize = 4;
}

const TC: RangeTo<usize> = ..2;
mod tc {
    pub const MASK: u16 = (1 << SIZE) - 1;
    pub const OFFSET: usize = 4;
    pub const SIZE: usize = 8;
}

const FLH: usize = 1;
const FLL: Range<usize> = 2..4;

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

        if get!((p.header()[V]), v) != 6 {
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
        debug_assert_eq!(get!(&self.header()[V], v), 6);

        6
    }

    /// Reads the 'Traffic Class' field
    pub fn get_traffic_class(&self) -> u8 {
        get!(NE::read_u16(&self.header()[TC]), tc) as u8
    }

    /// Reads the 'Flow Label' field (20 bits)
    pub fn get_flow_label(&self) -> u32 {
        let mask = (1 << 4) - 1;

        (u32(self.header()[FLH]) & mask) << 16 | u32(NE::read_u16(&self.header()[FLL]))
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

    /// Returns the byte representation of this packet
    pub fn as_bytes(&self) -> &[u8] {
        self.as_slice()
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

impl<B> Packet<B>
where
    B: AsMutSlice<Element = u8>,
{
    /* Constructors */
    /// Transforms the given buffer into an IPv4 packet
    ///
    /// Most of the header will be filled with sensible defaults:
    ///
    /// - Version = 6
    /// - Traffic class = 0
    /// - Flow label = 0
    /// - Length = buffer.len() - HEADER_SIZE
    /// - Hop limit = 255
    ///
    /// The fields that are left unpopulated are:
    ///
    /// - Next header
    /// - Source address
    /// - Destination address
    ///
    /// # Panics
    ///
    /// This constructor panics if
    ///
    /// - the given `buffer` is smaller than `HEADER_SIZE`
    /// - the packet would result in a payload length larger than `u16::MAX`.
    pub fn new(buffer: B) -> Self {
        let blen = buffer.as_slice().len();
        assert!(blen >= usize(HEADER_SIZE) || blen > usize(u16::MAX) + usize(HEADER_SIZE));

        let mut p = Packet { buffer };

        p.set_version();
        p.set_traffic_class(0);
        p.set_flow_label(0);
        // NOTE(cast) see `assert` above
        unsafe { p.set_length((blen - usize(HEADER_SIZE)) as u16) }
        // p.set_next_header(..);
        p.set_hop_limit(255);
        // p.set_source(..);
        // p.set_destination(..);

        p
    }

    /// Sets the 'Traffic class' field
    pub fn set_traffic_class(&mut self, tc: u8) {
        let mask = (1 << 4) - 1;

        // low byte
        let tcl = &mut self.header_mut()[1];
        *tcl &= !(mask << 4);
        *tcl |= (tc & mask) << 4;

        // high byte
        let tch = &mut self.header_mut()[0];
        *tch &= !mask;
        *tch |= tc >> 4;
    }

    /// Sets the 'Flow label' field
    pub fn set_flow_label(&mut self, fl: u32) {
        // low half-word
        NE::write_u16(&mut self.header_mut()[2..4], fl as u16);

        // high byte
        let mask = (1 << 4) - 1;
        let flh = &mut self.header_mut()[1];
        *flh &= !mask;
        *flh |= (fl >> 16) as u8;
    }

    /// Sets the 'Next Header' field
    ///
    /// # Panics
    ///
    /// This function panics if `nh` is an extension header (currently not supported)
    pub fn set_next_header(&mut self, nh: NextHeader) {
        assert!(!nh.is_ipv6_extension_header());

        self.header_mut()[NEXT_HEADER] = nh.into();
    }

    /// Sets the 'Hop limit' field
    pub fn set_hop_limit(&mut self, hl: u8) {
        self.header_mut()[HOP_LIMIT] = hl;
    }

    /// Sets the 'Source address' field
    pub fn set_source(&mut self, addr: Addr) {
        self.header_mut()[SOURCE].copy_from_slice(&addr.0)
    }

    /// Sets the 'Destination address' field
    pub fn set_destination(&mut self, addr: Addr) {
        self.header_mut()[DESTINATION].copy_from_slice(&addr.0)
    }

    /// Immutable view into the payload
    pub fn payload_mut(&mut self) -> &mut [u8] {
        // NOTE we reject packets that contain extension headers in `parse`
        unsafe { self.as_mut_slice().rfm(PAYLOAD) }
    }

    /* Private */
    fn header_mut(&mut self) -> &mut [u8; HEADER_SIZE as usize] {
        debug_assert!(self.as_slice().len() >= usize(HEADER_SIZE));

        unsafe { &mut *(self.as_mut_slice().as_mut_ptr() as *mut _) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }

    fn set_version(&mut self) {
        set!(self.header_mut()[V], v, 6);
    }

    // NOTE(unsafe) this does *not* truncate the buffer or check if `len` is greater than the
    // length of the current buffer
    unsafe fn set_length(&mut self, len: u16) {
        NE::write_u16(&mut self.header_mut()[LENGTH], len);
    }
}

impl<B> Packet<B>
where
    B: AsMutSlice<Element = u8> + Truncate<u16>,
{
    /// Fills the payload with a Neighbor Advertisement ICMPv6 message
    pub fn neighbor_advertisement(
        &mut self,
        target_ll_addr: Option<mac::Addr>,
        f: impl FnOnce(&mut icmpv6::Message<&mut [u8], icmpv6::NeighborAdvertisement>),
    ) {
        let src = self.get_source();
        let dest = self.get_destination();

        self.set_next_header(NextHeader::Ipv6Icmp);

        let mut message = icmpv6::Message::neighbor_advertisement(
            self.payload_mut(),
            if target_ll_addr.is_some() { 1 } else { 0 },
        );

        f(&mut message);

        if let Some(target_ll_addr) = target_ll_addr {
            unsafe {
                message.set_target_mac_addr(target_ll_addr);
            }
        }

        message.update_checksum(src, dest);

        let len = message.as_bytes().len() as u16;
        self.truncate(len);
    }

    /// Fills the payload with a UDP packet
    pub fn udp(&mut self, f: impl FnOnce(&mut udp::Packet<&mut [u8]>)) {
        let src = self.get_source();
        let dest = self.get_destination();

        self.set_next_header(NextHeader::Udp);

        let mut packet = udp::Packet::new(self.payload_mut());

        f(&mut packet);

        packet.update_ipv6_checksum(src, dest);

        let len = packet.as_bytes().len() as u16;
        self.truncate(len);
    }

    /// Truncates the *payload* to the specified length
    pub fn truncate(&mut self, len: u16) {
        if self.get_length() > len {
            unsafe { self.set_length(len) }
            self.buffer.truncate(len + u16(HEADER_SIZE));
        }
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
            .field("source", &Quoted(self.get_source()))
            .field("destination", &Quoted(self.get_destination()))
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
    use crate::ipv6;

    use super::HEADER_SIZE;

    #[test]
    fn solicited_node() {
        let unicast = ipv6::Addr([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xec, 0x0b, 0xfb, 0x0f, 0x76, 0xb9, 0xf3, 0x93,
        ]);

        assert_eq!(
            unicast.into_solicited_node(),
            ipv6::Addr([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xb9, 0xf3, 0x93])
        );
    }

    #[test]
    fn new() {
        const SZ: usize = 128;

        let mut chunk = [0; SZ];

        let unspecified = ipv6::Addr::UNSPECIFIED;
        let next_header = ipv6::NextHeader::Udp;

        let mut ip = ipv6::Packet::new(&mut chunk[..]);
        ip.set_next_header(next_header);
        ip.set_destination(unspecified);
        ip.set_source(unspecified);

        assert_eq!(ip.get_version(), 6);
        assert_eq!(ip.get_traffic_class(), 0);
        assert_eq!(ip.get_flow_label(), 0);
        assert_eq!(
            usize::from(ip.get_length()),
            (SZ - usize::from(HEADER_SIZE))
        );
        assert_eq!(ip.get_next_header(), next_header);
        assert_eq!(ip.get_hop_limit(), 255);
        assert_eq!(ip.get_source(), unspecified);
        assert_eq!(ip.get_destination(), unspecified);
    }
}
