//! IPv4: Internet Protocol v4
//!
//! # References
//!
//! - [RFC 791: Internet protocol][rfc]
//!
//! [rfc]: https://tools.ietf.org/html/rfc791

use core::marker::PhantomData;
use core::ops::Range;
use core::{fmt, u16};

use as_slice::{AsMutSlice, AsSlice};
use byteorder::{ByteOrder, NetworkEndian as NE};
use cast::{u16, u32, usize};
use hash32_derive::Hash32;

use crate::{
    fmt::Hex,
    icmp,
    traits::{Resize, UncheckedIndex, UxxExt},
    udp, Invalid, Valid,
};

/* Packet structure */
const VERSION_IHL: usize = 0;
mod ihl {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = 0;
    pub const SIZE: usize = 4;
}
mod version {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::ihl::OFFSET + super::ihl::SIZE;
    pub const SIZE: usize = 4;
}

const DSCP_ECN: usize = 1;
mod ecn {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = 0;
    pub const SIZE: usize = 2;
}
mod dscp {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::ecn::OFFSET + super::ecn::SIZE;
    pub const SIZE: usize = 6;
}

const TOTAL_LENGTH: Range<usize> = 2..4;
const IDENTIFICATION: Range<usize> = 4..6;

const FLAGS: usize = 6;
mod mf {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = 5;
    pub const SIZE: usize = 1;
}
mod df {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::mf::OFFSET + super::mf::SIZE;
    pub const SIZE: usize = 1;
}
mod reserved {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::df::OFFSET + super::df::SIZE;
    pub const SIZE: usize = 1;
}

const FRAGMENT_OFFSET: Range<usize> = 6..8;
mod fragment_offset {
    pub const MASK: u16 = (1 << SIZE) - 1;
    pub const OFFSET: usize = 0;
    pub const SIZE: usize = 13;
}

const TTL: usize = 8;
const PROTOCOL: usize = 9;
const CHECKSUM: Range<usize> = 10..12;
const SOURCE: Range<usize> = 12..16;
const DESTINATION: Range<usize> = 16..20;

/// Minimum size of the IPv4 header
pub const MIN_HEADER_SIZE: u16 = DESTINATION.end as u16;

/// IPv4 packet
pub struct Packet<BUFFER, CHECKSUM>
where
    BUFFER: AsSlice<Element = u8>,
{
    buffer: BUFFER,
    _checksum: PhantomData<CHECKSUM>,
}

impl<B> Packet<B, Valid>
where
    B: AsSlice<Element = u8> + Resize,
{
    /* Constructors */
    /// Parses bytes into an IPv4 packet
    pub fn parse(bytes: B) -> Result<Self, B> {
        if bytes.as_slice().len() < usize(MIN_HEADER_SIZE) {
            // input doesn't contain a complete header
            return Err(bytes);
        }

        let mut packet = Packet {
            buffer: bytes,
            _checksum: PhantomData,
        };

        let header_len = u16(packet.header_len());
        let total_len = packet.get_total_length();

        if header_len < MIN_HEADER_SIZE {
            // IHL < 5
            Err(packet.buffer)
        } else if total_len < header_len {
            Err(packet.buffer)
        } else if packet.get_version() != 4 {
            Err(packet.buffer)
        } else {
            if packet.verify_header_checksum() {
                if total_len < u16(packet.as_slice().len()).unwrap_or(u16::MAX) {
                    packet.buffer.truncate(total_len);
                    Ok(packet)
                } else {
                    Ok(packet)
                }
            } else {
                Err(packet.buffer)
            }
        }
    }
}

impl<B, C> Packet<B, C>
where
    B: AsSlice<Element = u8>,
{
    /* Getters */
    /// Returns the version field of the header
    pub fn get_version(&self) -> u8 {
        unsafe { get!(*self.as_slice().gu(VERSION_IHL), version) }
    }

    /// Returns the IHL (Internet Header Length) field of the header
    pub fn get_ihl(&self) -> u8 {
        unsafe { get!(self.as_slice().gu(VERSION_IHL), ihl) }
    }

    /// Returns the DSCP (Differentiated Services Code Point) field of the header
    pub fn get_dscp(&self) -> u8 {
        unsafe { get!(self.as_slice().gu(DSCP_ECN), dscp) }
    }

    /// Returns the ECN (Explicit Congestion Notification) field of the header
    pub fn get_ecn(&self) -> u8 {
        unsafe { get!(self.as_slice().gu(DSCP_ECN), ecn) }
    }

    /// Returns the total length field of the header
    pub fn get_total_length(&self) -> u16 {
        unsafe { NE::read_u16(self.as_slice().r(TOTAL_LENGTH)) }
    }

    /// Returns the length (header + data) of this packet
    ///
    /// This returns the same value as the `get_total_length` method
    pub fn len(&self) -> u16 {
        self.get_total_length()
    }

    /// Returns the identification field of the header
    pub fn get_identification(&self) -> u16 {
        unsafe { NE::read_u16(&self.as_slice().r(IDENTIFICATION)) }
    }

    /// Returns the DF (Don't Fragment) field of the header
    pub fn get_df(&self) -> bool {
        unsafe { get!(self.as_slice().gu(FLAGS), df) == 1 }
    }

    /// Returns the MF (More Fragments) field of the header
    pub fn get_mf(&self) -> bool {
        unsafe { get!(self.as_slice().gu(FLAGS), mf) == 1 }
    }

    /// Returns the Fragment Offset field of the header
    pub fn get_fragment_offset(&self) -> u16 {
        unsafe {
            get!(
                NE::read_u16(&self.as_slice().r(FRAGMENT_OFFSET)),
                fragment_offset
            )
        }
    }

    /// Returns the TTL (Time To Live) field of the header
    pub fn get_ttl(&self) -> u8 {
        unsafe { self.as_slice().gu(TTL).clone() }
    }

    /// Returns the protocol field of the header
    pub fn get_protocol(&self) -> Protocol {
        unsafe { self.as_slice().gu(PROTOCOL).clone().into() }
    }

    /// Returns the Source (IP address) field of the header
    pub fn get_source(&self) -> Addr {
        unsafe { Addr(*(self.as_slice().as_ptr().add(SOURCE.start) as *const _)) }
    }

    /// Returns the Destination (IP address) field of the header
    pub fn get_destination(&self) -> Addr {
        unsafe { Addr(*(self.as_slice().as_ptr().add(DESTINATION.start) as *const _)) }
    }

    /* Miscellaneous */
    /// View into the payload
    pub fn payload(&self) -> &[u8] {
        let start = usize(self.header_len());
        unsafe { &self.as_slice().rf(start..) }
    }

    /* Private */
    fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    fn get_header_checksum(&self) -> u16 {
        unsafe { NE::read_u16(&self.as_slice().r(CHECKSUM)) }
    }

    fn header_len(&self) -> u8 {
        self.get_ihl() * 4
    }

    fn payload_len(&self) -> u16 {
        self.get_total_length() - u16(self.header_len())
    }

    fn header(&self) -> &[u8] {
        unsafe { self.as_slice().rt(..usize(self.header_len())) }
    }

    fn invalidate_header_checksum(self) -> Packet<B, Invalid> {
        Packet {
            buffer: self.buffer,
            _checksum: PhantomData,
        }
    }

    fn verify_header_checksum(&self) -> bool {
        verify_checksum(self.header())
    }
}

impl<B, C> Packet<B, C>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
{
    /* Miscellaneous */
    /// View into the payload
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let start = usize(self.header_len());
        unsafe { self.as_mut_slice().rfm(start..) }
    }

    /* Private */
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }
}

impl<B, C> Packet<B, C>
where
    B: AsSlice<Element = u8> + Resize,
{
    /* Miscellaneous */
    /// Returns the payload of this frame
    pub fn into_payload(self) -> B {
        let offset = u16(self.header_len());
        let mut buffer = self.buffer;
        buffer.slice_from(offset);
        buffer
    }
}

impl<B> Packet<B, Invalid>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8> + Resize,
{
    /* Constructors */
    /// Transforms the given buffer into an IPv4 packet
    ///
    /// Most of the header will be filled with sensible defaults:
    ///
    /// - Version = 4
    /// - IHL = 5
    /// - DSCP = 0
    /// - ECN = 0
    /// - Total Length = `cmp::min(buffer.len(), u16::MAX)`
    /// - Identification = 0
    /// - DF = true
    /// - MF = false
    /// - Fragment Offset = 0
    /// - TTL = 64
    ///
    /// The fields that are left unpopulated are:
    ///
    /// - Protocol
    /// - Checksum
    /// - Source
    /// - Destination
    ///
    /// # Panics
    ///
    /// This constructor panics if the given `buffer` is smaller than `MIN_HEADER_SIZE`
    pub fn new(buffer: B) -> Self {
        let len = buffer.as_slice().len();
        assert!(len >= usize(MIN_HEADER_SIZE));

        let mut packet: Self = Packet {
            buffer,
            _checksum: PhantomData,
        };

        let total_len = u16(len).unwrap_or(u16::MAX);
        packet.set_version(4);
        unsafe { packet.set_ihl(5) }

        packet.set_dscp(0);
        packet.set_ecn(0);

        unsafe { packet.set_total_length(total_len) }
        packet.buffer.truncate(total_len);

        packet.set_identification(0);

        packet.clear_reserved_flag();
        packet.set_df(true);
        packet.set_mf(false);
        packet.set_fragment_offset(0);

        packet.set_ttl(64); // cf. RFC 1700

        // protocol: unpopulated

        // source: unpopulated

        // destination: unpopulated

        packet
    }

    /// Fills the payload with an Echo Request ICMP packet
    pub fn echo_request<F>(&mut self, f: F)
    where
        F: FnOnce(&mut icmp::Packet<&mut [u8], icmp::EchoRequest, Invalid>),
    {
        self.set_protocol(Protocol::Icmp);
        let len = {
            let mut icmp = icmp::Packet::new(self.payload_mut());
            f(&mut icmp);
            icmp.update_checksum().len()
        };
        self.truncate(len);
    }

    /// Fills the payload with an UDP packet
    pub fn udp<F>(&mut self, f: F)
    where
        F: FnOnce(&mut udp::Packet<&mut [u8]>),
    {
        self.set_protocol(Protocol::Udp);
        let len = {
            let mut udp = udp::Packet::new(self.payload_mut());
            f(&mut udp);
            udp.len()
        };
        self.truncate(len);
    }

    /// Truncates the *payload* to the specified length
    pub fn truncate(&mut self, len: u16) {
        if self.payload_len() > len {
            let total_len = u16(self.header_len()) + len;
            unsafe { self.set_total_length(total_len) }
            self.buffer.truncate(total_len);
        }
    }
}

impl<B> Packet<B, Valid>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8> + Resize,
{
    /// Truncates the *payload* to the specified length
    pub fn truncate(self, len: u16) -> Packet<B, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.truncate(len);
        packet
    }
}

impl<B> Packet<B, Invalid>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
{
    /* Setters */
    /// Sets the version field of the header
    pub fn set_version(&mut self, version: u8) {
        unsafe {
            set_!(self.as_mut_slice().gum(VERSION_IHL), version, version);
        }
    }

    // NOTE(unsafe) this doesn't check that the header still fits in the buffer
    unsafe fn set_ihl(&mut self, ihl: u8) {
        set!(self.as_mut_slice()[VERSION_IHL], ihl, ihl);
    }

    /// Sets the DSCP (Differentiated Services Code Point) field of the header
    pub fn set_dscp(&mut self, dscp: u8) {
        set!(self.as_mut_slice()[DSCP_ECN], dscp, dscp);
    }

    /// Sets the ECN (Explicit Congestion Notification) field of the header
    pub fn set_ecn(&mut self, ecn: u8) {
        set!(self.as_mut_slice()[DSCP_ECN], ecn, ecn);
    }

    // NOTE(unsafe) this doesn't check that `len` is greater than the header length or that it
    // doesn't exceed the buffer length
    unsafe fn set_total_length(&mut self, len: u16) {
        NE::write_u16(&mut self.as_mut_slice()[TOTAL_LENGTH], len)
    }

    /// Sets the identification field of the header
    pub fn set_identification(&mut self, id: u16) {
        NE::write_u16(&mut self.as_mut_slice()[IDENTIFICATION], id)
    }

    fn clear_reserved_flag(&mut self) {
        set!(self.as_mut_slice()[FLAGS], reserved, 0);
    }

    /// Sets the DF (Don't Fragment) field of the header
    pub fn set_df(&mut self, df: bool) {
        set!(self.as_mut_slice()[FLAGS], df, if df { 1 } else { 0 });
    }

    /// Sets the MF (More Fragments) field of the header
    pub fn set_mf(&mut self, mf: bool) {
        set!(self.as_mut_slice()[FLAGS], mf, if mf { 1 } else { 0 });
    }

    /// Sets the Fragment Offset field of the header
    pub fn set_fragment_offset(&mut self, fo: u16) {
        let offset = self::fragment_offset::OFFSET;
        let mask = self::fragment_offset::MASK;
        let start = FRAGMENT_OFFSET.start;

        // low byte
        self.as_mut_slice()[start + 1] = fo.low();

        // high byte
        let byte = &mut self.as_mut_slice()[start];
        *byte &= !(mask << offset).high();
        *byte |= (fo << offset).high();
    }

    /// Sets the TTL (Time To Live) field of the header
    pub fn set_ttl(&mut self, ttl: u8) {
        self.as_mut_slice()[TTL] = ttl;
    }

    /// Sets the Protocol field of the header
    pub fn set_protocol(&mut self, proto: Protocol) {
        self.as_mut_slice()[PROTOCOL] = proto.into();
    }

    /// Sets the Source (IP address) field of the header
    pub fn set_source(&mut self, addr: Addr) {
        self.as_mut_slice()[SOURCE].copy_from_slice(&addr.0)
    }

    /// Sets the Destination (IP address) field of the header
    pub fn set_destination(&mut self, addr: Addr) {
        self.as_mut_slice()[DESTINATION].copy_from_slice(&addr.0)
    }

    /* Miscellaneous */
    /// Updates the Checksum field of the header
    pub fn update_checksum(mut self) -> Packet<B, Valid> {
        let cksum = compute_checksum(&self.as_slice()[..usize(self.header_len())], CHECKSUM.start);
        NE::write_u16(&mut self.as_mut_slice()[CHECKSUM], cksum);

        Packet {
            buffer: self.buffer,
            _checksum: PhantomData,
        }
    }
}

impl<B> Packet<B, Valid>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
{
    /* Setters */
    /// Sets the version field of the header
    pub fn set_version(self, version: u8) -> Packet<B, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.set_version(version);
        packet
    }

    /// Sets the DSCP (Differentiated Services Code Point) field of the header
    pub fn set_dscp(self, dscp: u8) -> Packet<B, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.set_dscp(dscp);
        packet
    }

    /// Sets the ECN (Explicit Congestion Notification) field of the header
    pub fn set_ecn(self, ecn: u8) -> Packet<B, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.set_ecn(ecn);
        packet
    }

    /// Sets the identification field of the header
    pub fn set_identification(self, id: u16) -> Packet<B, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.set_identification(id);
        packet
    }

    /// Sets the DF (Don't Fragment) field of the header
    pub fn set_df(self, df: bool) -> Packet<B, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.set_df(df);
        packet
    }

    /// Sets the MF (More Fragments) field of the header
    pub fn set_mf(self, mf: bool) -> Packet<B, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.set_mf(mf);
        packet
    }

    /// Sets the Fragment Offset field of the header
    pub fn set_fragment_offset(self, fo: u16) -> Packet<B, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.set_fragment_offset(fo);
        packet
    }

    /// Sets the TTL (Time To Live) field of the header
    pub fn set_ttl(self, ttl: u8) -> Packet<B, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.set_ttl(ttl);
        packet
    }

    /// Sets the Protocol field of the header
    pub fn set_protocol(self, proto: Protocol) -> Packet<B, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.set_protocol(proto);
        packet
    }

    /// Sets the Source (IP address) field of the header
    pub fn set_source(self, addr: Addr) -> Packet<B, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.set_source(addr);
        packet
    }

    /// Sets the Destination (IP address) field of the header
    pub fn set_destination(self, addr: Addr) -> Packet<B, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.set_destination(addr);
        packet
    }
}

/// NOTE excludes the payload
impl<B, C> fmt::Debug for Packet<B, C>
where
    B: AsSlice<Element = u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ipv4::Packet")
            .field("version", &self.get_version())
            .field("ihl", &self.get_ihl())
            .field("dscp", &self.get_dscp())
            .field("ecn", &self.get_ecn())
            .field("total_length", &self.get_total_length())
            .field("identification", &self.get_identification())
            .field("df", &self.get_df())
            .field("mf", &self.get_mf())
            .field("fragment_offset", &self.get_fragment_offset())
            .field("ttl", &self.get_ttl())
            .field("protocol", &self.get_protocol())
            .field("checksum", &Hex(self.get_header_checksum()))
            .field("source", &self.get_source())
            .field("destination", &self.get_destination())
            // .field("payload", &self.payload())
            .finish()
    }
}

/// IPv4 address
#[derive(Clone, Copy, Eq, Hash32, PartialEq)]
pub struct Addr(pub [u8; 4]);

impl Addr {
    /// Loopback address
    pub const LOOPBACK: Self = Addr([127, 0, 0, 1]);

    /// Unspecified address
    pub const UNSPECIFIED: Self = Addr([0; 4]);
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("ipv4::Addr").field(&self.0).finish()
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use core::fmt::Write;

        let mut is_first = true;
        for byte in &self.0 {
            if is_first {
                is_first = false;
            } else {
                f.write_char('.')?;
            }

            write!(f, "{}", byte)?;
        }

        Ok(())
    }
}

full_range!(
    u8,
    /// IP protocol
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum Protocol {
        /// UDP
        Udp = 0x11,
        /// ICMP
        Icmp = 0x01,
    }
);

/// Computes the IPv4 checksum of the header
pub(crate) fn compute_checksum(header: &[u8], cksum_pos: usize) -> u16 {
    let mut sum = 0u32;
    let skip = cksum_pos / 2;
    for (i, chunk) in header.chunks(2).enumerate() {
        if i == skip {
            // skip checksum field
            continue;
        }
        sum = sum.wrapping_add(u32(NE::read_u16(chunk)));
    }

    loop {
        let carry = sum.high();
        if carry == 0 {
            break;
        }
        sum = u32(sum.low()) + u32(carry);
    }

    !sum.low()
}

/// Verifies the IPv4 checksum of the header
pub(crate) fn verify_checksum(header: &[u8]) -> bool {
    debug_assert!(header.len() % 2 == 0);

    let mut sum = 0u32;
    for chunk in header.chunks_exact(2) {
        sum = sum.wrapping_add(u32(NE::read_u16(chunk)));
    }

    sum.low() + sum.high() == 0xffff
}

#[cfg(test)]
mod tests {
    use crate::{ipv4, Buffer};

    #[test]
    fn checksum() {
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];

        assert_eq!(
            super::compute_checksum(&header, super::CHECKSUM.start),
            0xb861
        )
    }

    #[test]
    fn new() {
        const SZ: u16 = 128;

        let mut chunk = [0; SZ as usize];
        let buf = Buffer::new(&mut chunk);

        let ip = ipv4::Packet::new(buf);
        assert_eq!(ip.len(), SZ);
        assert_eq!(ip.get_total_length(), SZ);
    }

    #[test]
    fn verify() {
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];

        assert!(super::verify_checksum(&header))
    }
}
