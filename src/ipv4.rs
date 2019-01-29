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
use owning_slice::{IntoSliceFrom, Truncate};

use crate::{
    fmt::Hex,
    icmp,
    traits::{UncheckedIndex, UxxExt},
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
    B: AsSlice<Element = u8> + Truncate<u16>,
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
    B: AsSlice<Element = u8> + IntoSliceFrom<u16>,
{
    /* Miscellaneous */
    /// Returns the payload of this frame
    pub fn into_payload(self) -> B::OutputF {
        let offset = u16(self.header_len());
        self.buffer.into_slice_from(offset)
    }
}

impl<B> Packet<B, Invalid>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8> + Truncate<u16>,
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
        F: FnOnce(&mut icmp::Message<&mut [u8], icmp::EchoRequest, Invalid>),
    {
        self.set_protocol(Protocol::Icmp);
        let len = {
            let mut icmp = icmp::Message::new(self.payload_mut());
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
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8> + Truncate<u16>,
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ipv4::Addr").field(&self.0).finish()
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

// From https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
// ("Last Updated: 2017-10-13")
full_range!(
    u8,
    /// IP protocol
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum Protocol {
        /// IPv6 Hop-by-Hop Option
        Hopopt = 0,

        /// ICMP
        Icmp = 1,

        /// Internet Group Management Protocol
        Igmp = 2,

        /// Gateway-to-Gateway Protocol
        Ggp = 3,

        /// IPv4 encapsulation
        Ipv4 = 4,

        /// Stream
        St = 5,

        /// Transmission Control Protocol
        Tcp = 6,

        /// CBT
        Cbt = 7,

        /// Exterior Gateway Protocol
        Egp = 8,

        /// Any private interior gateway
        Igp = 9,

        /// BBN RCC Monitoring
        BbnRccMon = 10,

        /// Network Voice Protocol
        NvpIi = 11,

        /// PUP
        Pup = 12,

        /// ARGUS (deprecated)
        Argus = 13,

        /// EMCON
        Emcon = 14,

        /// Cross Net Debugger
        Xnet = 15,

        /// Chaos
        Chaos = 16,

        /// UDP
        Udp = 17,

        /// Multiplexing
        Mux = 18,

        /// DCN Measurement Subsystems
        DcnMeas = 19,

        /// Host Monitoring
        Hmp = 20,

        /// Packet Radio Measurement
        Prm = 21,

        /// XEROX NS IDP
        XnsIdp = 22,

        /// Trunk-1
        Trunk1 = 23,

        /// Trunk-2
        Trunk2 = 24,

        /// Leaf-1
        Leaf1 = 25,

        /// Leaf-2
        Leaf2 = 26,

        /// Reliable Data Protocol
        Rdp = 27,

        /// Internet Reliable Transaction
        Irtp = 28,

        /// ISO Transport Protocol Class 4
        IsoTp4 = 29,

        /// Bulk Data Transfer Protocol
        Netblt = 30,

        /// MFE Network Services Protocol
        MfeNsp = 31,

        /// MERIT Internodal Protocol
        MeritInp = 32,

        /// Datagram Congestion Control Protocol
        Dccp = 33,

        /// Third Party Connect Protocol
        ThreePc = 34,

        /// Inter-Domain Policy Routing Protocol
        Idpr = 35,

        /// Xpress Transport Protocol
        Xtp = 36,

        /// Datagram Delivery Protocol
        Ddp = 37,

        /// IDPR Control Message Transport Proto
        IdprCmtp = 38,

        /// TP++ Transport Protocol
        Tppp = 39,

        /// IL Transport Protocol
        Il = 40,

        /// IPv6 Encapsulation
        Ipv6 = 41,

        /// Source Demand Routing Protocol
        Sdrp = 42,

        /// Routing Header for IPv6
        Ipv6Route = 43,

        /// Fragment Header for IPv6
        Ipv6Frag = 44,

        /// Inter-Domain Routing Protocol
        Idrp = 45,

        /// Resource Protocol
        Rsvp = 46,

        /// Generic Routing Encapsulation
        Gres = 47,

        /// Dynamic Source Routing Protocol
        Dsr = 48,

        /// BNA
        Bna = 49,

        /// Encap Security Payload
        Esp = 50,

        /// Authentication Header
        Ah = 51,

        /// Integrated Net Layer Security Protocol
        INlsp = 52,

        /// IP with Encryption (deprecated)
        Swipe = 53,

        /// NBMA Address Resolution Protocol
        Narp = 54,

        /// IP Mobility
        Mobile = 55,

        /// Transport Layer Security Protocol using Kryptonet key management
        Tlsp = 56,

        /// SKIP
        Skip = 57,

        /// ICMP for IPv6
        Ipv6Icmp = 58,

        /// No Next Header for IPv6
        Ipv6NoNxt = 59,

        /// Destination Options for IPv6
        Ipv6Opts = 60,

        /// Any host internal protocol
        AnyHostInternalProtocol = 61,

        /// CFTP
        Cftp = 62,

        /// Any local network
        AnyLocalNetwork = 63,

        /// SATNET and Backroom EXPAK
        SatExpak = 64,

        /// Kryptolan
        Kryptolan = 65,

        /// MIT Remote Virtual Disk Protocol
        Rvd = 66,

        /// Internet Pluribus Packet Core
        Ippc = 67,

        /// Any distributed file system
        AnyDistributedFileSystem = 68,

        /// SATNET Monitoring
        SatMon = 69,

        /// VISA Protocol
        Visa = 70,

        /// Internet Packet Core Utility
        Ipcu = 71,

        /// Computer Protocol Network Executive
        Cpnx = 72,

        /// Computer Protocol Heart Beat
        Cphb = 73,

        /// Wang Span Network
        Wsn = 74,

        /// Packet Video Protocol
        Pvp = 75,

        /// Backroom SATNET Monitoring
        BrSatMon = 76,

        /// SUN ND PROTOCOL-Temporary
        SunNd = 77,

        /// WIDEBAND Monitoring
        WbMon = 78,

        /// WIDEBAND EXPAK
        WbExpak = 79,

        /// International Organization for Standardization Internet Protocol
        IsoIp = 80,

        /// VMTP
        Vmtp = 81,

        /// Secure-VMTP
        SecureVmtp = 82,

        /// VINES
        Vines = 83,

        /// Transaction Transport Protocol || Internet Protocol Traffic Manager
        TtpIptm = 84,

        /// NSFNET-IGP
        NfsnetIgp = 85,

        /// Dissimilar Gateway Protocol
        Dgp = 86,

        /// TCF
        Tcf = 87,

        /// EIGRP
        Eigrp = 88,

        /// OSPFIGP
        Ospfigp = 89,

        /// Sprite RPC Protocol
        SpriteRpc = 90,

        /// Locus Address Resolution Protocol
        Larp = 91,

        /// Multicast Transport Protocol
        Mtp = 92,

        /// AX.25 Frames
        Ax25 = 93,

        /// IP-within-IP Encapsulation Protocol
        Ipip = 94,

        /// Mobile Internetworking Control Pro. (deprecated)
        Micp = 95,

        /// Semaphore Communications Sec. Pro.
        SccSp = 96,

        /// Ethernet-within-IP Encapsulation
        Etherip = 97,

        /// Encapsulation Header
        Encap = 98,

        /// Any private encryption scheme
        AnyPrivateEncryptionScheme = 99,

        /// GMTP
        Gmtp = 100,

        /// Ipsilon Flow Management Protocol
        Ifmp = 101,

        /// PNNI over IP
        Pnni = 102,

        /// Protocol Independent Multicast
        Pim = 103,

        /// ARIS
        Aris = 104,

        /// SCPS
        Scps = 105,

        /// QNX
        Qnx = 106,

        /// Active Networks
        AN = 107,

        /// IP Payload Compression Protocol
        IpComp = 108,

        /// Sitara Networks Protocol
        Snp = 109,

        /// Compaq Peer Protocol
        CompaqPeer = 110,

        /// IPX in IP
        IpxInIp = 111,

        /// Virtual Router Redundancy Protocol
        Vrrp = 112,

        /// PGM Reliable Transport Protocol
        Pgm = 113,

        /// any 0-hop protocol
        Any0HopProtocol = 114,

        /// Layer Two Tunneling Protocol
        L2tp = 115,

        /// D-II Data Exchange (DDX)
        Ddx = 116,

        /// Interactive Agent Transfer Protocol
        Iatp = 117,

        /// Schedule Transfer Protocol
        Stp = 118,

        /// SpectraLink Radio Protocol
        Srp = 119,

        /// UTI
        Uti = 120,

        /// Simple Message Protocol
        Smp = 121,

        /// Simple Multicast Protocol (deprecated)
        Sm = 122,

        /// Performance Transparency Protocol
        Ptp = 123,

        /// ISIS over IPv4
        IsisOverIpv4 = 124,

        /// FIRE
        Fire = 125,

        /// Combat Radio Transport Protocol
        Crtp = 126,

        /// Combat Radio User Datagram
        Crudp = 127,

        /// SSCOPMCE
        Sscopmce = 128,

        /// IPLT
        Iplt = 129,

        /// Secure Packet Shield
        Sps = 130,

        /// Private IP Encapsulation within IP
        Pipe = 131,

        /// Stream Control Transmission Protocol
        Sctp = 132,

        /// Fibre Channel
        Fc = 133,

        /// RSVP-E2E-IGNORE
        RsvpE2eIgnore = 134,

        /// Mobility Header
        MobilityHeader = 135,

        /// UDPLite
        UdpLite = 136,

        /// MPLS-in-IP
        MplsInIp = 137,

        /// MANET Protocols
        Manet = 138,

        /// Host Identity Protocol
        Hip = 139,

        /// Shim6 Protocol
        Shim6 = 140,

        /// Wrapped Encapsulating Security Payload
        Wesp = 141,

        /// Robust Header Compression
        Rohc = 142,

        /// Reserved
        Reserved = 255,
    }
);

impl Protocol {
    /// Is this an IPv6 extension header?
    pub fn is_ipv6_extension_header(&self) -> bool {
        match *self {
            Protocol::Hopopt => true,
            Protocol::Ipv6Route => true,
            Protocol::Ipv6Frag => true,
            Protocol::Esp => true,
            Protocol::Ah => true,
            Protocol::Ipv6Opts => true,
            Protocol::MobilityHeader => true,
            Protocol::Hip => true,
            Protocol::Shim6 => true,
            Protocol::Unknown(byte) => byte == 253 || byte == 254,
            _ => false,
        }
    }
}

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
    use crate::ipv4;

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
        let buf = &mut chunk[..];

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
