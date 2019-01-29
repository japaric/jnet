//! ARP: Address Resolution Protocol
//!
//! # References
//!
//! - [RFC 826: An Ethernet Address Resolution Protocol][rfc]
//!
//! [rfc]: https://tools.ietf.org/html/rfc826

use core::fmt;
use core::marker::PhantomData;
use core::ops::{Range, RangeFrom};

use as_slice::{AsMutSlice, AsSlice};
use byteorder::{ByteOrder, NetworkEndian as NE};
use cast::usize;
use owning_slice::Truncate;

use crate::{
    ether, ipv4, mac,
    traits::{TryFrom, TryInto, UncheckedIndex},
    Unknown,
};

/* Packet structure */
const HTYPE: Range<usize> = 0..2;
const PTYPE: Range<usize> = 2..4;
const HLEN: usize = 4;
const PLEN: usize = 5;
const OPER: Range<usize> = 6..8;
const PAYLOAD: RangeFrom<usize> = 8..;

/// Size of the ARP header
pub const HEADER_SIZE: u8 = PAYLOAD.start as u8;

// NOTE Use only for Packet<_, Ethernet, Ipv4>
const SHA: Range<usize> = 8..14;
const SPA: Range<usize> = 14..18;
const THA: Range<usize> = 18..24;
const TPA: Range<usize> = 24..28;

/// [Type state] The Ethernet hardware type
pub enum Ethernet {}

/// [Type state] The IPv4 protocol type
pub enum Ipv4 {}

/// ARP packet
pub struct Packet<BUFFER, HTYPE = Ethernet, PTYPE = Ipv4>
where
    BUFFER: AsSlice<Element = u8>,
    HTYPE: 'static,
    PTYPE: 'static,
{
    buffer: BUFFER,
    _htype: PhantomData<HTYPE>,
    _ptype: PhantomData<PTYPE>,
}

/* Ethernet - Ipv4 */
impl<B> Packet<B, Ethernet, Ipv4>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8> + Truncate<u8>,
{
    /* Constructors */
    /// Transforms the given buffer into an ARP packet
    ///
    /// This function populates the following header fields:
    ///
    /// - HTYPE = Ethernet
    /// - PTYPE = IPv4
    /// - HLEN = 6
    /// - PLEN = 4
    /// - OPER = Request
    pub fn new(buffer: B) -> Self {
        let len = HEADER_SIZE + 20;
        assert!(buffer.as_slice().len() >= usize(len));

        let mut packet: Packet<B, Unknown, Unknown> = Packet {
            buffer,
            _htype: PhantomData,
            _ptype: PhantomData,
        };

        packet.buffer.truncate(len);
        packet.set_htype(HardwareType::Ethernet);
        packet.set_ptype(ether::Type::Ipv4);
        packet.buffer.as_mut_slice()[HLEN] = 6;
        packet.buffer.as_mut_slice()[PLEN] = 4;
        packet.set_oper(Operation::Request);

        Packet {
            buffer: packet.buffer,
            _htype: PhantomData,
            _ptype: PhantomData,
        }
    }
}

impl<B> Packet<B, Ethernet, Ipv4>
where
    B: AsSlice<Element = u8>,
{
    /* Getters */
    /// Returns the SHA (Sender Hardware Address) field of the payload
    pub fn get_sha(&self) -> mac::Addr {
        unsafe { mac::Addr(*(self.as_slice().as_ptr().add(SHA.start) as *const _)) }
    }

    /// Returns the SPA (Sender Protocol Address) field of the payload
    pub fn get_spa(&self) -> ipv4::Addr {
        unsafe { ipv4::Addr(*(self.as_slice().as_ptr().add(SPA.start) as *const _)) }
    }

    /// Returns the THA (Target Hardware Address) field of the payload
    pub fn get_tha(&self) -> mac::Addr {
        unsafe { mac::Addr(*(self.as_slice().as_ptr().add(THA.start) as *const _)) }
    }

    /// Returns the TPA (Target Protocol Address) field of the payload
    pub fn get_tpa(&self) -> ipv4::Addr {
        unsafe { ipv4::Addr(*(self.as_slice().as_ptr().add(TPA.start) as *const _)) }
    }

    /// Is this an ARP probe?
    pub fn is_a_probe(&self) -> bool {
        self.get_spa() == ipv4::Addr::UNSPECIFIED
    }
}

impl<B> Packet<B, Ethernet, Ipv4>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
{
    /* Setters */
    /// Sets the SHA (Sender Hardware Address) field of the payload
    pub fn set_sha(&mut self, sha: mac::Addr) {
        self.as_mut_slice()[SHA].copy_from_slice(&sha.0);
    }

    /// Sets the SPA (Sender Protocol Address) field of the payload
    pub fn set_spa(&mut self, spa: ipv4::Addr) {
        self.as_mut_slice()[SPA].copy_from_slice(&spa.0);
    }

    /// Sets the THA (Target Hardware Address) field of the payload
    pub fn set_tha(&mut self, tha: mac::Addr) {
        self.as_mut_slice()[THA].copy_from_slice(&tha.0);
    }

    /// Sets the TPA (Target Protocol Address) field of the payload
    pub fn set_tpa(&mut self, tpa: ipv4::Addr) {
        self.as_mut_slice()[TPA].copy_from_slice(&tpa.0);
    }

    /* Miscellaneous */
    /// ARP announcement
    ///
    /// Shortcut for setting these fields
    ///
    /// - OPER = Request
    /// - SPA = TPA = addr
    /// - THA = 00:00:00:00:00:00
    pub fn announce(&mut self, addr: ipv4::Addr) {
        self.set_oper(Operation::Request);

        self.set_spa(addr);

        self.set_tha(mac::Addr([0; 6]));
        self.set_tpa(addr);
    }

    /// ARP probe
    ///
    /// Shortcut for setting these fields
    ///
    /// - OPER = Request
    /// - SPA = 0.0.0.0
    /// - THA = 00:00:00:00:00:00
    /// - TPA = addr
    pub fn probe(&mut self, addr: ipv4::Addr) {
        self.set_oper(Operation::Request);

        self.set_spa(ipv4::Addr::UNSPECIFIED);

        self.set_tha(mac::Addr([0; 6]));
        self.set_tpa(addr);
    }
}

/* Unknown - Unknown */
impl<B> Packet<B, Unknown, Unknown>
where
    B: AsSlice<Element = u8>,
{
    /* Getters */
    // htype: covered by the generic impl
    // ptype: covered by the generic impl
    // hlen: covered by the generic impl
    // plen: covered by the generic impl
    // oper: covered by the generic impl

    /// Returns the SHA (Sender Hardware Address) field of the payload
    pub fn get_sha(&self) -> &[u8] {
        let end = usize(self.get_hlen());

        unsafe { self.payload().rt(..end) }
    }

    /// Returns the SPA (Sender Protocol Address) field of the payload
    pub fn get_spa(&self) -> &[u8] {
        let start = usize(self.get_hlen());
        let end = start + usize(self.get_plen());

        unsafe { self.payload().r(start..end) }
    }

    /// Returns the THA (Target Hardware Address) field of the payload
    pub fn get_tha(&self) -> &[u8] {
        let start = usize(self.get_hlen()) + usize(self.get_plen());
        let end = start + usize(self.get_hlen());

        unsafe { self.payload().r(start..end) }
    }

    /// Returns the TPA (Target Protocol Address) field of the payload
    pub fn get_tpa(&self) -> &[u8] {
        let start = 2 * usize(self.get_hlen()) + usize(self.get_plen());
        let end = start + usize(self.get_plen());

        unsafe { self.payload().r(start..end) }
    }

    /* Miscellaneous */
    /// Interprets this packet as `Packet<Ethernet, Ipv4>`
    pub fn downcast(self) -> Result<Packet<B>, Self> {
        TryInto::try_into(self)
    }
}

impl<B> Packet<B, Unknown, Unknown>
where
    B: AsSlice<Element = u8>,
{
    /// Parses bytes into an ARP packet
    pub fn parse(bytes: B) -> Result<Self, B> {
        if bytes.as_slice().len() < usize(HEADER_SIZE) {
            // too small; header doesn't fit
            return Err(bytes);
        }

        let p = Packet {
            buffer: bytes,
            _htype: PhantomData,
            _ptype: PhantomData,
        };

        let hlen = p.get_hlen();
        let plen = p.get_plen();

        let payload_len = 2 * (usize(hlen) + usize(plen));
        if p.as_slice().len() < usize(HEADER_SIZE) + payload_len {
            // too small; payload doesn't fit
            Err(p.buffer)
        } else {
            Ok(p)
        }
    }
}

impl<B> Packet<B, Unknown, Unknown>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
{
    /* Setters */
    /// Sets the HTYPE (Hardware TYPE) field of the header
    pub fn set_htype(&mut self, htype: HardwareType) {
        NE::write_u16(&mut self.as_mut_slice()[HTYPE], htype.into());
    }

    /// Sets the PTYPE (Protocol TYPE) field of the header
    pub fn set_ptype(&mut self, ptype: ether::Type) {
        NE::write_u16(&mut self.as_mut_slice()[PTYPE], ptype.into());
    }
}

impl<B> TryFrom<Packet<B, Unknown, Unknown>> for Packet<B, Ethernet, Ipv4>
where
    B: AsSlice<Element = u8>,
{
    type Error = Packet<B, Unknown, Unknown>;

    fn try_from(p: Packet<B, Unknown, Unknown>) -> Result<Self, Packet<B, Unknown, Unknown>> {
        if p.get_htype() == HardwareType::Ethernet
            && p.get_ptype() == ether::Type::Ipv4
            && p.get_hlen() == 6
            && p.get_plen() == 4
        {
            Ok(Packet {
                buffer: p.buffer,
                _htype: PhantomData,
                _ptype: PhantomData,
            })
        } else {
            Err(p)
        }
    }
}

/* HTYPE - PTYPE */
impl<B, H, P> Packet<B, H, P>
where
    B: AsSlice<Element = u8>,
{
    /* Getters */
    /// Returns the HTYPE (Hardware TYPE) field of the header
    pub fn get_htype(&self) -> HardwareType {
        if typeid!(H == Ethernet) {
            HardwareType::Ethernet
        } else {
            NE::read_u16(&self.header()[HTYPE]).into()
        }
    }

    /// Returns the PTYPE (Protocol TYPE) field of the header
    pub fn get_ptype(&self) -> ether::Type {
        if typeid!(P == Ipv4) {
            ether::Type::Ipv4
        } else {
            NE::read_u16(&self.header()[PTYPE]).into()
        }
    }

    /// Returns the HLEN (Hardware LENgth) field of the header
    pub fn get_hlen(&self) -> u8 {
        if typeid!(H == Ethernet) {
            6
        } else {
            self.header()[HLEN]
        }
    }

    /// Returns the PLEN (Protocol LENgth) field of the header
    pub fn get_plen(&self) -> u8 {
        if typeid!(P == Ipv4) {
            4
        } else {
            self.header()[PLEN]
        }
    }

    /// Returns the OPER (OPERation) field of the header
    pub fn get_oper(&self) -> Operation {
        NE::read_u16(&self.header()[OPER]).into()
    }

    /// View into the payload
    ///
    /// NOTE this may contain padding bytes at the end
    pub fn payload(&self) -> &[u8] {
        unsafe { self.as_slice().rf(PAYLOAD) }
    }

    /// Returns the canonical length of this packet
    ///
    /// This ignores padding bytes, if any
    pub fn len(&self) -> u8 {
        HEADER_SIZE + 2 * (self.get_hlen() + self.get_plen())
    }

    /* Miscellaneous */
    /// Frees the underlying buffer
    pub fn free(self) -> B {
        self.buffer
    }

    /* Private */
    fn header(&self) -> &[u8; 8] {
        debug_assert!(self.as_slice().len() >= 8);

        unsafe { &*(self.as_slice().as_ptr() as *const _) }
    }

    fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }
}

impl<B, H, P> Packet<B, H, P>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
{
    /* Setters */
    /// Sets the OPER (OPERation) field of the header
    pub fn set_oper(&mut self, oper: Operation) {
        NE::write_u16(&mut self.as_mut_slice()[OPER], oper.into())
    }

    /// Mutable view into the payload
    ///
    /// NOTE this may contain padding bytes at the end
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut_slice()[PAYLOAD]
    }

    /* Private */
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }
}

impl<B, H, P> Clone for Packet<B, H, P>
where
    B: Clone + AsSlice<Element = u8>,
{
    fn clone(&self) -> Self {
        Packet {
            buffer: self.buffer.clone(),
            _htype: PhantomData,
            _ptype: PhantomData,
        }
    }
}

impl<B, H, P> Copy for Packet<B, H, P> where B: Copy + AsSlice<Element = u8> {}

impl<B> fmt::Debug for Packet<B, Ethernet, Ipv4>
where
    B: AsSlice<Element = u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("arp::Packet")
            .field("oper", &self.get_oper())
            .field("sha", &self.get_sha())
            .field("spa", &self.get_spa())
            .field("tha", &self.get_tha())
            .field("tpa", &self.get_tpa())
            .finish()
    }
}

impl<B> fmt::Debug for Packet<B, Unknown, Unknown>
where
    B: AsSlice<Element = u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("arp::Packet")
            .field("htype", &self.get_htype())
            .field("ptype", &self.get_ptype())
            .field("hlen", &self.get_hlen())
            .field("plen", &self.get_plen())
            .field("oper", &self.get_oper())
            .field("sha", &self.get_sha())
            .field("spa", &self.get_spa())
            .field("tha", &self.get_tha())
            .field("tpa", &self.get_tpa())
            .finish()
    }
}

full_range!(
    u16,
    /// Hardware type
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum HardwareType {
        /// Ethernet
        Ethernet = 1,
    }
);

full_range!(
    u16,
    /// ARP operation
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum Operation {
        /// Request operation
        Request = 1,
        /// Reply operation
        Reply = 2,
    }
);

#[cfg(test)]
mod tests {
    use rand::{self, RngCore};

    use crate::{arp, ether, ipv4, mac};

    const SIZE: usize = 46;

    const BYTES: &[u8; SIZE] = &[
        255, 255, 255, 255, 255, 255, // eth: destination
        120, 68, 118, 217, 106, 124, // eth: source
        8, 6, // eth: type
        0, 1, // arp: HTYPE
        8, 0, // arp: PTYPE
        6, // arp: HLEN
        4, // arp: PLEN
        0, 2, // arp: OPER
        120, 68, 118, 217, 106, 124, // arp: SHA
        192, 168, 1, 1, // arp: SPA
        32, 24, 3, 1, 0, 0, // arp: THA
        192, 168, 1, 33, // arp: TPA
        0, 0, 0, 0, // eth: padding
    ];

    const SENDER_MAC: mac::Addr = mac::Addr([0x78, 0x44, 0x76, 0xd9, 0x6a, 0x7c]);
    const SENDER_IP: ipv4::Addr = ipv4::Addr([192, 168, 1, 1]);

    const TARGET_MAC: mac::Addr = mac::Addr([0x20, 0x18, 0x03, 0x01, 0x00, 0x00]);
    const TARGET_IP: ipv4::Addr = ipv4::Addr([192, 168, 1, 33]);

    #[test]
    fn construct() {
        // NOTE start with randomized array to make sure we set *everything* correctly
        let mut array: [u8; SIZE] = [0; SIZE];
        rand::thread_rng().fill_bytes(&mut array);

        let mut eth = ether::Frame::new(&mut array[..]);

        eth.set_destination(mac::Addr::BROADCAST);
        eth.set_source(SENDER_MAC);

        eth.arp(|arp| {
            arp.set_oper(arp::Operation::Reply);
            arp.set_sha(SENDER_MAC);
            arp.set_spa(SENDER_IP);
            arp.set_tha(TARGET_MAC);
            arp.set_tpa(TARGET_IP);
        });

        // ignore the padding
        assert_eq!(eth.as_bytes(), &BYTES[..SIZE - 4]);
    }

    #[test]
    fn parse() {
        let eth = ether::Frame::parse(&BYTES[..]).unwrap();
        let packet = arp::Packet::parse(eth.payload()).unwrap();

        assert_eq!(packet.get_htype(), arp::HardwareType::Ethernet);
        assert_eq!(packet.get_ptype(), ether::Type::Ipv4);
        assert_eq!(packet.get_hlen(), 6);
        assert_eq!(packet.get_plen(), 4);
        assert_eq!(packet.get_oper(), arp::Operation::Reply);
        assert_eq!(packet.get_sha(), &SENDER_MAC.0);
        assert_eq!(packet.get_spa(), &SENDER_IP.0);
        assert_eq!(packet.get_tha(), &TARGET_MAC.0);
        assert_eq!(packet.get_tpa(), &TARGET_IP.0);
    }
}
