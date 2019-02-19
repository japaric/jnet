//! ICMPv6: Internet Control Message Protocol for IPv6
//!
//! # References
//!
//! - [RFC 4443:  Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6
//! (IPv6) Specification][0]
//!
//! [0]: https://tools.ietf.org/html/rfc4443
//!
//! - [RFC 2461: Neighbor Discovery for IP Version 6 (IPv6)][1]
//!
//! [1]: https://tools.ietf.org/html/rfc2461

use core::{
    fmt,
    marker::PhantomData,
    ops::{Range, RangeFrom},
};

use as_slice::{AsMutSlice, AsSlice};
use byteorder::{ByteOrder, NetworkEndian as NE};
use owning_slice::Truncate;

pub use crate::icmp::{EchoReply, EchoRequest};
use crate::{
    fmt::Quoted,
    ieee802154, ipv6, mac,
    sealed::Echo,
    traits::{TryFrom, TryInto, UncheckedIndex},
    Unknown,
};

/* Message structure */
const TYPE: usize = 0;
const CODE: usize = 1;
const CHECKSUM: Range<usize> = 2..4;
const PAYLOAD: RangeFrom<usize> = 4..;

/// Header size
pub const HEADER_SIZE: u8 = CHECKSUM.end as u8;

// Neighbor{Advertisement,Solicitation}
const RESERVED0: usize = 4;

// Echo{Request,Reply}
const IDENTIFIER: Range<usize> = 4..6;
const SEQUENCE: Range<usize> = 6..8;

mod router {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::solicited::OFFSET + super::solicited::SIZE;
    pub const SIZE: usize = 1;
}

mod solicited {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::override_::OFFSET + super::override_::SIZE;
    pub const SIZE: usize = 1;
}

mod override_ {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = 5;
    pub const SIZE: usize = 1;
}

const TARGET: Range<usize> = 8..24;

/// ICMPv6 Message
// TODO add 'Checksum = {Valid,Unknown}' type state
pub struct Message<BUFFER, TYPE>
where
    BUFFER: AsSlice<Element = u8>,
{
    buffer: BUFFER,
    _type: PhantomData<TYPE>,
}

impl<B, T> Clone for Message<B, T>
where
    B: AsSlice<Element = u8> + Clone,
{
    fn clone(&self) -> Self {
        Message {
            buffer: self.buffer.clone(),
            _type: PhantomData,
        }
    }
}

impl<B, T> Copy for Message<B, T> where B: AsSlice<Element = u8> + Copy {}

impl<B, T> Message<B, T>
where
    B: AsSlice<Element = u8>,
{
    /* Getters */
    /// Reads the 'Type' field
    pub fn get_type(&self) -> Type {
        Type::from(self.header_()[TYPE])
    }

    /// Reads the 'Code' field
    pub fn get_code(&self) -> u8 {
        self.header_()[CODE]
    }

    /// Reads the 'Checksum' field
    pub fn get_checksum(&self) -> u16 {
        NE::read_u16(&self.header_()[CHECKSUM])
    }

    /// Returns the byte representation of this frame
    pub fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }

    /* Miscellaneous */
    pub(crate) fn compute_checksum(&self, src: ipv6::Addr, dest: ipv6::Addr) -> u16 {
        const NEXT_HEADER: u8 = 58;

        let mut sum: u32 = 0;

        // Pseudo-header
        for chunk in src.0.chunks_exact(2).chain(dest.0.chunks_exact(2)) {
            sum += u32::from(NE::read_u16(chunk));
        }

        // XXX should this be just `as u16`?
        let len = self.as_slice().len() as u32;
        sum += len >> 16;
        sum += len & 0xffff;

        sum += u32::from(NEXT_HEADER);

        // ICMPv6 message
        for (i, chunk) in self.as_slice().chunks(2).enumerate() {
            if i == 1 {
                // this is the checksum field, skip
                continue;
            }

            if chunk.len() == 1 {
                sum += u32::from(chunk[0]) << 8;
            } else {
                sum += u32::from(NE::read_u16(chunk));
            }
        }

        // fold carry-over
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !(sum as u16)
    }

    /// Verifies the 'Checksum' field
    pub fn verify_checksum(&self, src: ipv6::Addr, dest: ipv6::Addr) -> bool {
        self.compute_checksum(src, dest) == self.get_checksum()
    }

    /// Returns the underlying buffer
    pub fn free(self) -> B {
        self.buffer
    }

    /* Private */
    unsafe fn unchecked(bytes: B) -> Self {
        Message {
            buffer: bytes,
            _type: PhantomData,
        }
    }

    fn body(&self) -> &[u8] {
        &self.as_slice()[PAYLOAD]
    }

    fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    fn header_(&self) -> &[u8; HEADER_SIZE as usize] {
        debug_assert!(self.as_slice().len() >= HEADER_SIZE as usize);

        unsafe { &*(self.as_slice().as_ptr() as *const _) }
    }
}

impl<B, T> Message<B, T>
where
    B: AsMutSlice<Element = u8>,
{
    /// Recomputes and updates the 'Checksum' field
    pub fn update_checksum(&mut self, src: ipv6::Addr, dest: ipv6::Addr) {
        let checksum = self.compute_checksum(src, dest);
        self.set_checksum(checksum);
    }

    fn set_checksum(&mut self, checksum: u16) {
        NE::write_u16(&mut self.header_mut_()[CHECKSUM], checksum);
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }

    fn header_mut_(&mut self) -> &mut [u8; HEADER_SIZE as usize] {
        debug_assert!(self.as_slice().len() >= HEADER_SIZE as usize);

        unsafe { &mut *(self.as_mut_slice().as_mut_ptr() as *mut _) }
    }
}

impl<B> Message<B, Unknown>
where
    B: AsSlice<Element = u8>,
{
    /* Constructors */
    /// Parses the bytes as an ICMPv6 message
    //
    /// NOTE this function does not validate the message checksum
    pub fn parse(bytes: B) -> Result<Self, B> {
        let len = bytes.as_slice().len();

        if len < PAYLOAD.start {
            Err(bytes)
        } else {
            Ok(Message {
                buffer: bytes,
                _type: PhantomData,
            })
        }
    }
}

impl<B> Message<B, Unknown>
where
    B: AsMutSlice<Element = u8>,
{
    fn set_type(&mut self, ty: Type) {
        self.header_mut_()[TYPE] = ty.into();
    }

    fn set_code(&mut self, code: u8) {
        self.header_mut_()[CODE] = code;
    }
}

impl<B> Message<B, Unknown>
where
    B: AsSlice<Element = u8>,
{
    /* Miscellaneous */
    /// Downcasts this packet with unknown type into a specific type
    pub fn downcast<TYPE>(self) -> Result<Message<B, TYPE>, Message<B, Unknown>>
    where
        Self: TryInto<Message<B, TYPE>, Error = Self>,
    {
        self.try_into()
    }
}

impl<B> fmt::Debug for Message<B, Unknown>
where
    B: AsSlice<Element = u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("icmpv6::Message");
        s.field("type", &self.get_type())
            .field("code", &self.get_code())
            .field("checksum", &self.get_checksum());
        s.field("body", &self.body());
        s.finish()
    }
}

/// [Type state]
pub enum NeighborSolicitation {}

impl<B> Message<B, NeighborSolicitation>
where
    B: AsSlice<Element = u8>,
{
    /// Reads the 'Target Address' field
    pub fn get_target(&self) -> ipv6::Addr {
        unsafe { ipv6::Addr(*(self.as_slice().as_ptr().add(8) as *const _)) }
    }

    /// Reads the 'Source Link-layer address' option
    // NOTE this contains padding
    pub fn get_source_ll(&self) -> Option<&[u8]> {
        unsafe {
            Options::new(&self.as_slice().rf(24..))
                .filter_map(|opt| {
                    if opt.ty == OptionType::SourceLinkLayerAddress {
                        Some(opt.contents)
                    } else {
                        None
                    }
                })
                .next()
        }
    }
}

impl<B> fmt::Debug for Message<B, NeighborSolicitation>
where
    B: AsSlice<Element = u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("icmpv6::Message<NeighborSolicitation>")
            .field("checksum", &self.get_checksum())
            .field("target", &Quoted(self.get_target()))
            .field("source_ll", &self.get_source_ll())
            .finish()
    }
}

impl<B> From<Message<B, EchoRequest>> for Message<B, EchoReply>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
{
    fn from(p: Message<B, EchoRequest>) -> Self {
        let mut p: Message<B, Unknown> = unsafe { Message::unchecked(p.buffer) };
        p.set_type(Type::EchoReply);
        let p: Message<B, EchoReply> = unsafe { Message::unchecked(p.buffer) };
        p
    }
}

impl<B> TryFrom<Message<B, Unknown>> for Message<B, NeighborSolicitation>
where
    B: AsSlice<Element = u8>,
{
    type Error = Message<B, Unknown>;

    fn try_from(m: Message<B, Unknown>) -> Result<Self, Message<B, Unknown>> {
        // RFC 4861 - Section 7.1.1.  Validation of Neighbor Solicitations
        // "ICMP Code is 0"
        // "ICMP length (derived from the IP length) is 24 or more octets"
        if m.get_type() == Type::NeighborSolicitation
            && m.get_code() == 0
            && m.as_slice().len() >= 24
        {
            // "Target Address is not a multicast address"
            if ipv6::Addr(unsafe { *(m.as_slice().as_ptr().add(8) as *const _) }).is_multicast() {
                return Err(m);
            }

            if m.as_slice().len() == 24 {
                // no options
                Ok(unsafe { Message::unchecked(m.buffer) })
            } else {
                // "All included options have a length that is greater than zero"
                if Options::are_valid(&m.as_slice()[24..]) {
                    Ok(unsafe { Message::unchecked(m.buffer) })
                } else {
                    Err(m)
                }
            }
        } else {
            Err(m)
        }
    }
}

/// [Type state]
pub enum NeighborAdvertisement {}

impl<B> TryFrom<Message<B, Unknown>> for Message<B, NeighborAdvertisement>
where
    B: AsSlice<Element = u8>,
{
    type Error = Message<B, Unknown>;

    fn try_from(m: Message<B, Unknown>) -> Result<Self, Message<B, Unknown>> {
        if m.get_type() == Type::NeighborAdvertisement
            && m.get_code() == 0
            && m.as_slice().len() >= 24
        {
            // "Target Address is not a multicast address."
            if ipv6::Addr(unsafe { *(m.as_slice().as_ptr().add(8) as *const _) }).is_multicast() {
                return Err(m);
            }

            if m.as_slice().len() == 24 {
                // no options
                Ok(unsafe { Message::unchecked(m.buffer) })
            } else {
                if Options::are_valid(&m.as_slice()[24..]) {
                    Ok(unsafe { Message::unchecked(m.buffer) })
                } else {
                    Err(m)
                }
            }
        } else {
            Err(m)
        }
    }
}

impl<B> Message<B, NeighborAdvertisement>
where
    B: AsMutSlice<Element = u8> + Truncate<u8>,
{
    /* Constructors */
    /// Transforms the input buffer into a Neighbor Advertisement ICMPv6 message
    ///
    /// `target_ll_opt_size` is the size of the 'Target Link-layer Address' option *in units of 8
    /// octets*. A value of `0` means that the option will be omitted.
    ///
    /// All these fields need to be filled by the caller
    ///
    /// - Override bit
    /// - Solicited bit
    /// - Router bit
    /// - Target Address field
    /// - Target Link-layer Address option
    pub fn neighbor_advertisement(mut buffer: B, target_ll_opt_size: u8) -> Self {
        let size = 24 + target_ll_opt_size * 8;
        assert!(buffer.as_slice().len() >= usize::from(size));

        // clear reserved field
        unsafe { buffer.as_mut_slice().rm(4..8).copy_from_slice(&[0; 4]) };

        buffer.truncate(size);

        // set option type and length, and clear it (padding)
        if target_ll_opt_size != 0 {
            unsafe {
                *buffer.as_mut_slice().gum(24) = OptionType::TargetLinkLayerAddress.into();
                *buffer.as_mut_slice().gum(25) = target_ll_opt_size;
            }

            // TODO we remove this
            // for byte in buffer.as_mut_slice()[26..].iter_mut() {
            //     *byte = 0;
            // }
        }

        let mut m = Message {
            buffer,
            _type: PhantomData,
        };

        m.set_type(Type::NeighborAdvertisement);
        m.set_code(0);

        unsafe { Message::unchecked(m.buffer) }
    }
}

impl<B> Message<B, NeighborAdvertisement>
where
    B: AsSlice<Element = u8>,
{
    /* Getters */
    /// Reads the 'Router' flag
    pub fn get_router(&self) -> bool {
        unsafe { get!(self.as_slice().gu(RESERVED0), router) == 1 }
    }

    /// Reads the 'Solicited' flag
    pub fn get_solicited(&self) -> bool {
        unsafe { get!(self.as_slice().gu(RESERVED0), solicited) == 1 }
    }

    /// Reads the 'Override' flag
    pub fn get_override(&self) -> bool {
        unsafe { get!(self.as_slice().gu(RESERVED0), override_) == 1 }
    }

    /// Reads the 'Target Address' field
    pub fn get_target(&self) -> ipv6::Addr {
        unsafe { ipv6::Addr(*(self.as_slice().as_ptr().add(8) as *const _)) }
    }

    /// Reads the 'Target Link-layer Address' option
    pub fn get_target_ll(&self) -> Option<&[u8]> {
        unsafe {
            Options::new(self.as_slice().rf(24..))
                .filter_map(|opt| {
                    if opt.ty == OptionType::TargetLinkLayerAddress {
                        Some(opt.contents)
                    } else {
                        None
                    }
                })
                .next()
        }
    }
}

impl<B> Message<B, NeighborAdvertisement>
where
    B: AsMutSlice<Element = u8>,
{
    /* Setters */
    /// Sets the 'Router' flag
    pub fn set_router(&mut self, router: bool) {
        unsafe {
            set!(
                *self.as_mut_slice().gum(RESERVED0),
                router,
                if router { 1 } else { 0 }
            )
        }
    }

    /// Sets the 'Solicited' flag
    pub fn set_solicited(&mut self, solicited: bool) {
        unsafe {
            set!(
                *self.as_mut_slice().gum(RESERVED0),
                solicited,
                if solicited { 1 } else { 0 }
            )
        }
    }

    /// Sets the 'Override' flag
    pub fn set_override(&mut self, override_: bool) {
        unsafe {
            set!(
                *self.as_mut_slice().gum(RESERVED0),
                override_,
                if override_ { 1 } else { 0 }
            )
        }
    }

    /// Sets the 'Target Address' field
    pub fn set_target(&mut self, addr: ipv6::Addr) {
        unsafe {
            self.as_mut_slice().rm(TARGET).copy_from_slice(&addr.0);
        }
    }

    // NOTE(unsafe) caller must ensure that the 'Target Link-layer Address' exists
    pub(crate) unsafe fn set_target_ieee802154_addr(&mut self, addr: ieee802154::ExtendedAddr) {
        let opt = self.target_ll_mut().unwrap_or_else(|| debug_unreachable!());

        NE::write_u64(&mut opt[..8], addr.0);
    }

    // NOTE(unsafe) caller must ensure that the 'Target Link-layer Address' exists
    pub(crate) unsafe fn set_target_mac_addr(&mut self, addr: mac::Addr) {
        self.target_ll_mut()
            .unwrap_or_else(|| debug_unreachable!())
            .copy_from_slice(&addr.0);
    }

    /// Mutable view into the 'Target Link-layer address' option
    pub fn target_ll_mut(&mut self) -> Option<&mut [u8]> {
        OptionsMut::new(unsafe { self.as_mut_slice().rfm(24..) })
            .filter_map(|opt| {
                if opt.ty == OptionType::TargetLinkLayerAddress {
                    Some(opt.contents)
                } else {
                    None
                }
            })
            .next()
    }
}

impl<B> fmt::Debug for Message<B, NeighborAdvertisement>
where
    B: AsSlice<Element = u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("icmpv6::Message<NeighborAdvertisement>")
            .field("checksum", &self.get_checksum())
            .field("target", &Quoted(self.get_target()))
            .field("target_ll", &self.get_target_ll())
            .finish()
    }
}

impl<B, E> Message<B, E>
where
    B: AsSlice<Element = u8>,
    E: Echo,
{
    /* Getters */
    /// Reads the 'Identifier' field
    pub fn get_identifier(&self) -> u16 {
        unsafe { NE::read_u16(&self.as_slice().r(IDENTIFIER)) }
    }

    /// Reads the 'Sequence number' field
    pub fn get_sequence_number(&self) -> u16 {
        unsafe { NE::read_u16(&self.as_slice().r(SEQUENCE)) }
    }

    /// Immutable view into the payload of this message
    pub fn payload(&self) -> &[u8] {
        unsafe { self.as_slice().rf(SEQUENCE.end..) }
    }
}

impl<B, E> fmt::Debug for Message<B, E>
where
    B: AsSlice<Element = u8>,
    E: Echo,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = if typeid!(E == EchoReply) {
            f.debug_struct("icmpv6::Message<EchoReply>")
        } else {
            f.debug_struct("icmpv6::Message<EchoRequest>")
        };
        s.field("checksum", &self.get_checksum())
            .field("identifier", &self.get_identifier())
            .field("sequence_number", &self.get_sequence_number())
            .finish()
    }
}

impl<B> TryFrom<Message<B, Unknown>> for Message<B, EchoRequest>
where
    B: AsSlice<Element = u8>,
{
    type Error = Message<B, Unknown>;

    fn try_from(m: Message<B, Unknown>) -> Result<Self, Message<B, Unknown>> {
        if m.get_type() == Type::EchoRequest && m.get_code() == 0 && m.as_slice().len() >= 8 {
            Ok(unsafe { Message::unchecked(m.buffer) })
        } else {
            Err(m)
        }
    }
}

impl<B> TryFrom<Message<B, Unknown>> for Message<B, EchoReply>
where
    B: AsSlice<Element = u8>,
{
    type Error = Message<B, Unknown>;

    fn try_from(m: Message<B, Unknown>) -> Result<Self, Message<B, Unknown>> {
        if m.get_type() == Type::EchoReply && m.get_code() == 0 && m.as_slice().len() >= 8 {
            Ok(unsafe { Message::unchecked(m.buffer) })
        } else {
            Err(m)
        }
    }
}

impl<B> Message<B, EchoReply>
where
    B: AsMutSlice<Element = u8>,
{
    /// Transforms the input buffer into a Echo Reply ICMPv6 message
    pub fn echo_reply(buffer: B) -> Self {
        assert!(buffer.as_slice().len() >= 8);

        let mut m: Message<B, Unknown> = unsafe { Message::unchecked(buffer) };
        m.set_type(Type::EchoReply);
        m.set_code(0);
        unsafe { Message::unchecked(m.buffer) }
    }

    /// Sets the 'Identifier' field
    pub fn set_identifier(&mut self, id: u16) {
        unsafe { NE::write_u16(self.as_mut_slice().rm(IDENTIFIER), id) }
    }

    /// Sets the 'Sequence number' field
    pub fn set_sequence_number(&mut self, seq: u16) {
        unsafe { NE::write_u16(self.as_mut_slice().rm(SEQUENCE), seq) }
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        unsafe { self.as_mut_slice().rfm(SEQUENCE.end..) }
    }
}

impl<B> Message<B, EchoReply>
where
    B: AsMutSlice<Element = u8> + Truncate<u8>,
{
    /// Fills the payload with the given data and adjusts the length of the UDP packet
    pub fn set_payload(&mut self, data: &[u8]) {
        let dlen = data.len();
        self.payload_mut()[..dlen].copy_from_slice(data);
        self.buffer.truncate(dlen as u8 + SEQUENCE.end as u8);
    }
}

// See Section 4.6 of RFC 2461
struct Options<'a> {
    opts: &'a [u8],
}

struct OptionRef<'a> {
    pub ty: OptionType,
    pub contents: &'a [u8],
}

struct OptionMut<'a> {
    pub ty: OptionType,
    pub contents: &'a mut [u8],
}

impl<'a> Options<'a> {
    // NOTE: Caller must ensure that `are_valid` returns `true` before using this as an iterator
    unsafe fn new(opts: &'a [u8]) -> Self {
        Options { opts }
    }

    fn are_valid(mut opts: &'a [u8]) -> bool {
        if opts.is_empty() {
            return true;
        }

        loop {
            if opts.len() < 2 {
                // not big enough to contain the Type and Length
                return false;
            }

            let length = usize::from(8 * opts[1]);

            if length == 0 {
                // zero sized option
                return false;
            }

            if opts.len() == length {
                return true;
            } else if opts.len() < length {
                return false;
            } else {
                opts = &opts[length..];
            }
        }
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = OptionRef<'a>;

    fn next(&mut self) -> Option<OptionRef<'a>> {
        if self.opts.is_empty() {
            None
        } else {
            unsafe {
                let ty = OptionType::from(*self.opts.gu(0));
                let len = 8 * usize::from(*self.opts.gu(1));
                let contents = self.opts.r(2..len);

                self.opts = self.opts.rf(len..);

                Some(OptionRef { ty, contents })
            }
        }
    }
}

struct OptionsMut<'a> {
    opts: &'a mut [u8],
}

impl<'a> OptionsMut<'a> {
    fn new(opts: &'a mut [u8]) -> Self {
        OptionsMut { opts }
    }
}

impl<'a> Iterator for OptionsMut<'a> {
    type Item = OptionMut<'a>;

    fn next(&mut self) -> Option<OptionMut<'a>> {
        if self.opts.is_empty() {
            None
        } else {
            unsafe {
                let ty = OptionType::from(*self.opts.gu(0));
                let len = 8 * usize::from(*self.opts.gu(1));
                let contents = &mut *(self.opts.rm(2..len) as *mut [u8]);

                self.opts = &mut *(self.opts.rfm(len..) as *mut [u8]);

                Some(OptionMut { ty, contents })
            }
        }
    }
}

full_range!(
    u8,
    /// ICMPv6 types
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Type {
        /// Echo request
        EchoRequest = 128,
        /// Echo reply
        EchoReply = 129,
        /// Router solicitation
        RouterSolicitation = 133,
        /// Router advertisement
        RouterAdvertisement = 134,
        /// Neighbor solicitation
        NeighborSolicitation = 135,
        /// Neighbor advertisement
        NeighborAdvertisement = 136,
    }
);

full_range!(
    u8,
    /// Option type
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum OptionType {
        // Source link-layer address
        SourceLinkLayerAddress = 1,
        // Target link-layer address
        TargetLinkLayerAddress = 2,
        // Prefix information
        PrefixInformation = 3,
        // Redirected header
        RedirectedHeader = 4,
        // MTU
        Mtu = 5,
    }
);
