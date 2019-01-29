//! ICMP: Internet Control Message Protocol
//!
//! # References
//!
//! - [RFC 792: Internet Control Message Protocol][rfc]
//!
//! [rfc]: https://tools.ietf.org/html/rfc792

use core::fmt;
use core::marker::PhantomData;
use core::ops::{Range, RangeFrom};

use as_slice::{AsMutSlice, AsSlice};
use byteorder::{ByteOrder, NetworkEndian as NE};
use cast::usize;

use crate::{
    fmt::Hex,
    ipv4,
    sealed::Echo,
    traits::{TryFrom, TryInto, UncheckedIndex},
    Invalid, Unknown, Valid,
};

/* Message structure */
const TYPE: usize = 0;
const CODE: usize = 1;
const CHECKSUM: Range<usize> = 2..4;
const IDENT: Range<usize> = 4..6;
const SEQ_NO: Range<usize> = 6..8;
const PAYLOAD: RangeFrom<usize> = 8..;

/// Size of the ICMP header
pub const HEADER_SIZE: u16 = PAYLOAD.start as u16;

/// ICMP Message
pub struct Message<BUFFER, TYPE, CHECKSUM>
where
    BUFFER: AsSlice<Element = u8>,
    TYPE: 'static,
{
    buffer: BUFFER,
    _type: PhantomData<TYPE>,
    _checksum: PhantomData<CHECKSUM>,
}

/// [Type State] The Echo Reply type
pub enum EchoReply {}

/// [Type State] The Echo Request type
pub enum EchoRequest {}

/* EchoRequest */
impl<B> Message<B, EchoRequest, Invalid>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
{
    /* Constructors */
    /// Transforms the input buffer into a Echo Request ICMP packet
    pub fn new(buffer: B) -> Self {
        assert!(buffer.as_slice().len() >= usize(HEADER_SIZE));

        let mut packet: Message<B, Unknown, Invalid> = unsafe { Message::unchecked(buffer) };

        packet.set_type(Type::EchoRequest);
        packet.set_code(0);

        unsafe { Message::unchecked(packet.buffer) }
    }
}

/* EchoReply OR EchoRequest */
impl<B, E, C> Message<B, E, C>
where
    B: AsSlice<Element = u8>,
    E: Echo,
{
    /* Getters */
    /// Returns the Identifier field of the header
    pub fn get_identifier(&self) -> u16 {
        unsafe { NE::read_u16(&self.as_slice().r(IDENT)) }
    }

    /// Returns the Identifier field of the header
    pub fn get_sequence_number(&self) -> u16 {
        unsafe { NE::read_u16(&self.as_slice().r(SEQ_NO)) }
    }
}

impl<B, E> Message<B, E, Invalid>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
    E: Echo,
{
    /* Setters */
    /// Returns the Identifier field of the header
    pub fn set_identifier(&mut self, ident: u16) {
        NE::write_u16(&mut self.as_mut_slice()[IDENT], ident)
    }

    /// Returns the Identifier field of the header
    pub fn set_sequence_number(&mut self, seq_no: u16) {
        NE::write_u16(&mut self.as_mut_slice()[SEQ_NO], seq_no)
    }
}

/* Unknown */
impl<B> Message<B, Unknown, Valid>
where
    B: AsSlice<Element = u8>,
{
    /* Constructors */
    /// Parses the input bytes into a
    pub fn parse(bytes: B) -> Result<Self, B> {
        if bytes.as_slice().len() < usize(HEADER_SIZE) {
            return Err(bytes);
        }

        let packet: Self = unsafe { Message::unchecked(bytes) };

        if ipv4::verify_checksum(packet.as_bytes()) {
            Ok(packet)
        } else {
            Err(packet.buffer)
        }
    }
}

impl<B> Message<B, Unknown, Invalid>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
{
    /* Setters */
    /// Sets the Type field of the header
    pub fn set_type(&mut self, type_: Type) {
        self.as_mut_slice()[TYPE] = type_.into();
    }

    /// Sets the Code field of the header
    pub fn set_code(&mut self, code: u8) {
        self.as_mut_slice()[CODE] = code;
    }
}

impl<B> Message<B, Unknown, Valid>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
{
    /* Setters */
    /// Sets the Type field of the header
    pub fn set_type(self, type_: Type) -> Message<B, Unknown, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.set_type(type_);
        packet
    }

    /// Sets the Code field of the header
    pub fn set_code(self, code: u8) -> Message<B, Unknown, Invalid> {
        let mut packet = self.invalidate_header_checksum();
        packet.set_code(code);
        packet
    }
}

impl<B, C> Message<B, Unknown, C>
where
    B: AsSlice<Element = u8>,
{
    /// Downcasts this packet with unknown type into a specific type
    pub fn downcast<TYPE>(self) -> Result<Message<B, TYPE, C>, Self>
    where
        Self: TryInto<Message<B, TYPE, C>, Error = Self>,
    {
        self.try_into()
    }
}

impl<B, C> From<Message<B, EchoRequest, C>> for Message<B, EchoReply, Valid>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
{
    fn from(p: Message<B, EchoRequest, C>) -> Self {
        let mut p: Message<B, Unknown, Invalid> = unsafe { Message::unchecked(p.buffer) };
        p.set_type(Type::EchoReply);
        let p: Message<B, EchoReply, Invalid> = unsafe { Message::unchecked(p.buffer) };
        p.update_checksum()
    }
}

impl<B, C> TryFrom<Message<B, Unknown, C>> for Message<B, EchoReply, C>
where
    B: AsSlice<Element = u8>,
{
    type Error = Message<B, Unknown, C>;

    fn try_from(p: Message<B, Unknown, C>) -> Result<Self, Message<B, Unknown, C>> {
        if p.get_type() == Type::EchoReply && p.get_code() == 0 {
            Ok(unsafe { Message::unchecked(p.buffer) })
        } else {
            Err(p)
        }
    }
}

impl<B, C> TryFrom<Message<B, Unknown, C>> for Message<B, EchoRequest, C>
where
    B: AsSlice<Element = u8>,
{
    type Error = Message<B, Unknown, C>;

    fn try_from(p: Message<B, Unknown, C>) -> Result<Self, Message<B, Unknown, C>> {
        if p.get_type() == Type::EchoRequest && p.get_code() == 0 {
            Ok(unsafe { Message::unchecked(p.buffer) })
        } else {
            Err(p)
        }
    }
}

/* TYPE */
impl<B, T, C> Message<B, T, C>
where
    B: AsSlice<Element = u8>,
{
    /* Constructors */
    unsafe fn unchecked(buffer: B) -> Self {
        Message {
            buffer,
            _checksum: PhantomData,
            _type: PhantomData,
        }
    }

    /* Getters */
    /// Returns the Type field of the header
    pub fn get_type(&self) -> Type {
        if typeid!(T == EchoReply) {
            Type::EchoReply
        } else if typeid!(T == EchoRequest) {
            Type::EchoRequest
        } else {
            unsafe { self.as_slice().gu(TYPE).clone().into() }
        }
    }

    /// Returns the Type field of the header
    pub fn get_code(&self) -> u8 {
        if typeid!(T == EchoReply) {
            0
        } else if typeid!(T == EchoRequest) {
            0
        } else {
            unsafe { self.as_slice().gu(CODE).clone() }
        }
    }

    /// View into the payload
    pub fn payload(&self) -> &[u8] {
        unsafe { &self.as_slice().rf(PAYLOAD) }
    }

    /// Returns the length (header + data) of this packet
    pub fn len(&self) -> u16 {
        self.as_slice().len() as u16
    }

    /// Returns the byte representation of this packet
    pub fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }

    /* Private */
    fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    fn get_checksum(&self) -> u16 {
        NE::read_u16(&self.as_slice()[CHECKSUM])
    }
}

impl<B, T, C> Message<B, T, C>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
{
    /* Private */
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }
}

impl<B, T> Message<B, T, Invalid>
where
    B: AsSlice<Element = u8> + AsMutSlice<Element = u8>,
{
    /// Mutable view into the payload
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut_slice()[PAYLOAD]
    }

    /// Updates the Checksum field of the header
    pub fn update_checksum(mut self) -> Message<B, T, Valid> {
        let cksum = ipv4::compute_checksum(&self.as_bytes(), CHECKSUM.start);
        NE::write_u16(&mut self.as_mut_slice()[CHECKSUM], cksum);

        unsafe { Message::unchecked(self.buffer) }
    }
}

impl<B, T> Message<B, T, Valid>
where
    B: AsSlice<Element = u8>,
{
    fn invalidate_header_checksum(self) -> Message<B, T, Invalid> {
        unsafe { Message::unchecked(self.buffer) }
    }
}

impl<B, T, C> Clone for Message<B, T, C>
where
    B: AsSlice<Element = u8> + Clone,
{
    fn clone(&self) -> Self {
        Message {
            buffer: self.buffer.clone(),
            _type: PhantomData,
            _checksum: PhantomData,
        }
    }
}

/// NOTE excludes the payload
impl<B, E, C> fmt::Debug for Message<B, E, C>
where
    B: AsSlice<Element = u8>,
    E: Echo,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("icmp::Message")
            .field("type", &self.get_type())
            .field("code", &self.get_code())
            .field("checksum", &Hex(self.get_checksum()))
            .field("id", &self.get_identifier())
            .field("seq_no", &self.get_sequence_number())
            // .field("payload", &self.payload())
            .finish()
    }
}

impl<B, C> fmt::Debug for Message<B, Unknown, C>
where
    B: AsSlice<Element = u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("icmp::Message")
            .field("type", &self.get_type())
            .field("code", &self.get_code())
            .field("checksum", &Hex(self.get_checksum()))
            // .field("payload", &self.payload())
            .finish()
    }
}

full_range!(
    u8,
    /// ICMP types
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum Type {
        /// Echo Reply
        EchoReply = 0,
        /// Destination Unreachable
        DestinationUnreachable = 3,
        /// Echo Request
        EchoRequest = 8,
    }
);

#[cfg(test)]
mod tests {
    use rand::{self, RngCore};

    use crate::{ether, icmp, ipv4, mac};

    const SIZE: usize = 42;

    const BYTES: [u8; SIZE] = [
        255, 255, 255, 255, 255, 255, // eth: destination
        1, 1, 1, 1, 1, 1, // eth: source
        8, 0,  // eth: type
        69, //ipv4: version & ihl
        0,  // ipv4: DSCP & ECN
        0, 28, // ipv4: total length
        0, 0, // ipv4: identification
        64, 0,  // ipv4: fragments
        64, // ipv4: TTL
        1,  // ipv4: protocol
        185, 110, // ipv4: checksum
        192, 168, 0, 33, // ipv4: source
        192, 168, 0, 1, // ipv4: destination
        8, // icmp: type
        0, // icmp: code
        247, 249, // icmp: checksum
        0, 4, // icmp: identifier
        0, 2, // icmp: sequence number
    ];

    const MAC_SRC: mac::Addr = mac::Addr([0x01; 6]);
    const MAC_DST: mac::Addr = mac::Addr([0xff; 6]);

    const IP_SRC: ipv4::Addr = ipv4::Addr([192, 168, 0, 33]);
    const IP_DST: ipv4::Addr = ipv4::Addr([192, 168, 0, 1]);

    #[test]
    fn construct() {
        // NOTE start with randomized array to make sure we set *everything* correctly
        let mut array: [u8; SIZE] = [0; SIZE];
        rand::thread_rng().fill_bytes(&mut array);

        let mut eth = ether::Frame::new(&mut array[..]);

        eth.set_destination(MAC_DST);
        eth.set_source(MAC_SRC);

        eth.ipv4(|ip| {
            ip.set_destination(IP_DST);
            ip.set_source(IP_SRC);

            ip.echo_request(|icmp| {
                icmp.set_identifier(4);
                icmp.set_sequence_number(2);
            });
        });

        assert_eq!(eth.as_bytes(), &BYTES[..]);
    }

    #[test]
    fn parse() {
        let eth = ether::Frame::parse(&BYTES[..]).unwrap();
        assert_eq!(eth.get_source(), MAC_SRC);
        assert_eq!(eth.get_destination(), MAC_DST);

        let ip = ipv4::Packet::parse(eth.payload()).unwrap();
        assert_eq!(ip.get_destination(), IP_DST);
        assert_eq!(ip.get_source(), IP_SRC);

        let icmp = icmp::Message::parse(ip.payload())
            .unwrap()
            .downcast::<icmp::EchoRequest>()
            .unwrap();

        assert_eq!(icmp.get_identifier(), 4);
        assert_eq!(icmp.get_sequence_number(), 2);
    }
}
