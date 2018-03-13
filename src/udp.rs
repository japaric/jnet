//! UDP: User Datagram Protocol

use core::{fmt, u16};
use core::ops::{Range, RangeFrom};

use byteorder::{ByteOrder, NetworkEndian as NE};
use cast::{usize, u16};

use {coap, Resize};

/* Packet structure */
const SOURCE: Range<usize> = 0..2;
const DESTINATION: Range<usize> = 2..4;
const LENGTH: Range<usize> = 4..6;
const CHECKSUM: Range<usize> = 6..8;
const PAYLOAD: RangeFrom<usize> = 8..;

/// Size of the UDP header
pub const HEADER_SIZE: u16 = PAYLOAD.start as u16;

/// UDP packet
pub struct Packet<BUFFER>
where
    BUFFER: AsRef<[u8]>,
{
    buffer: BUFFER,
}

impl<B> Packet<B>
where
    B: AsRef<[u8]>,
{
    /* Constructors */
    /// Parses the bytes as an UDP packet
    pub fn parse(bytes: B) -> Result<Self, B> {
        let nbytes = bytes.as_ref().len();
        if nbytes < usize(HEADER_SIZE) {
            return Err(bytes);
        }

        let packet = Packet { buffer: bytes };
        let len = packet.get_length();

        if len < HEADER_SIZE || usize(len) > nbytes {
            Err(packet.buffer)
        } else {
            Ok(packet)
        }
    }

    /* Getters */
    /// Returns the Source (port) field of the header
    pub fn get_source(&self) -> u16 {
        NE::read_u16(&self.as_ref()[SOURCE])
    }

    /// Returns the Destination (port) field of the header
    pub fn get_destination(&self) -> u16 {
        NE::read_u16(&self.as_ref()[DESTINATION])
    }

    /// Returns the Length field of the header
    pub fn get_length(&self) -> u16 {
        NE::read_u16(&self.as_ref()[LENGTH])
    }

    fn get_checksum(&self) -> u16 {
        NE::read_u16(&self.as_ref()[CHECKSUM])
    }

    /// Returns the length (header + data) of this packet
    pub fn len(&self) -> u16 {
        self.get_length()
    }

    /* Miscellaneous */
    /// View into the payload
    pub fn payload(&self) -> &[u8] {
        &self.as_ref()[PAYLOAD]
    }

    /// Returns the byte representation of this UDP packet
    pub fn as_bytes(&self) -> &[u8] {
        self.as_ref()
    }

    /* Private */
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }

    fn payload_len(&self) -> u16 {
        self.get_length() - HEADER_SIZE
    }
}

impl<B> Packet<B>
where
    B: AsRef<[u8]> + AsMut<[u8]>,
{
    /* Setters */
    /// Sets the Source (port) field of the header
    pub fn set_source(&mut self, port: u16) {
        NE::write_u16(&mut self.as_mut()[SOURCE], port)
    }

    /// Sets the Destination (port) field of the header
    pub fn set_destination(&mut self, port: u16) {
        NE::write_u16(&mut self.as_mut()[DESTINATION], port)
    }

    unsafe fn set_length(&mut self, len: u16) {
        NE::write_u16(&mut self.as_mut()[LENGTH], len)
    }

    /// Zeroes the Checksum field of the header
    pub fn zero_checksum(&mut self) {
        self.set_checksum(0);
    }

    /// Sets the Destination (port) field of the header
    fn set_checksum(&mut self, checksum: u16) {
        NE::write_u16(&mut self.as_mut()[CHECKSUM], checksum)
    }

    /* Miscellaneous */
    /// Mutable view into the payload
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.as_mut()[PAYLOAD]
    }

    /* Private */
    fn as_mut(&mut self) -> &mut [u8] {
        self.buffer.as_mut()
    }
}

impl<B> Packet<B>
where
    B: AsRef<[u8]> + AsMut<[u8]> + Resize,
{
    /* Constructors */
    /// Transforms the given buffer into an UDP packet
    ///
    /// NOTE The UDP packet will span the whole buffer and the Checksum field will be zeroed.
    ///
    /// # Panics
    ///
    /// This constructor panics if the given `buffer` is not large enough to contain the UDP header.
    pub fn new(mut buffer: B) -> Self {
        assert!(buffer.as_ref().len() >= usize(HEADER_SIZE));

        let len = u16(buffer.as_ref().len()).unwrap_or(u16::MAX);
        buffer.truncate(len);
        let mut packet = Packet { buffer };

        packet.set_checksum(0);
        unsafe { packet.set_length(len) }

        packet
    }

    /* Setters */
    /// Fills the payload with the given data and adjusts the length of the UDP packet
    pub fn set_payload(&mut self, data: &[u8]) {
        let len = u16(data.len()).unwrap();
        assert!(self.payload_len() >= len);

        self.truncate(len);
        self.payload_mut().copy_from_slice(data);
    }

    /* Miscellaneous */
    /// Fills the payload with a CoAP message
    pub fn coap<F>(&mut self, token_length: u8, f: F)
    where
        F: FnOnce(&mut coap::Message<&mut [u8]>),
    {
        let len = {
            let mut coap = coap::Message::new(self.payload_mut(), token_length);
            f(&mut coap);
            coap.len()
        };
        self.truncate(len);
    }

    /// Truncates the *payload* to the specified length
    pub fn truncate(&mut self, len: u16) {
        if len < self.payload_len() {
            let total_len = len + HEADER_SIZE;
            self.buffer.truncate(total_len);
            unsafe { self.set_length(total_len) }
        }
    }
}

/// NOTE excludes the payload
impl<B> fmt::Debug for Packet<B>
where
    B: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("udp::Packet")
            .field("source", &self.get_source())
            .field("destination", &self.get_destination())
            .field("length", &self.get_length())
            .field("checksum", &self.get_checksum())
            // .field("payload", &self.payload())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use rand::{self, Rng};

    use {ether, mac, udp, Buffer, ipv4};

    const SIZE: usize = 56;

    const BYTES: &[u8; SIZE] = &[
        255, 255, 255, 255, 255, 255, // ether: destination
        1, 1, 1, 1, 1, 1, // ether: source
        8, 0, // ether: type
        69, // ipv4: version & IHL
        0, // ipv4: DSCP & ECN
        0, 42, //ipv4: total length
        0, 0, // ipv4: identification
        64, 0, // ipv4: fragment
        64, //ipv4: ttl
        17, //ipv4: protocol
        185, 80, // ipv4: checksum
        192, 168, 0, 33, // ipv4: source
        192, 168, 0, 1,  // ipv4: destination
        0, 0, // udp: source
        5, 57, // udp: destination
        0, 22, // udp: length
        0, 0, // udp: checksum
        72, 101, 108, 108, 111, 44, 32, 119, 111, 114, 108, 100, 33, 10, // udp: payload
    ];

    const MAC_SRC: mac::Addr = mac::Addr([0x01; 6]);
    const MAC_DST: mac::Addr = mac::Addr([0xff; 6]);

    const IP_SRC: ipv4::Addr = ipv4::Addr([192, 168, 0, 33]);
    const IP_DST: ipv4::Addr = ipv4::Addr([192, 168, 0, 1]);

    const UDP_DST: u16 = 1337;

    const MESSAGE: &[u8] = b"Hello, world!\n";

    #[test]
    fn construct() {
        // NOTE start with randomized array to make sure we set *everything* correctly
        let mut array: [u8; SIZE] = [0; SIZE];
        rand::thread_rng().fill_bytes(&mut array);

        let mut eth = ether::Frame::new(Buffer::new(&mut array));

        eth.set_destination(MAC_DST);
        eth.set_source(MAC_SRC);

        eth.ipv4(|ip| {
            ip.set_destination(IP_DST);
            ip.set_source(IP_SRC);

            ip.udp(|udp| {
                udp.set_source(0);
                udp.set_destination(UDP_DST);
                udp.set_payload(MESSAGE);
            });
        });

        assert_eq!(eth.as_bytes(), &BYTES[..]);
    }

    #[test]
    fn new() {
        const SZ: u16 = 128;

        let mut chunk = [0; SZ as usize];
        let buf = Buffer::new(&mut chunk);

        let udp = udp::Packet::new(buf);
        assert_eq!(udp.len(), SZ);
        assert_eq!(udp.get_length(), SZ);
    }

    #[test]
    fn parse() {
        let eth = ether::Frame::parse(&BYTES[..]).unwrap();
        assert_eq!(eth.get_destination(), MAC_DST);
        assert_eq!(eth.get_source(), MAC_SRC);
        assert_eq!(eth.get_type(), ether::Type::Ipv4);

        let ip = ipv4::Packet::parse(eth.payload()).unwrap();
        assert_eq!(ip.get_source(), IP_SRC);
        assert_eq!(ip.get_destination(), IP_DST);

        let udp = udp::Packet::parse(ip.payload()).unwrap();
        assert_eq!(udp.get_source(), 0);
        assert_eq!(udp.get_destination(), UDP_DST);
        assert_eq!(udp.get_length(), MESSAGE.len() as u16 + udp::HEADER_SIZE);
        assert_eq!(udp.payload(), MESSAGE);
    }
}
