//! IEEE 802.15.4
//!
//! # References
//!
//! - [IEEE 802.15.4-2003 standard][standard], Section 7.2.1 General MAC frame format
//!
//! [standard]: https://www.iith.ac.in/~tbr/teaching/docs/802.15.4-2003.pdf

// NOTE(dev) unlike other networking protocol 802.15.4 uses the LITTLE endian byte order

use core::fmt;

use as_slice::{AsMutSlice, AsSlice};
use byteorder::{ByteOrder, NetworkEndian as NE, LE};
use owning_slice::Truncate;

use crate::{
    icmpv6, ipv6,
    sixlowpan::{iphc, nhc},
    traits::UncheckedIndex,
};

/* Frame format (Section 7.2.1) */
// Frame control low byte
const CONTROLL: usize = 0;
mod frame_type {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = 0;
    pub const SIZE: u8 = 3;
}

mod security_enabled {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = super::frame_type::OFFSET + super::frame_type::SIZE;
    pub const SIZE: u8 = 1;
}

mod frame_pending {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = super::security_enabled::OFFSET + super::security_enabled::SIZE;
    pub const SIZE: u8 = 1;
}

mod ack_request {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = super::frame_pending::OFFSET + super::frame_pending::SIZE;
    pub const SIZE: u8 = 1;
}

mod intra_pan {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = super::ack_request::OFFSET + super::ack_request::SIZE;
    pub const SIZE: u8 = 1;
}

// Frame control high byte
const CONTROLH: usize = 1;
mod dest_addr_mode {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = 2;
    pub const SIZE: u8 = 2;
}

mod src_addr_mode {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = 6;
    pub const SIZE: u8 = 2;
}

// Sequence number
const SEQUENCE: usize = 2;

const HEADER_SIZE: u8 = SEQUENCE as u8 + 1;

/// IEEE 802.15.4 MAC frame
#[derive(Clone, Copy)]
pub struct Frame<BUFFER>
where
    BUFFER: AsSlice<Element = u8>,
{
    buffer: BUFFER,
    payload: u8,
}

impl<B> Frame<B>
where
    B: AsSlice<Element = u8>,
{
    /* Constructors */
    /// Parses bytes into an 802.15.4 frame
    pub fn parse(bytes: B) -> Result<Self, B> {
        // validation
        let len = (|| {
            let slice = bytes.as_slice();

            let mut len = 3u8; // length of (Frame control + Sequence number)

            // too small
            if slice.len() < usize::from(len) {
                return Err(());
            }

            let ftype = Type::from(get!(slice[CONTROLL], frame_type));

            let dest_addr_mode =
                AddrMode::checked(get!(slice[CONTROLH], dest_addr_mode)).ok_or(())?;
            let src_addr_mode = AddrMode::checked(get!(slice[CONTROLH], src_addr_mode)).ok_or(())?;

            len += match dest_addr_mode {
                AddrMode::None => {
                    // 7.2.1.1.6 Destination addressing mode subfield
                    //
                    // "If this subfield is equal to 0 and the frame type subfield does not specify
                    // that this frame is an acknowledgment or beacon frame, the source addressing
                    // mode subfield shall be nonzero"
                    if ftype != Type::Acknowledgment || ftype != Type::Beacon {
                        if src_addr_mode == AddrMode::None {
                            return Err(());
                        }
                    }

                    0
                }
                AddrMode::Short => 2,
                AddrMode::Extended => 8,
            };

            len += match src_addr_mode {
                AddrMode::None => {
                    // 7.2.1.1.7 Source addressing mode subfield
                    //
                    // "If this subfield is equal to 0 and the frame type subfield does not specify
                    // that this frame is an acknowledgment frame, the destination addressing mode
                    // subfield shall be nonzero"
                    if ftype != Type::Acknowledgment {
                        if dest_addr_mode == AddrMode::None {
                            return Err(());
                        }
                    }

                    0
                }
                AddrMode::Short => 2,
                AddrMode::Extended => 8,
            };

            // 7.2.1.3 Destination PAN identifier field
            //
            // "This field shall be included in the MAC frame only if the destination addressing
            // mode subfield of the frame control field is nonzero."
            if dest_addr_mode != AddrMode::None {
                len += 2;
            }

            let intra_pan = get!(slice[CONTROLL], intra_pan);

            // 7.2.1.5 Source PAN identifier field
            //
            // "This field shall be included in the MAC frame only if the source addressing mode and
            // intra-PAN subfields of the frame control field are nonzero and equal to zero,
            // respectively."
            if src_addr_mode != AddrMode::None && intra_pan == 0 {
                len += 2;
            }

            if slice.len() < usize::from(len) {
                // too small
                Err(())
            } else {
                Ok(len)
            }
        })();

        if let Ok(len) = len {
            Ok(Frame {
                payload: len,
                buffer: bytes,
            })
        } else {
            Err(bytes)
        }
    }

    /* Accessors */
    /// Reads the 'Frame type' field
    pub fn get_type(&self) -> Type {
        Type::from(get!(self.header_()[CONTROLL], frame_type) & 0b111)
    }

    /// Reads the 'Security enabled' field
    pub fn get_security_enabled(&self) -> bool {
        get!(self.header_()[CONTROLL], security_enabled) == 1
    }

    /// Reads the 'Frame pending' field
    pub fn get_frame_pending(&self) -> bool {
        get!(self.header_()[CONTROLL], frame_pending) == 1
    }

    /// Reads the 'Ack. request' field
    pub fn get_ack_request(&self) -> bool {
        get!(self.header_()[CONTROLL], ack_request) == 1
    }

    /// Reads the 'Intra-PAN' field
    pub fn get_intra_pan(&self) -> bool {
        get!(self.header_()[CONTROLL], intra_pan) == 1
    }

    /// Reads the 'Dest. addressing mode' field
    pub fn get_dest_addr_mode(&self) -> AddrMode {
        unsafe { AddrMode::unchecked(get!(self.header_()[CONTROLH], dest_addr_mode)) }
    }

    /// Reads the 'Source addressing mode' field
    pub fn get_src_addr_mode(&self) -> AddrMode {
        unsafe { AddrMode::unchecked(get!(self.header_()[CONTROLH], src_addr_mode)) }
    }

    /// Reads the 'Sequence number' field
    pub fn get_sequence_number(&self) -> u8 {
        self.header_()[SEQUENCE]
    }

    /// Reads the 'Destination PAN identifier' field
    pub fn get_dest_pan_id(&self) -> Option<PanId> {
        // See 7.2.1.3 Destination PAN identifier field
        if self.get_dest_addr_mode() == AddrMode::None {
            None
        } else {
            Some(PanId(LE::read_u16(unsafe { self.as_slice().r(3..5) })))
        }
    }

    /// Reads the 'Destination address' field
    pub fn get_dest_addr(&self) -> Option<Addr> {
        let mut start = 3;

        if self.get_dest_pan_id().is_some() {
            start += 2;
        }

        Some(match self.get_dest_addr_mode() {
            AddrMode::None => return None,
            AddrMode::Short => Addr::Short(ShortAddr(LE::read_u16(unsafe {
                self.as_slice().r(start..start + 2)
            }))),
            AddrMode::Extended => Addr::Extended(ExtendedAddr(LE::read_u64(unsafe {
                self.as_slice().r(start..start + 8)
            }))),
        })
    }

    /// Reads the 'Source PAN identifier' field
    pub fn get_src_pan_id(&self) -> Option<PanId> {
        if self.get_src_addr_mode() != AddrMode::None && !self.get_intra_pan() {
            let mut start = 3;

            if self.get_dest_pan_id().is_some() {
                start += 2
            }

            start += match self.get_dest_addr_mode() {
                AddrMode::None => 0,
                AddrMode::Short => 2,
                AddrMode::Extended => 8,
            };

            Some(PanId(LE::read_u16(unsafe {
                self.as_slice().r(start..start + 2)
            })))
        } else {
            None
        }
    }

    /// Reads the 'Source address' field
    pub fn get_src_addr(&self) -> Option<Addr> {
        let mut start = 3;

        if self.get_dest_pan_id().is_some() {
            start += 2;
        }

        start += match self.get_dest_addr_mode() {
            AddrMode::None => 0,
            AddrMode::Short => 2,
            AddrMode::Extended => 8,
        };

        if self.get_src_pan_id().is_some() {
            start += 2;
        }

        Some(match self.get_src_addr_mode() {
            AddrMode::None => return None,
            AddrMode::Short => Addr::Short(ShortAddr(LE::read_u16(unsafe {
                self.as_slice().r(start..start + 2)
            }))),
            AddrMode::Extended => Addr::Extended(ExtendedAddr(LE::read_u64(unsafe {
                self.as_slice().r(start..start + 8)
            }))),
        })
    }

    /// Returns an immutable view into the header
    pub fn header(&self) -> &[u8] {
        unsafe { self.as_slice().rt(..usize::from(self.payload)) }
    }

    /// Returns an immutable view into the payload
    pub fn payload(&self) -> &[u8] {
        unsafe { self.as_slice().rf(usize::from(self.payload)..) }
    }

    /// Returns the byte representation of this frame
    pub fn as_bytes(&self) -> &[u8] {
        self.as_slice()
    }

    /* Miscellaneous */
    /// Frees the underlying buffer
    pub fn free(self) -> B {
        self.buffer
    }

    /* Private */
    fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    fn header_(&self) -> &[u8; HEADER_SIZE as usize] {
        debug_assert!(self.as_slice().len() >= HEADER_SIZE as usize);

        unsafe { &*(self.as_slice().as_ptr() as *const _) }
    }
}

impl<B> fmt::Debug for Frame<B>
where
    B: AsSlice<Element = u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::fmt::{Display, Quoted};

        let mut s = f.debug_struct("ieee802154::Frame");
        s.field("type", &self.get_type())
            .field("security_enabled", &self.get_security_enabled())
            .field("frame_pending", &self.get_frame_pending())
            .field("ack_request", &self.get_ack_request())
            .field("intra_pan", &self.get_intra_pan())
            .field("dest_addr_mode", &self.get_dest_addr_mode())
            .field("src_addr_mode", &self.get_src_addr_mode())
            .field("sequence_number", &self.get_sequence_number());

        if let Some(pan_id) = self.get_dest_pan_id() {
            s.field("dest_pan_id", &Display(pan_id));
        }
        match self.get_dest_addr() {
            Some(Addr::Short(sa)) => {
                s.field("dest_addr", &Display(sa));
            }
            Some(Addr::Extended(ea)) => {
                s.field("dest_addr", &Quoted(ea));
            }
            None => {}
        }

        if let Some(pan_id) = self.get_src_pan_id() {
            s.field("src_pan_id", &Display(pan_id));
        }
        match self.get_src_addr() {
            Some(Addr::Short(sa)) => {
                s.field("src_addr", &Display(sa));
            }
            Some(Addr::Extended(ea)) => {
                s.field("src_addr", &Quoted(ea));
            }
            _ => {}
        }

        // TODO uncomment
        // s.field("payload", &self.payload());
        s.finish()
    }
}

impl<B> Frame<B>
where
    B: AsMutSlice<Element = u8>,
{
    /* Constructors */
    /// Creates a new data frame from the given buffer
    pub fn data(mut buffer: B, src_dest: SrcDest) -> Self {
        let payload = 3 + src_dest.size();
        assert!(buffer.as_slice().len() >= usize::from(payload));

        // Zero the frame control field and sequence number
        buffer.as_mut_slice()[..3].copy_from_slice(&[0, 0, 0]);
        let mut frame = Frame { buffer, payload };

        frame.set_frame_type(Type::Data);

        match src_dest {
            SrcDest::PanCoordToNode { .. } => unimplemented!(),
            SrcDest::NodeToPanCoord { .. } => unimplemented!(),
            SrcDest::IntraPan {
                pan_id,
                src_addr,
                dest_addr,
            } => {
                frame.set_intra_pan(1);

                let mut start = 3;
                LE::write_u16(&mut frame.as_mut_slice()[start..start + 2], pan_id.0);
                start += 2;

                frame.set_dest_addr_mode(dest_addr.mode());
                match dest_addr {
                    Addr::Short(sa) => {
                        LE::write_u16(&mut frame.as_mut_slice()[start..start + 2], sa.0);
                        start += 2;
                    }
                    Addr::Extended(ea) => {
                        LE::write_u64(&mut frame.as_mut_slice()[start..start + 8], ea.0);
                        start += 8;
                    }
                }

                frame.set_src_addr_mode(src_addr.mode());
                match src_addr {
                    Addr::Short(sa) => {
                        LE::write_u16(&mut frame.as_mut_slice()[start..start + 2], sa.0);
                        // start += 2;
                    }
                    Addr::Extended(ea) => {
                        LE::write_u64(&mut frame.as_mut_slice()[start..start + 8], ea.0);
                        // start += 8;
                    }
                }

                frame
            }
            SrcDest::InterPan { .. } => unimplemented!(),
        }
    }

    /* Setters */
    /// Sets the 'Ack. request' field to `ack`
    pub fn set_ack_request(&mut self, ack: bool) {
        set!(
            self.header_mut_()[CONTROLL],
            ack_request,
            if ack { 1 } else { 0 }
        )
    }

    /// Sets the 'Sequence number' field to `seq`
    pub fn set_sequence_number(&mut self, seq: u8) {
        self.header_mut_()[SEQUENCE] = seq;
    }

    fn set_frame_type(&mut self, ftype: Type) {
        set!(self.header_mut_()[CONTROLL], frame_type, u8::from(ftype))
    }

    fn set_intra_pan(&mut self, ip: u8) {
        set!(self.header_mut_()[CONTROLL], intra_pan, ip)
    }

    fn set_dest_addr_mode(&mut self, am: AddrMode) {
        set!(self.header_mut_()[CONTROLH], dest_addr_mode, u8::from(am))
    }

    fn set_src_addr_mode(&mut self, am: AddrMode) {
        set!(self.header_mut_()[CONTROLH], src_addr_mode, u8::from(am))
    }

    /* Private */
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }

    fn header_mut_(&mut self) -> &mut [u8; HEADER_SIZE as usize] {
        debug_assert!(self.as_slice().len() >= HEADER_SIZE as usize);

        unsafe { &mut *(self.as_mut_slice().as_mut_ptr() as *mut _) }
    }

    fn payload_mut(&mut self) -> &mut [u8] {
        let start = usize::from(self.payload);
        &mut self.as_mut_slice()[start..]
    }
}

impl<B> Frame<B>
where
    B: AsMutSlice<Element = u8> + Truncate<u8>,
{
    /// Fills the payload with the given data and adjusts the length of the frame
    pub fn set_payload(&mut self, payload: &[u8]) {
        assert!(self.payload().len() >= payload.len());

        let plen = payload.len();

        self.payload_mut()[..plen].copy_from_slice(payload);
        self.buffer.truncate(self.payload + plen as u8);
    }

    /// Fills the buffer with an 'Echo Reply' ICMPv6 message
    pub fn echo_reply<F>(&mut self, src: ipv6::Addr, dest: ipv6::Addr, f: F)
    where
        F: FnOnce(&mut icmpv6::Message<&mut [u8], icmpv6::EchoReply>),
    {
        const HOP_LIMIT: u8 = 64;

        let ctxt = iphc::Context {
            source: self.get_src_addr(),
            destination: self.get_dest_addr(),
        };

        let mut packet = iphc::Packet::new(
            self.payload_mut(),
            Some(ipv6::NextHeader::Ipv6Icmp),
            HOP_LIMIT,
            src,
            dest,
            &ctxt,
        );

        let mut message = icmpv6::Message::echo_reply(packet.payload_mut());
        f(&mut message);
        message.update_checksum(src, dest);

        let len = (message.as_bytes().len() + packet.header().len() + self.header().len()) as u8;
        self.buffer.truncate(len);
    }

    /// Fills the payload with a 'Neighbor Advertisement' ICMPv6 message
    pub fn neighbor_advertisement<F>(
        &mut self,
        src: ipv6::Addr,
        dest: ipv6::Addr,
        target_addr: ipv6::Addr,
        target_ll_addr: Option<ExtendedAddr>,
        f: F,
    ) where
        F: FnOnce(&mut icmpv6::Message<&mut [u8], icmpv6::NeighborAdvertisement>),
    {
        const HOP_LIMIT: u8 = 255;

        let ctxt = iphc::Context {
            source: self.get_src_addr(),
            destination: self.get_dest_addr(),
        };

        let mut packet = iphc::Packet::new(
            self.payload_mut(),
            Some(ipv6::NextHeader::Ipv6Icmp),
            HOP_LIMIT,
            src,
            dest,
            &ctxt,
        );

        let mut message = icmpv6::Message::neighbor_advertisement(
            packet.payload_mut(),
            if target_ll_addr.is_some() { 2 } else { 0 },
        );
        f(&mut message);
        message.set_target_addr(target_addr);
        if let Some(target_ll_addr) = target_ll_addr {
            message.set_target_ll_addr(target_ll_addr);
        }
        message.update_checksum(src, dest);

        let len = (message.as_bytes().len() + packet.header().len() + self.header().len()) as u8;
        self.buffer.truncate(len);
    }

    /// Fills the payload with a UDP packet
    pub fn udp<F>(
        &mut self,
        src_addr: ipv6::Addr,
        src_port: u16,
        dest_addr: ipv6::Addr,
        dest_port: u16,
        elide_checksum: bool,
        f: F,
    ) where
        F: FnOnce(&mut nhc::UdpPacket<&mut [u8]>),
    {
        use nhc::UdpPacket;

        const HOP_LIMIT: u8 = 64;

        let ctxt = iphc::Context {
            source: self.get_src_addr(),
            destination: self.get_dest_addr(),
        };

        let mut ip_packet = iphc::Packet::new(
            self.payload_mut(),
            None,
            HOP_LIMIT,
            src_addr,
            dest_addr,
            &ctxt,
        );

        let mut udp_packet =
            UdpPacket::new(ip_packet.payload_mut(), elide_checksum, src_port, dest_port);
        f(&mut udp_packet);
        if !elide_checksum {
            udp_packet.update_checksum(src_addr, dest_addr);
        }

        let len = (udp_packet.bytes().len() + ip_packet.header().len() + self.header().len()) as u8;
        self.buffer.truncate(len);
    }

    // pub fn sixlowpan<F>(&mut self, hop_limit: u8, src: ipv6::Addr, dest: ipv6::Addr, f: F)
    // where
    //     F: FnOnce(&mut sixlowpan::Packet<&mut [u8]>),
    // {
    //     let ctxt = sixlowpan::Context {
    //         source: self.get_src_addr(),
    //         destination: self.get_dest_addr(),
    //     };
    //     let len = self.payload + {
    //         let mut packet =
    //             sixlowpan::Packet::new(self.payload_mut(), hop_limit, src, dest, &ctxt);
    //         f(&mut packet);
    //         packet.bytes().len() as u8
    //     };
    //     self.buffer.truncate(len);
    // }
}

// NOTE `src_addr` can't never be the broadcast address
/// Source and destination address
pub enum SrcDest {
    /// Source: PAN coordinator, Dest: some node in the PAN
    PanCoordToNode {
        /// PAN identifier
        pan_id: PanId,
        /// Address of the destination node
        dest_addr: Addr,
    },
    /// Source: some node, Dest: coordinator of the PAN the node belongs to
    NodeToPanCoord {
        /// PAN identifier
        pan_id: PanId,
        /// Address of the source node
        src_addr: Addr,
    },
    /// Both nodes are in the same PAN
    IntraPan {
        /// PAN identifier
        pan_id: PanId,
        /// Address of the source node
        src_addr: Addr,
        /// Address of the destination node
        dest_addr: Addr,
    },
    /// Nodes are in different PANs
    InterPan {
        /// Identifier of the PAN the source node is in
        src_pan_id: PanId,
        /// Address of the source node
        src_addr: Addr,
        /// Identifier of the PAN the destination node is in
        dest_pan_id: PanId,
        /// Address of the destination node
        dest_addr: Addr,
    },
}

impl SrcDest {
    fn size(&self) -> u8 {
        match *self {
            SrcDest::PanCoordToNode { .. } => unimplemented!(),
            SrcDest::NodeToPanCoord { .. } => unimplemented!(),
            SrcDest::IntraPan {
                src_addr,
                dest_addr,
                ..
            } => 2 + src_addr.size() + dest_addr.size(),
            SrcDest::InterPan {
                src_addr,
                dest_addr,
                ..
            } => 2 + 2 + src_addr.size() + dest_addr.size(),
        }
    }
}

full_range!(
    u8,
    /// Frame type
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum Type {
        /// Beacon frame
        Beacon = 0b000,
        /// Data frame
        Data = 0b001,
        /// Acknowledgment frame
        Acknowledgment = 0b010,
        /// MAC command frame
        MacCommand = 0b011,
    }
);

/// Address mode
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddrMode {
    /// PAN identifier and address field are not present
    None = 0b00,
    /// Address field contains a 16 bit short addres
    Short = 0b10,
    /// Address field contains a 64 bit extended address
    Extended = 0b11,
}

impl AddrMode {
    // Returns `None` if bits equals the reserved value (0b01)
    fn checked(bits: u8) -> Option<Self> {
        Some(match bits & 0b11 {
            0b00 => AddrMode::None,
            0b01 => return None,
            0b10 => AddrMode::Short,
            0b11 => AddrMode::Extended,
            _ => unreachable!(),
        })
    }

    unsafe fn unchecked(bits: u8) -> Self {
        Self::checked(bits).unwrap_or_else(|| debug_unreachable!())
    }
}

impl From<AddrMode> for u8 {
    fn from(am: AddrMode) -> u8 {
        am as u8
    }
}

/// An address, either short or extended
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Addr {
    /// Short address
    Short(ShortAddr),
    /// Extended address
    Extended(ExtendedAddr),
}

impl Addr {
    fn mode(&self) -> AddrMode {
        match *self {
            Addr::Short(_) => AddrMode::Short,
            Addr::Extended(_) => AddrMode::Extended,
        }
    }

    fn size(&self) -> u8 {
        match *self {
            Addr::Short(..) => 2,
            Addr::Extended(..) => 8,
        }
    }
}

/// PAN identifier
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PanId(pub u16);

impl fmt::Display for PanId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#04x}", self.0)
    }
}

impl PanId {
    /// Broadcast identifier
    pub const BROADCAST: PanId = PanId(0xffff);

    /// Is this the broadcast address?
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }
}

/// Short (16-bit) address
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortAddr(pub u16);

impl fmt::Display for ShortAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#04x}", self.0)
    }
}

impl ShortAddr {
    /// Broadcast address
    pub const BROADCAST: ShortAddr = ShortAddr(0xffff);

    /// Is this the broadcast address?
    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }
}

impl From<ShortAddr> for Addr {
    fn from(sa: ShortAddr) -> Addr {
        Addr::Short(sa)
    }
}

/// Extended (64-bit) address
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtendedAddr(pub u64);

impl ExtendedAddr {
    // Network endianness bytes
    /// Serializes the address into an array of bytes using network endianness
    pub fn ne_bytes(&self) -> [u8; 8] {
        let mut bytes = [0; 8];
        NE::write_u64(&mut bytes, self.0);
        bytes
    }

    /// Converts the address into an Extended Unique Identifier (EUI-64)
    pub fn eui_64(&self) -> [u8; 8] {
        let mut bytes = [0; 8];

        NE::write_u64(&mut bytes, self.0);

        // toggle the universal / local bit
        bytes[0] ^= 1 << 1;

        bytes
    }
}

// NOTE printed in BIG (Network) endian representation to match the output of `ip link`
impl fmt::Display for ExtendedAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut is_first = true;

        for byte in self.ne_bytes().iter() {
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

impl From<ExtendedAddr> for Addr {
    fn from(ea: ExtendedAddr) -> Addr {
        Addr::Extended(ea)
    }
}

#[cfg(test)]
mod tests {
    use rand::{self, RngCore};

    use super::{Addr, ExtendedAddr, Frame, PanId, ShortAddr, SrcDest, Type};

    #[test]
    fn data() {
        macro_rules! test {
            ($src:expr, $dest:expr) => {{
                let src: Addr = $src.into();
                let dest: Addr = $dest.into();

                // NOTE start with randomized array to make sure we set *everything* correctly
                let mut buf = [0; 128];
                rand::thread_rng().fill_bytes(&mut buf);
                let mut frame = Frame::data(
                    &mut buf[..],
                    SrcDest::IntraPan {
                        pan_id: PanId(0xbeef),
                        dest_addr: dest,
                        src_addr: src,
                    },
                );
                frame.set_payload(&[]);

                assert_eq!(frame.get_type(), Type::Data);
                assert_eq!(frame.get_security_enabled(), false);
                assert_eq!(frame.get_frame_pending(), false);
                assert_eq!(frame.get_ack_request(), false);
                assert_eq!(frame.get_intra_pan(), true);
                assert_eq!(frame.get_dest_addr_mode(), dest.mode());
                assert_eq!(frame.get_src_addr_mode(), src.mode());
                assert_eq!(frame.get_dest_pan_id(), Some(PanId(0xbeef)));
                assert_eq!(frame.get_dest_addr(), Some(dest));
                assert_eq!(frame.get_src_pan_id(), None);
                assert_eq!(frame.get_src_addr(), Some(src));
                assert_eq!(frame.payload(), &[]);
            }};
        }

        test!(ShortAddr(0x01_02), ShortAddr(0x03_04));

        test!(ShortAddr(0x01_02), ExtendedAddr(0x03_04_05_06_07_08_09_0A));

        test!(ExtendedAddr(0x01_02_03_04_05_06_07_08), ShortAddr(0x09_0A));

        test!(
            ExtendedAddr(0x01_02_03_04_05_06_07_08),
            ExtendedAddr(0x09_0A_0B_0C_0D_0E_0F_10)
        );
    }
}
