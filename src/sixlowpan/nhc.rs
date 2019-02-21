//! LOWPAN_NHC encoding

use as_slice::{AsMutSlice, AsSlice};
use byteorder::{ByteOrder, NetworkEndian as NE};
use owning_slice::Truncate;

use crate::{ipv6, traits::UncheckedIndex};

/* Header format */
const NHC: usize = 0;

mod id {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::c::OFFSET + super::c::SIZE;
    pub const SIZE: usize = 5;
    pub const VALUE: u8 = 0b11110;
}

mod c {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::p::OFFSET + super::p::SIZE;
    pub const SIZE: usize = 1;
}

mod p {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = 0;
    pub const SIZE: usize = 2;
}

/// LOWPAN_NHC compressed UDP packet
pub struct UdpPacket<BUFFER>
where
    BUFFER: AsSlice<Element = u8>,
{
    buffer: BUFFER,
    /// Index at which the payload starts
    payload: u8,
}

impl<B> UdpPacket<B>
where
    B: AsSlice<Element = u8>,
{
    /* Constructors */
    /// Parses the bytes as a LOWPAN_IPHC compressed IPv6 packet
    pub fn parse(buffer: B) -> Result<Self, B> {
        let mut start = 1u8; // NHC

        if buffer.as_slice().len() < usize::from(start) {
            return Err(buffer);
        }

        let mut p = UdpPacket { buffer, payload: 0 };

        // check NHC ID
        if get!(p.header_(), id) != id::VALUE {
            return Err(p.buffer);
        }

        if !p.get_c() {
            start += 2; // checksum
        }

        start += p.ports_size();

        p.payload = start;

        if p.buffer.as_slice().len() < usize::from(start) {
            Err(p.buffer)
        } else {
            Ok(p)
        }
    }

    /* Getters */
    /// Reads the (potentially compressed) 'Source Port' field
    pub fn get_source(&self) -> u16 {
        unsafe {
            match self.get_p() {
                0b00 | 0b01 => NE::read_u16(self.as_slice().r(1..3)),
                0b10 => 0xf000 + u16::from(*self.as_slice().gu(1)),
                0b11 => 0xf0b0 + u16::from(*self.as_slice().gu(1) >> 4),
                _ => unreachable!(),
            }
        }
    }

    /// Reads the (potentially compressed) 'Destination Port' field
    pub fn get_destination(&self) -> u16 {
        unsafe {
            match self.get_p() {
                0b00 => NE::read_u16(self.as_slice().r(3..5)),
                0b01 => 0xf000 + u16::from(*self.as_slice().gu(3)),
                0b10 => NE::read_u16(self.as_slice().r(2..4)),
                0b11 => 0xf0b0 + u16::from(*self.as_slice().gu(1) & 0x0f),
                _ => unreachable!(),
            }
        }
    }

    /// Reads the (potentially compressed) 'Checksum' field
    ///
    /// `None` means that the checksum has been elided by the compressor
    pub fn get_checksum(&self) -> Option<u16> {
        if !self.get_c() {
            let start = usize::from(1 + self.ports_size());
            Some(NE::read_u16(unsafe { self.as_slice().r(start..start + 2) }))
        } else {
            None
        }
    }

    /// Immutable view into the UDP payload
    pub fn payload(&self) -> &[u8] {
        let start = usize::from(self.payload);
        unsafe { self.as_slice().rf(start..) }
    }

    /// Byte representation of this packet
    pub fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    /// Reads the 'Checksum' NHC field
    pub fn get_c(&self) -> bool {
        get!(self.header_(), c) != 0
    }

    /// Reads the 'Ports' NHC field
    pub fn get_p(&self) -> u8 {
        get!(self.header_(), p)
    }

    /// Verifies the 'Checksum' field
    pub fn verify_ipv6_checksum(&self, src: ipv6::Addr, dest: ipv6::Addr) -> bool {
        if let Some(cksum) = self.get_checksum() {
            self.compute_checksum(src, dest) == cksum
        } else {
            true
        }
    }

    /* Private */
    fn ports_size(&self) -> u8 {
        match self.get_p() {
            // source & destination uncompressed
            0b00 => 2 + 2,
            // destination compressed
            0b01 => 2 /* source */ + 1, /* destination */
            // source compressed
            0b10 => 1 /* source */ + 2, /* destination */
            // source and destination compressed
            0b11 => 1,
            _ => unreachable!(),
        }
    }

    fn compute_checksum(&self, src: ipv6::Addr, dest: ipv6::Addr) -> u16 {
        const NEXT_HEADER: u8 = 17;

        let mut sum: u32 = 0;

        /* Pseudo-header */
        for chunk in src.0.chunks_exact(2).chain(dest.0.chunks_exact(2)) {
            sum += u32::from(NE::read_u16(chunk));
        }

        // length in pseudo-header
        // XXX should this be just `as u16`?
        let udp_len = self.payload().len() as u32 + 8;
        sum += udp_len >> 16;
        sum += udp_len & 0xffff;

        sum += u32::from(NEXT_HEADER);

        /* UDP packet */
        sum += u32::from(self.get_source());
        sum += u32::from(self.get_destination());

        // length in UDP header (yes, again)
        sum += udp_len >> 16;
        sum += udp_len & 0xffff;

        for chunk in self.payload().chunks(2) {
            if chunk.len() == 2 {
                sum += u32::from(NE::read_u16(chunk));
            } else {
                sum += u32::from(chunk[0]) << 8;
            }
        }

        // fold carry-over
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }

        !(sum as u16)
    }

    fn header_(&self) -> u8 {
        unsafe { *self.as_slice().gu(NHC) }
    }

    fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }
}

impl<B> UdpPacket<B>
where
    B: AsMutSlice<Element = u8>,
{
    /* Constructors */
    pub(crate) fn new(buffer: B, elide_checksum: bool, source: u16, destination: u16) -> Self {
        // NHC ID
        let mut len = 1;

        // ports
        let p = if source >> 4 == 0xf0b && destination >> 4 == 0xf0b {
            len += 1;

            0b11
        } else if source >> 8 == 0xf0 {
            len += 3;

            0b10
        } else if destination >> 8 == 0xf0 {
            len += 3;

            0b01
        } else {
            len += 4;

            0b00
        };

        // checksum
        let mut payload = len as u8;
        let c = if !elide_checksum {
            len += 2;
            payload += 2;
            0
        } else {
            1
        };

        if buffer.as_slice().len() < len {
            panic!(); // buffer too small
        }

        unsafe {
            let mut up = UdpPacket { buffer, payload };

            // c = 0, p = 0
            *up.as_mut_slice().gum(0) =
                (id::VALUE << id::OFFSET) | (c << c::OFFSET) | (p << p::OFFSET);

            match p {
                0b00 => {
                    NE::write_u16(&mut up.as_mut_slice().rm(1..3), source);
                    NE::write_u16(&mut up.as_mut_slice().rm(3..5), destination);
                }

                0b01 => {
                    NE::write_u16(&mut up.as_mut_slice().rm(1..3), source);
                    *up.as_mut_slice().gum(3) = (destination & 0xff) as u8;
                }

                0b10 => {
                    *up.as_mut_slice().gum(1) = (source & 0xff) as u8;
                    NE::write_u16(&mut up.as_mut_slice().rm(2..4), destination);
                }

                0b11 => {
                    *up.as_mut_slice().gum(1) =
                        (((source & 0x0f) as u8) << 4) + (destination & 0x0f) as u8;
                }

                _ => {} // unreachable
            }

            up
        }
    }

    /// Mutable view into the payload
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let start = usize::from(self.payload);
        unsafe { self.as_mut_slice().rfm(start..) }
    }

    /// Updates the checksum field, if not elided
    pub fn update_checksum(&mut self, src: ipv6::Addr, dest: ipv6::Addr) {
        if !self.get_c() {
            let cksum = self.compute_checksum(src, dest);
            unsafe { self.set_checksum(cksum) }
        }
    }

    /* Private */
    unsafe fn set_checksum(&mut self, cksum: u16) {
        debug_assert!(!self.get_c());

        let start = 1 + usize::from(self.ports_size());
        NE::write_u16(self.as_mut_slice().rm(start..start + 2), cksum);
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }
}

impl<B> UdpPacket<B>
where
    B: AsMutSlice<Element = u8> + Truncate<u8>,
{
    /// Fills the payload with the given data and adjusts the length of the CoAP message
    pub fn set_payload(&mut self, payload: &[u8]) {
        assert!(self.payload().len() >= payload.len());

        let plen = payload.len();

        self.payload_mut()[..plen].copy_from_slice(payload);
        self.buffer.truncate(self.payload + plen as u8);
    }
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::UdpPacket;

    #[test]
    fn new() {
        macro_rules! test {
            ($elide_checksum:expr, $source:expr, $destination:expr) => {{
                let no_cksum = $elide_checksum;
                let s = $source;
                let d = $destination;

                let mut bytes = [0; 128];
                rand::thread_rng().fill_bytes(&mut bytes);

                let mut packet = UdpPacket::new(&mut bytes[..], no_cksum, s, d);
                packet.set_payload(&[]);

                if no_cksum {
                    assert_eq!(packet.get_checksum(), None);
                }
                assert_eq!(packet.get_source(), s);
                assert_eq!(packet.get_destination(), d);
                assert_eq!(packet.payload(), &[]);
            }};
        }

        for elide in &[true, false] {
            // source and destination, both compressed
            test!(*elide, 0xf0b1, 0xf0b2);

            // source compressed
            test!(*elide, 0xf001, 1337);

            // destination compressed
            test!(*elide, 1337, 0xf001);

            // uncompressed ports
            test!(*elide, 1337, 1337);
        }
    }
}
