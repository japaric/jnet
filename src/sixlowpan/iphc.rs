//! LOWPAN_IPHC encoding

use core::fmt;

use as_slice::{AsMutSlice, AsSlice};
use byteorder::{ByteOrder, NetworkEndian as NE};
use owning_slice::Truncate;

use crate::{fmt::Quoted, ieee802154 as ll, ipv6, traits::UncheckedIndex};

/* Header format */
const IPHC0: usize = 0;

mod dispatch {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::tf::OFFSET + super::tf::SIZE;
    pub const SIZE: usize = 3;
    pub const VALUE: u8 = 0b011;
}

mod tf {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::nh::OFFSET + super::nh::SIZE;
    pub const SIZE: usize = 2;
}

mod nh {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::hlim::OFFSET + super::hlim::SIZE;
    pub const SIZE: usize = 1;
}

mod hlim {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = 0;
    pub const SIZE: usize = 2;
}

const IPHC1: usize = 1;

mod cid {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::sac::OFFSET + super::sac::SIZE;
    pub const SIZE: usize = 1;
}

mod sac {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::sam::OFFSET + super::sam::SIZE;
    pub const SIZE: usize = 1;
}

mod sam {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::m::OFFSET + super::m::SIZE;
    pub const SIZE: usize = 2;
}

mod m {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::dac::OFFSET + super::dac::SIZE;
    pub const SIZE: usize = 1;
}

mod dac {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = super::dam::OFFSET + super::dam::SIZE;
    pub const SIZE: usize = 1;
}

mod dam {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: usize = 0;
    pub const SIZE: usize = 2;
}

/// LOWPAN_IPHC compressed IPv6 packet
#[derive(Clone, Copy)]
pub struct Packet<BUFFER>
where
    BUFFER: AsSlice<Element = u8>,
{
    buffer: BUFFER,
    /// Index at which the payload starts
    payload: u8,
}

impl<B> Packet<B>
where
    B: AsSlice<Element = u8>,
{
    /* Constructors */
    /// Parses the bytes as a LOWPAN_IPHC compressed IPv6 packet
    ///
    /// # Notes
    ///
    /// The following field values are currently not supported and treated as errors
    ///
    /// - CID = 1
    /// - SAC = 1 && SAM != 0
    /// - DAC = 1
    ///
    /// Likewise, extension headers are not supported and their presence are treated as errors
    pub fn parse(bytes: B) -> Result<Self, B> {
        // validation
        if let Ok(len) = (|| {
            let slice = bytes.as_slice();

            let mut len = 2;
            if slice.len() < usize::from(len) {
                // too small
                return Err(());
            }

            let header = Packet {
                buffer: slice,
                payload: 0,
            };

            if header.get_dispatch() != dispatch::VALUE {
                return Err(());
            }

            // unsupported modes currently treated as errors
            if header.get_cid()
                || (header.get_sac() && header.get_sam() != 0b00)
                || header.get_dac()
            {
                return Err(());
            }

            // end of IPHC encoding
            len += header.cid_size();

            len += header.tf_size();
            len += header.nh_size();
            len += header.hlim_size();
            len += header.src_addr_size();

            // end of inline IP fields
            len += header.dest_addr_size()?;

            if slice.len() < usize::from(len) {
                // too small
                Err(())
            } else {
                Ok(len)
            }
        })() {
            Ok(Packet {
                buffer: bytes,
                payload: len,
            })
        } else {
            Err(bytes)
        }
    }

    /* Accessors */
    /// Reads the 'Next header' field
    ///
    /// **NOTE**: This returns `None` if the next header is encoded using the LOWPAN_NHC format. In
    /// that case the slice returned by `payload` starts with a LOWPAN_NHC encoding and *must* be
    /// parsed using one of the encoders in the `nhc` module
    pub fn get_next_header(&self) -> Option<ipv6::NextHeader> {
        if self.get_nh() {
            None
        } else {
            let mut start = self.ip_fields_start();
            start += self.tf_size();

            Some(ipv6::NextHeader::from(unsafe {
                *self.as_slice().gu(usize::from(start))
            }))
        }
    }

    /// Reads the (potentially compressed) 'Hop limit' field
    pub fn get_hop_limit(&self) -> u8 {
        match self.get_hlim() {
            0b00 => {
                let mut start = self.ip_fields_start();
                start += self.tf_size();
                start += self.nh_size();

                unsafe { *self.as_slice().gu(usize::from(start)) }
            }
            0b01 => 1,
            0b10 => 64,
            0b11 => 255,
            _ => unreachable!(),
        }
    }

    /// Reads the (potentially compressed) 'Source Address' field
    pub fn get_source(&self) -> Addr {
        let mut start = self.ip_fields_start();
        start += self.tf_size();
        start += self.nh_size();
        start += self.hlim_size();

        let start = usize::from(start);

        match (self.get_sac(), self.get_sam()) {
            (false, 0b00) => Addr::Complete(ipv6::Addr(unsafe {
                *(self.as_slice().as_ptr().add(start) as *const _)
            })),
            (false, 0b01) => {
                let mut bytes = [0; 16];

                // 0..8: link local prefix padded with zeros
                bytes[0] = 0xfe;
                bytes[1] = 0x80;

                // 8..16: in-line
                bytes[8..].copy_from_slice(unsafe { self.as_slice().r(start..start + 8) });

                Addr::Complete(ipv6::Addr(bytes))
            }
            (false, 0b10) => {
                let mut bytes = [0; 16];

                // 0..8: link local prefix padded with zeros
                bytes[0] = 0xfe;
                bytes[1] = 0x80;

                // 8..14 = 0000:00ff:fe00
                bytes[11] = 0xff;
                bytes[12] = 0xfe;

                // 14..16: in-line
                bytes[14..].copy_from_slice(unsafe { self.as_slice().r(start..start + 2) });

                Addr::Complete(ipv6::Addr(bytes))
            }
            (false, 0b11) => Addr::Elided(ElidedAddr { _0: () }),

            (true, 0b00) => Addr::Complete(ipv6::Addr::UNSPECIFIED),

            // reserved combination -- we reject these in `parse`
            (true, _) => unsafe { debug_unreachable!() },

            _ => unreachable!(),
        }
    }

    /// Reads the (potentially compressed) 'Destination Address' field
    pub fn get_destination(&self) -> Addr {
        let mut start = self.ip_fields_start();
        start += self.tf_size();
        start += self.nh_size();
        start += self.hlim_size();
        start += self.src_addr_size();

        let start = usize::from(start);

        match (self.get_m(), self.get_dac(), self.get_dam()) {
            (false, false, 0b00) => Addr::Complete(ipv6::Addr(unsafe {
                *(self.as_slice().as_ptr().add(start) as *const _)
            })),

            (false, false, 0b01) => {
                let mut bytes = [0; 16];

                // 0..8: link local prefix padded with zeros
                bytes[0] = 0xfe;
                bytes[1] = 0x80;

                // 8..16: in-line
                bytes[8..].copy_from_slice(unsafe { self.as_slice().r(start..start + 8) });

                Addr::Complete(ipv6::Addr(bytes))
            }

            (false, false, 0b10) => {
                let mut bytes = [0; 16];

                // 0..8: link local prefix padded with zeros
                bytes[0] = 0xfe;
                bytes[1] = 0x80;

                // 8..14 = 0000:00ff:fe00
                bytes[11] = 0xff;
                bytes[12] = 0xfe;

                // 14..16: in-line
                bytes[14..].copy_from_slice(unsafe { self.as_slice().r(start..start + 2) });

                Addr::Complete(ipv6::Addr(bytes))
            }

            (false, false, 0b11) => Addr::Elided(ElidedAddr { _0: () }),

            (true, false, 0b00) => Addr::Complete(ipv6::Addr(unsafe {
                *(self.as_slice().as_ptr().add(start) as *const _)
            })),

            (true, false, 0b01) => {
                let mut bytes = [0; 16];

                // ffXX::00XX:XXXX:XXXX
                bytes[0] = 0xff;
                bytes[1] = unsafe { *self.as_slice().gu(start) };

                bytes[11..].copy_from_slice(unsafe { self.as_slice().r(start + 1..start + 6) });

                Addr::Complete(ipv6::Addr(bytes))
            }

            (true, false, 0b10) => {
                let mut bytes = [0; 16];

                // ffXX::00XX:XXXX
                bytes[0] = 0xff;
                bytes[1] = unsafe { *self.as_slice().gu(start) };

                bytes[13..].copy_from_slice(unsafe { self.as_slice().r(start + 1..start + 4) });

                Addr::Complete(ipv6::Addr(bytes))
            }

            (true, false, 0b11) => {
                let mut bytes = [0; 16];

                // ff02::00XX
                bytes[0] = 0xff;
                bytes[1] = 0x02;

                bytes[15] = unsafe { *self.as_slice().gu(start) };

                Addr::Complete(ipv6::Addr(bytes))
            }

            // reserved combination -- we reject these in `parse`
            (_, true, _) => unsafe { debug_unreachable!() },

            _ => unreachable!(),
        }
    }

    /// Immutable view into the header
    pub fn header(&self) -> &[u8] {
        unsafe { self.as_slice().rt(..usize::from(self.payload)) }
    }

    /// Immutable view into the payload
    pub fn payload(&self) -> &[u8] {
        unsafe { self.as_slice().rf(usize::from(self.payload)..) }
    }

    /// Byte representation of this packet
    pub fn bytes(&self) -> &[u8] {
        self.as_slice()
    }

    /// Reads the 'Traffic class, Flow label' field
    pub fn get_tf(&self) -> u8 {
        get!(self.header_()[IPHC0], tf)
    }

    /// Reads the 'Next Header field
    pub fn get_nh(&self) -> bool {
        get!(self.header_()[IPHC0], nh) != 0
    }

    /// Reads the 'Hop Limit' field
    pub fn get_hlim(&self) -> u8 {
        get!(self.header_()[IPHC0], hlim)
    }

    /// Reads the 'Context IDentifier extension' field
    pub fn get_cid(&self) -> bool {
        get!(self.header_()[IPHC1], cid) != 0
    }

    /// Reads the 'Source Address Compression' field
    pub fn get_sac(&self) -> bool {
        get!(self.header_()[IPHC1], sac) != 0
    }

    /// Reads the 'Source Address Mode' field
    pub fn get_sam(&self) -> u8 {
        get!(self.header_()[IPHC1], sam)
    }

    /// Reads the 'Multicast compression' field
    pub fn get_m(&self) -> bool {
        get!(self.header_()[IPHC1], m) != 0
    }

    /// Reads the 'Destination Address Compression' field
    pub fn get_dac(&self) -> bool {
        get!(self.header_()[IPHC1], dac) != 0
    }

    /// Reads the 'Destination Address Mode' IPHC field
    pub fn get_dam(&self) -> u8 {
        get!(self.header_()[IPHC1], dam)
    }

    /* Private */
    fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    // Header is at least two bytes long
    fn header_(&self) -> &[u8; 2] {
        debug_assert!(self.buffer.as_slice().len() >= 2);

        unsafe { &*(self.buffer.as_slice().as_ptr() as *const _) }
    }

    fn get_dispatch(&self) -> u8 {
        get!(self.as_slice()[IPHC0], dispatch)
    }

    fn cid_size(&self) -> u8 {
        if self.get_cid() {
            1
        } else {
            0
        }
    }

    fn ip_fields_start(&self) -> u8 {
        2 + self.cid_size()
    }

    fn tf_size(&self) -> u8 {
        match self.get_tf() {
            0b00 => 4,
            0b01 => 3,
            0b10 => 1,
            0b11 => 0,
            _ => unreachable!(),
        }
    }

    fn nh_size(&self) -> u8 {
        if self.get_nh() {
            0
        } else {
            1
        }
    }

    fn hlim_size(&self) -> u8 {
        if self.get_hlim() == 0b00 {
            1
        } else {
            0
        }
    }

    fn src_addr_size(&self) -> u8 {
        match (self.get_sac(), self.get_sam()) {
            (false, 0b00) => 16,
            (false, 0b01) => 8,
            (false, 0b10) => 2,
            (false, 0b11) => 0,

            (true, 0b00) => 0,
            (true, 0b01) => 8,
            (true, 0b10) => 2,
            (true, 0b11) => 0,

            _ => unreachable!(),
        }
    }

    fn dest_addr_size(&self) -> Result<u8, ()> {
        Ok(match (self.get_m(), self.get_dac(), self.get_dam()) {
            (false, false, 0b00) => 16,
            (false, false, 0b01) => 8,
            (false, false, 0b10) => 2,
            (false, false, 0b11) => 0,

            (false, true, 0b00) => return Err(()), // reserved
            (false, true, 0b01) => 8,
            (false, true, 0b10) => 2,
            (false, true, 0b11) => 0,

            (true, false, 0b00) => 16,
            (true, false, 0b01) => 6,
            (true, false, 0b10) => 4,
            (true, false, 0b11) => 1,

            (true, true, 0b00) => 6,
            (true, true, 0b01) => return Err(()), // reserved
            (true, true, 0b10) => return Err(()), // reserved
            (true, true, 0b11) => return Err(()), // reserved

            _ => unreachable!(),
        })
    }
}

impl<B> Packet<B>
where
    B: AsMutSlice<Element = u8>,
{
    #[allow(dead_code)]
    pub(crate) fn new(
        mut buffer: B,
        next_header: Option<ipv6::NextHeader>,
        hop_limit: u8,
        src: ipv6::Addr,
        dest: ipv6::Addr,
        ctxt: &Context,
    ) -> Self {
        let blen = buffer.as_slice().len();
        assert!(blen >= 2);
        // TODO check if this panicking branch gets removed after changing the repr of ExtendedAddr
        assert!(!src.is_multicast());

        // DISPATCH + (TF = 0b11)
        buffer.as_mut_slice()[0] = 0b011_11_0_00;
        buffer.as_mut_slice()[1] = 0b0_0_00_0_0_00;

        let mut packet = Packet { buffer, payload: 0 };
        let mut idx = 2;
        assert!(blen >= idx);

        if let Some(next_header) = next_header {
            packet.as_mut_slice()[idx] = next_header.into();
            idx += 1;
        } else {
            packet.set_nh(1);
        }

        if hop_limit == 255 {
            packet.set_hlim(0b11);
        } else if hop_limit == 64 {
            packet.set_hlim(0b10);
        } else if hop_limit == 1 {
            packet.set_hlim(0b01);
        } else {
            packet.set_hlim(0b00);
            idx += 1;
            assert!(blen >= idx);
            packet.as_mut_slice()[idx - 1] = hop_limit;
        }

        if src.is_unspecified() {
            packet.set_sac(1);
        } else if src.is_link_local() {
            debug_assert!(!packet.get_sac());

            // has a short address been mapped into an EUI-64 address
            if src.0[8..14] == [0, 0, 0, 0xff, 0xfe, 0] {
                if ctxt.source == Some(ll::ShortAddr(NE::read_u16(&src.0[14..])).into()) {
                    // elide the source address
                    packet.set_sam(0b11);
                } else {
                    packet.set_sam(0b10);

                    idx += 2;
                    assert!(blen >= idx);
                    packet.as_mut_slice()[idx - 2..idx].copy_from_slice(&src.0[14..]);
                }
            } else {
                if ctxt
                    .source
                    .map(|addr| match addr {
                        ll::Addr::Extended(ea) => ea.eui_64() == src.0[8..],
                        ll::Addr::Short(_) => false,
                    })
                    .unwrap_or(false)
                {
                    // elide the source address
                    packet.set_sam(0b11);
                } else {
                    packet.set_sam(0b01);

                    idx += 8;
                    assert!(blen >= idx);
                    packet.as_mut_slice()[idx - 8..idx].copy_from_slice(&src.0[8..]);
                }
            }
        } else {
            debug_assert!(!packet.get_sac());
            debug_assert_eq!(packet.get_sam(), 0b00);

            idx += 16;
            assert!(blen >= idx);
            packet.as_mut_slice()[idx - 16..idx].copy_from_slice(&src.0);
        }

        debug_assert!(!packet.get_dac());
        if dest.is_multicast() {
            packet.set_m(1);

            if dest.0[1] == 0x02 && dest.0[2..15] == [0; 13] {
                packet.set_dam(0b11);

                idx += 1;
                assert!(blen >= idx);
                packet.as_mut_slice()[idx - 1] = dest.0[15];
            } else if dest.0[2..13] == [0; 11] {
                packet.set_dam(0b10);

                idx += 4;
                assert!(blen >= idx);
                packet.as_mut_slice()[idx - 4] = dest.0[1];
                packet.as_mut_slice()[idx - 3..idx].copy_from_slice(&dest.0[13..]);
            } else if dest.0[2..11] == [0; 9] {
                packet.set_dam(0b01);

                idx += 6;
                assert!(blen >= idx);
                packet.as_mut_slice()[idx - 6] = dest.0[1];
                packet.as_mut_slice()[idx - 5..idx].copy_from_slice(&dest.0[11..]);
            } else {
                packet.set_dam(0b11);

                idx += 16;
                assert!(blen >= idx);
                packet.as_mut_slice()[idx - 16..idx].copy_from_slice(&dest.0);
            }
        } else {
            debug_assert!(!packet.get_m());

            if dest.is_link_local() {
                // has a short address been mapped into an EUI-64 address
                if dest.0[8..14] == [0, 0, 0, 0xff, 0xfe, 0] {
                    if ctxt.destination == Some(ll::ShortAddr(NE::read_u16(&dest.0[14..])).into()) {
                        // elide the destination address
                        packet.set_dam(0b11);
                    } else {
                        packet.set_dam(0b10);

                        idx += 2;
                        assert!(blen >= usize::from(idx));
                        let uidx = usize::from(idx);
                        packet.as_mut_slice()[uidx - 2..uidx].copy_from_slice(&dest.0[14..]);
                    }
                } else {
                    if ctxt
                        .destination
                        .map(|addr| match addr {
                            ll::Addr::Extended(ea) => ea.eui_64() == dest.0[8..],
                            ll::Addr::Short(_) => false,
                        })
                        .unwrap_or(false)
                    {
                        packet.set_dam(0b11);
                    } else {
                        packet.set_dam(0b01);

                        idx += 8;
                        assert!(blen >= idx);
                        packet.as_mut_slice()[idx - 8..idx].copy_from_slice(&dest.0[8..]);
                    }
                }
            } else {
                packet.set_dam(0b00);

                idx += 16;
                assert!(blen >= idx);
                packet.as_mut_slice()[idx - 16..idx].copy_from_slice(&dest.0);
            }
        }

        packet.payload = idx as u8;
        packet
    }

    /// Mutable view into the payload
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let start = usize::from(self.payload);
        unsafe { self.as_mut_slice().rfm(start..) }
    }

    /* Private */
    fn set_nh(&mut self, nh: u8) {
        set!(self.header_mut_()[IPHC0], nh, nh);
    }

    fn set_hlim(&mut self, hlim: u8) {
        set!(self.header_mut_()[IPHC0], hlim, hlim);
    }

    fn set_sac(&mut self, sac: u8) {
        set!(self.header_mut_()[IPHC1], sac, sac);
    }

    fn set_sam(&mut self, sam: u8) {
        set!(self.header_mut_()[IPHC1], sam, sam);
    }

    fn set_m(&mut self, m: u8) {
        set!(self.header_mut_()[IPHC1], m, m);
    }

    fn set_dam(&mut self, dam: u8) {
        set!(self.header_mut_()[IPHC1], dam, dam);
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }

    fn header_mut_(&mut self) -> &mut [u8; 2] {
        debug_assert!(self.buffer.as_slice().len() >= 2);

        unsafe { &mut *(self.buffer.as_slice().as_ptr() as *mut _) }
    }
}

impl<B> Packet<B>
where
    B: AsMutSlice<Element = u8> + Truncate<u8>,
{
    /// Fills the payload with the given data and adjusts the length of the CoAP message
    pub fn set_payload(&mut self, payload: &[u8]) {
        let plen = payload.len();

        self.payload_mut()[..plen].copy_from_slice(payload);
        self.buffer.truncate(self.payload + plen as u8);
    }
}

impl<B> fmt::Debug for Packet<B>
where
    B: AsSlice<Element = u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Binary(u8);

        impl fmt::Debug for Binary {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "0b{:02b}", self.0)
            }
        }

        fn bool2u8(x: bool) -> u8 {
            if x {
                1
            } else {
                0
            }
        }

        let mut s = f.debug_struct("iphc::Packet");
        s.field("tf", &Binary(self.get_tf()))
            .field("nh", &bool2u8(self.get_nh()))
            .field("hlim", &Binary(self.get_hlim()))
            .field("cid", &bool2u8(self.get_cid()))
            .field("sac", &bool2u8(self.get_sac()))
            .field("sam", &Binary(self.get_sam()))
            .field("m", &bool2u8(self.get_m()))
            .field("dac", &bool2u8(self.get_dac()))
            .field("dam", &Binary(self.get_dam()))
            .field("next_header", &self.get_next_header())
            .field("hop_limit", &self.get_hop_limit());

        match self.get_source() {
            Addr::Complete(addr) => {
                s.field("source", &Quoted(addr));
            }
            Addr::Elided(ea) => {
                s.field("source", &Quoted(ea));
            }
        }

        match self.get_destination() {
            Addr::Complete(addr) => {
                s.field("destination", &Quoted(addr));
            }
            Addr::Elided(ea) => {
                s.field("destination", &Quoted(ea));
            }
        }

        // s.field("payload", &self.payload());
        s.finish()
    }
}

/// Maybe IPHC compressed address
pub enum Addr {
    /// Complete address
    Complete(ipv6::Addr),
    /// Elided address
    Elided(ElidedAddr),
}

/// Fully elided IPv6 address
pub struct ElidedAddr {
    _0: (),
}

impl fmt::Display for ElidedAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fe80::X:X:X:X")
    }
}

impl ElidedAddr {
    /// Complete this elided address using Link-layer information
    pub fn complete<A>(self, ll_addr: A) -> ipv6::Addr
    where
        A: Into<ll::Addr>,
    {
        self.complete_(ll_addr.into())
    }

    fn complete_(self, ll_addr: ll::Addr) -> ipv6::Addr {
        let mut bytes = [0; 16];

        // link-local prefix
        bytes[0] = 0xfe;
        bytes[1] = 0x80;

        match ll_addr {
            ll::Addr::Short(sa) => {
                // map into an EUI-64 address
                bytes[11] = 0xff;
                bytes[12] = 0xfe;

                NE::write_u16(&mut bytes[14..], sa.0);
            }
            ll::Addr::Extended(ea) => bytes[8..].copy_from_slice(&ea.eui_64()),
        }

        ipv6::Addr(bytes)
    }
}

/// IPHC encoding context
pub struct Context {
    /// Source link-layer address
    pub source: Option<ll::Addr>,

    /// Destination link-layer address
    pub destination: Option<ll::Addr>,
}

impl Context {
    /// No context
    pub fn empty() -> Self {
        Context {
            source: None,
            destination: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use as_slice::AsSlice;
    use rand::RngCore;

    use super::{Addr, Context, ElidedAddr, Packet};

    use crate::{ieee802154 as ll, ipv6};

    #[test]
    fn offsets() {
        assert_eq!(super::hlim::OFFSET, 0);
        assert_eq!(super::nh::OFFSET, 2);
        assert_eq!(super::tf::OFFSET, 3);
        assert_eq!(super::dispatch::OFFSET, 5);

        assert_eq!(super::dam::OFFSET, 0);
        assert_eq!(super::dac::OFFSET, 2);
        assert_eq!(super::m::OFFSET, 3);
        assert_eq!(super::sam::OFFSET, 4);
        assert_eq!(super::sac::OFFSET, 6);
        assert_eq!(super::cid::OFFSET, 7);
    }

    #[test]
    fn sanity() {
        let bytes = [
            0b011_11_0_11,   // DISPATCH + TF + NH + HLIM
            0b0_0_11_1_0_01, // CID + SAC + SAM + M + DAC + DAM
            58,
            2,
            1,
            255,
            185,
            243,
            147,
            135, // .. rest of payload elided
        ];

        let packet = Packet::parse(&bytes[..]).unwrap();

        assert_eq!(packet.get_hlim(), 0b11);
        assert!(!packet.get_nh());
        assert_eq!(packet.get_tf(), 0b11);

        assert_eq!(packet.get_dam(), 0b01);
        assert!(!packet.get_dac());
        assert!(packet.get_m());
        assert_eq!(packet.get_sam(), 0b11);
        assert!(!packet.get_sac());
        assert!(!packet.get_cid());
    }

    #[test]
    fn elided_address() {
        let ea = ll::Addr::Extended(ll::ExtendedAddr(0x4e_3c_16_2f_0f_44_47_19));
        let addr = ElidedAddr { _0: () }.complete(ea);

        assert_eq!(
            addr.0,
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x4c, 0x3c, 0x16, 0x2f, 0x0f, 0x44, 0x47, 0x19]
        );
    }

    #[test]
    fn new() {
        let mut bytes = [0; 128];
        rand::thread_rng().fill_bytes(&mut bytes);

        macro_rules! test {
            ($ctxt:expr, $src:expr, $dest:expr, $extra:expr) => {{
                let ctxt = $ctxt;
                let src = $src;
                let dest = $dest;

                let mut bytes = [0; 128];
                rand::thread_rng().fill_bytes(&mut bytes);
                let mut packet = Packet::new(
                    &mut bytes[..],
                    Some(ipv6::NextHeader::Udp),
                    255,
                    src,
                    dest,
                    &ctxt,
                );

                packet.set_payload(&[]);

                {
                    let bytes = packet.bytes();
                    let packet = Packet::parse(bytes).unwrap();

                    assert_eq!(packet.get_hop_limit(), 255);
                    assert_eq!(
                        match packet.get_source() {
                            Addr::Complete(addr) => addr,
                            Addr::Elided(addr) => addr.complete(ctxt.source.unwrap()),
                        },
                        src
                    );
                    assert_eq!(
                        match packet.get_destination() {
                            Addr::Complete(addr) => addr,
                            Addr::Elided(ea) => ea.complete(ctxt.destination.unwrap()),
                        },
                        dest
                    );
                    assert_eq!(packet.payload(), &[]);

                    fn call<F, B>(f: F, packet: &Packet<B>)
                    where
                        F: FnOnce(&Packet<B>),
                        B: AsSlice<Element = u8>,
                    {
                        f(packet)
                    }

                    call($extra, &packet);
                }
            }};
        }

        // uncompressed
        test!(
            Context::empty(),
            ipv6::Addr([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            ipv6::Addr([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            |packet| {
                assert!(!packet.get_sac());
                assert_eq!(packet.get_sam(), 0b00);
                assert!(!packet.get_dac());
                assert!(!packet.get_m());
                assert_eq!(packet.get_dam(), 0b00);
            }
        );

        // link-local compression
        test!(
            Context::empty(),
            ipv6::Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]),
            ipv6::Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 9, 10, 11, 12, 13, 14, 15, 16]),
            |packet| {
                assert!(!packet.get_sac());
                assert_eq!(packet.get_sam(), 0b01);
                assert!(!packet.get_dac());
                assert!(!packet.get_m());
                assert_eq!(packet.get_dam(), 0b01);
            }
        );

        // link-local short addresses
        test!(
            Context::empty(),
            ipv6::Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 1, 2]),
            ipv6::Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 3, 4]),
            |packet| {
                assert!(!packet.get_sac());
                assert_eq!(packet.get_sam(), 0b10);
                assert!(!packet.get_dac());
                assert!(!packet.get_m());
                assert_eq!(packet.get_dam(), 0b10);
            }
        );

        // elided short destination address
        test!(
            Context {
                source: None,
                destination: Some(ll::ShortAddr(0xdead).into()),
            },
            ipv6::Addr::UNSPECIFIED,
            ipv6::Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 0xde, 0xad]),
            |packet| {
                assert!(packet.get_sac());
                assert_eq!(packet.get_sam(), 0b00);
                assert!(!packet.get_dac());
                assert!(!packet.get_m());
                assert_eq!(packet.get_dam(), 0b11);
            }
        );

        // elided extended destination address
        test!(
            Context {
                source: None,
                destination: Some(ll::ExtendedAddr(0x20_18_05_21_23_59_59_01).into()),
            },
            ipv6::Addr::UNSPECIFIED,
            ipv6::Addr([
                0xfe,
                0x80,
                0,
                0,
                0,
                0,
                0,
                0,
                0x20 ^ (1 << 1),
                0x18,
                0x05,
                0x21,
                0x23,
                0x59,
                0x59,
                0x01
            ]),
            |packet| {
                assert!(packet.get_sac());
                assert_eq!(packet.get_sam(), 0b00);
                assert!(!packet.get_dac());
                assert!(!packet.get_m());
                assert_eq!(packet.get_dam(), 0b11);
            }
        );

        // elided short source address
        test!(
            Context {
                source: Some(ll::ShortAddr(0xdead).into()),
                destination: None,
            },
            ipv6::Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xfe, 0, 0xde, 0xad]),
            ipv6::Addr([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            |packet| {
                assert!(!packet.get_sac());
                assert_eq!(packet.get_sam(), 0b11);
                assert!(!packet.get_dac());
                assert!(!packet.get_m());
                assert_eq!(packet.get_dam(), 0b00);
            }
        );

        // elided extended source address
        test!(
            Context {
                source: Some(ll::ExtendedAddr(0x20_18_05_21_23_59_59_01).into()),
                destination: None,
            },
            ipv6::Addr([
                0xfe,
                0x80,
                0,
                0,
                0,
                0,
                0,
                0,
                0x20 ^ (1 << 1),
                0x18,
                0x05,
                0x21,
                0x23,
                0x59,
                0x59,
                0x01
            ]),
            ipv6::Addr([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            |packet| {
                assert!(!packet.get_sac());
                assert_eq!(packet.get_sam(), 0b11);
                assert!(!packet.get_dac());
                assert!(!packet.get_m());
                assert_eq!(packet.get_dam(), 0b00);
            }
        );

        // 8-bit multicast destination
        test!(
            Context::empty(),
            ipv6::Addr::UNSPECIFIED,
            ipv6::Addr([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            |packet| {
                assert!(packet.get_sac());
                assert_eq!(packet.get_sam(), 0b00);
                assert!(!packet.get_dac());
                assert!(packet.get_m());
                assert_eq!(packet.get_dam(), 0b11);
            }
        );

        // 32-bit multicast destination
        test!(
            Context::empty(),
            ipv6::Addr::UNSPECIFIED,
            ipv6::Addr([0xff, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 4]),
            |packet| {
                assert!(packet.get_sac());
                assert_eq!(packet.get_sam(), 0b00);
                assert!(!packet.get_dac());
                assert!(packet.get_m());
                assert_eq!(packet.get_dam(), 0b10);
            }
        );

        // 48-bit multicast destination
        test!(
            Context::empty(),
            ipv6::Addr::UNSPECIFIED,
            ipv6::Addr([0xff, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 4, 5, 6]),
            |packet| {
                assert!(packet.get_sac());
                assert_eq!(packet.get_sam(), 0b00);
                assert!(!packet.get_dac());
                assert!(packet.get_m());
                assert_eq!(packet.get_dam(), 0b01);
            }
        );
    }
}
