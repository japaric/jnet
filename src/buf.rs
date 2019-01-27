use core::u16;

use as_slice::{AsMutSlice, AsSlice};
use cast::{u16, usize};

use traits::Resize;

/// Buffer that owns a (statically sized) chunk of memory and provides a slice view into it
///
/// The main use case for this `Buffer` abstraction is sending parsed frames / packets from one
/// execution context to another.
///
/// Let's say you use `type Chunk = &'static mut [u8; N]` for all your `Buffer`s and that a
/// component of your system is in charge of processing incoming Ethernet frames. These frames have
/// type `ether::Frame<Buffer<Chunk>>`. The task of this component is to classify the incoming
/// frames into ICMP packets or CoAP messages and send them to other components (potentially
/// running in different execution contexts) for further processing.
///
/// The `Buffer` abstraction lets you do this task with zero copying. Due to the layered nature of
/// network packets, for example, the ICMP packet inside an Ethernet frame is simply a slice of the
/// Ethernet frame; `Buffer` lets you perform the slicing operation without losing ownership.
///
/// With code it would look like this:
///
/// ``` ignore
/// fn component_a(frame: ether::Frame<Buffer<Chunk>>) {
///     // ..
///
///     if is_ipv4 {
///         // ..
///
///         if is_icmp {
///             send_to_component_b(ipv4_packet.into_payload());
///         }
///
///         // ..
///
///         if is_udp {
///             // ..
///
///             if is_coap {
///                 send_to_component_c(udp_packet.into_payload());
///             }
///
///             // ..
///         }
///
///         // ..
///     }
///
///     // ..
/// }
///
/// fn component_b(icmp: icmp::Packet<Buffer<Chunk>>) {
///     // ..
/// }
///
/// fn component_c(coap: coap::Message<Buffer<Chunk>>) {
///     // ..
/// }
/// ```
///
/// Or at least that's the idea we are still missing some API to preserve the type of payloads when
/// performing an `into_payload` operation.
///
/// A `Buffer` itself is also cheap to send as its size is the size of a pointer (to a fixed size
/// array) plus two `u16` indices. On 32-bit ARM this is just 8 bytes of data. Most of the `Frame`
/// and `Packet` abstractions in this crate are also just newtypes over buffer so they don't add any
/// runtime metadata; all the metadata needed to differentiate an IPv4 packet from an ICMP packet is
/// stored in the type system.
pub struct Buffer<CHUNK>
where
    CHUNK: AsSlice<Element = u8>,
{
    chunk: CHUNK,
    offset: u16,
    len: u16,
}

impl<C> Buffer<C>
where
    C: AsSlice<Element = u8>,
{
    /// Creates a new buffer from the given chunk of memory
    ///
    /// The `Chunk` trait is currently implemented for `&'a mut [u8]` and `&'a mut [u8; N]` but the
    /// plan is to also implement it for `Box<[u8]>` and `Box<[u8; N]`.
    pub fn new(chunk: C) -> Self {
        let len = u16(chunk.as_slice().len()).unwrap_or(u16::MAX);
        Buffer {
            chunk,
            offset: 0,
            len: len,
        }
    }

    /// Resets the slice view to span the full length of the `Chunk`
    pub fn reset(&mut self) {
        self.offset = 0;
        self.len = self.chunk.as_slice().len() as u16;
    }

    /// Truncates the buffer to the specified length
    pub fn truncate(&mut self, len: u16) {
        Resize::truncate(self, len)
    }

    /// Frees the chunk of memory
    pub fn free(self) -> C {
        self.chunk
    }
}

impl<C> AsSlice for Buffer<C>
where
    C: AsSlice<Element = u8>,
{
    type Element = u8;
    fn as_slice(&self) -> &[u8] {
        let start = usize(self.offset);
        let end = usize(self.offset + self.len);
        &self.chunk.as_slice()[start..end]
    }
}

impl<C> AsMutSlice for Buffer<C>
where
    C: AsMutSlice<Element = u8>,
{
    fn as_mut_slice(&mut self) -> &mut [u8] {
        let start = usize(self.offset);
        let end = usize(self.offset + self.len);
        &mut self.chunk.as_mut_slice()[start..end]
    }
}

impl<C> Resize for Buffer<C>
where
    C: AsSlice<Element = u8>,
{
    fn slice_from(&mut self, offset: u16) {
        assert!(offset <= self.len);

        self.offset += offset;
        self.len -= offset;
    }

    fn truncate(&mut self, len: u16) {
        if self.len > len {
            self.len = len;
        }
    }
}
