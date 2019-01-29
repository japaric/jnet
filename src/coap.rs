//! CoAP: Constrained Application Protocol
//!
//! # References
//!
//! - [RFC 7252: The Constrained Application Protocol (CoAP)][rfc]
//!
//! [rfc]: https://tools.ietf.org/html/rfc7252

use core::{fmt, marker::PhantomData, ops::Range, option::Option as CoreOption, str};

use as_slice::{AsMutSlice, AsSlice};
use byteorder::{ByteOrder, NetworkEndian as NE};
use cast::{u16, u8, usize};
use owning_slice::Truncate;

use crate::traits::{TryFrom, UncheckedIndex};

/// CoAP default UDP port
pub const PORT: u16 = 5683;

/* Message format */
const VER_T_TKL: usize = 0;
mod tkl {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = 0;
    pub const SIZE: u8 = 4;
}

mod t {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = super::tkl::OFFSET + super::tkl::SIZE;
    pub const SIZE: u8 = 2;
}

mod ver {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = super::t::OFFSET + super::t::SIZE;
    pub const SIZE: u8 = 2;
}

const CODE: usize = 1;
const MESSAGE_ID: Range<usize> = 2..4;
const TOKEN_START: usize = MESSAGE_ID.end;

// Option header
mod length {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = 0;
    pub const SIZE: u8 = 4;
}

mod delta {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = super::length::OFFSET + super::length::SIZE;
    pub const SIZE: u8 = 4;
}

/// Size of a CoAP header
pub const HEADER_SIZE: u8 = MESSAGE_ID.end as u8;

/* Option parsing */
// This marks the end of the options
const PAYLOAD_MARKER: u8 = 0xff;

// The option delta and option length nibbles can't never be this value
const RESERVED: u8 = 0b1111;

// Offset to add to the option delta / length when they are larger than a nibble
const OFFSET8: u16 = 13;
const OFFSET16: u16 = 269;

// Option delta is an 8-bit unsigned integer
const DELTA8: u8 = 13;

// Option delta is a 16-bit unsigned integer
const DELTA16: u8 = 14;

// Option length is an 8-bit unsigned integer
const LENGTH8: u8 = 13;

// Option length is a 16-bit unsigned integer
const LENGTH16: u8 = 14;

/* Transmission parameters */
// const ACK_TIMEOUT: u16 = 2_000; // ms
// const ACK_RANDOM_FACTOR: f32 = 1.5;
// const MAX_RETRANSMIT: u8 = 4;
// const NSTART: u8 = 1;
// const DEFAULT_LEISURE: u16 = 5_000; // ms
// const PROBING_RATE: u8 = 1; // byte / second

/// CoAP (version 1) message
// NOTE Invariants
// - Options are always valid. For example, this means that the reserved bit pattern (0b1111)
//   doesn't appear in the Option Length nibble. It also means that options are not truncated so
//   they'll always be terminated by the `PAYLOAD_MARKER`, if there's a payload, or by the end of
//   the slice, if there's no payload.
pub struct Message<BUFFER, PAYLOAD = Set>
where
    BUFFER: AsSlice<Element = u8>,
    PAYLOAD: 'static,
{
    _payload: PhantomData<PAYLOAD>,
    buffer: BUFFER,
    // Position of the `PAYLOAD_MARKER`. Cached to avoid traversing the options (O(N) runtime) when
    // the payload is requested. `NO_PAYLOAD` indicates that there is no payload
    // When PAYLOAD is `Unset` this is used to track where the marker *would be*, but that spot in
    // the buffer is not yet set to `PAYLOAD_MARKER`
    marker: u16,
    /// Highest option number stored in the Options field
    number: u16,
}

// Special value
const NO_PAYLOAD: u16 = 0;

/// Payload has been set
pub enum Set {}

/// Payload has not been set yet
pub enum Unset {}

impl<B, P> Message<B, P>
where
    B: AsSlice<Element = u8>,
{
    /* Getters */
    /// Returns the Version field of the header
    ///
    /// As per RFC 7252 this always returns 1
    pub fn get_version(&self) -> u8 {
        debug_assert_eq!(get!(self.header()[VER_T_TKL], ver), 1);

        1
    }

    /// Returns the Type field of the header
    pub fn get_type(&self) -> Type {
        Type::from(get!(self.header()[VER_T_TKL], t))
    }

    /// Returns the Token Length (TKL) field of the header
    ///
    /// As per RFC 7252 this always returns a value in the range `0..=8`
    pub fn get_token_length(&self) -> u8 {
        get!(self.header()[VER_T_TKL], tkl)
    }

    /// Returns the Code field of the header
    pub fn get_code(&self) -> Code {
        Code(self.header()[CODE])
    }

    /// Returns the Message ID field of the header
    pub fn get_message_id(&self) -> u16 {
        NE::read_u16(&self.header()[MESSAGE_ID])
    }

    /// View into the Token field of the header
    pub fn token(&self) -> &[u8] {
        let start = TOKEN_START;
        let end = start + self.get_token_length() as usize;
        unsafe { self.as_slice().r(start..end) }
    }

    /// Returns the byte representation of this message
    pub fn as_bytes(&self) -> &[u8] {
        if typeid!(P == Unset) {
            unsafe { self.buffer.as_slice().rt(..usize(self.marker)) }
        } else {
            self.buffer.as_slice()
        }
    }

    /// Returns the length (header + data) of the CoAP message
    pub fn len(&self) -> u16 {
        u16(self.as_bytes().len()).unwrap()
    }

    /// Returns an iterator over the options of this message
    pub fn options(&self) -> Options<'_> {
        let end = if self.marker != NO_PAYLOAD {
            usize(self.marker)
        } else {
            self.as_slice().len()
        };

        Options {
            number: 0,
            ptr: unsafe { self.as_slice().r(usize(self.options_start())..end) },
        }
    }

    /* Private */
    fn as_slice(&self) -> &[u8] {
        self.buffer.as_slice()
    }

    fn header(&self) -> &[u8; HEADER_SIZE as usize] {
        debug_assert!(self.as_slice().len() >= HEADER_SIZE as usize);

        unsafe { &*(self.as_slice().as_ptr() as *const _) }
    }

    /// Returns the index at which the options start
    fn options_start(&self) -> u8 {
        HEADER_SIZE + self.get_token_length()
    }

    unsafe fn unchecked(buffer: B) -> Self {
        Message {
            _payload: PhantomData,
            buffer,
            marker: NO_PAYLOAD,
            number: 0,
        }
    }
}

impl<B, P> Message<B, P>
where
    B: AsMutSlice<Element = u8>,
{
    /* Setters */
    /// Sets the Code field of the header
    pub fn set_code<C>(&mut self, code: C)
    where
        C: Into<Code>,
    {
        self.header_mut()[CODE] = code.into().0;
    }

    /// Sets the Message ID field of the header
    pub fn set_message_id(&mut self, id: u16) {
        NE::write_u16(&mut self.header_mut()[MESSAGE_ID], id)
    }

    /// Sets the Type field of the header
    pub fn set_type(&mut self, ty: Type) {
        let ty: u8 = ty.into();
        set!(self.header_mut()[VER_T_TKL], t, ty);
    }

    /// Mutable view into the Token field
    pub fn token_mut(&mut self) -> &mut [u8] {
        let start = TOKEN_START;
        let end = start + self.get_token_length() as usize;
        unsafe { self.as_mut_slice().rm(start..end) }
    }

    /* Private */
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }

    fn header_mut(&mut self) -> &mut [u8; HEADER_SIZE as usize] {
        debug_assert!(self.as_slice().len() >= HEADER_SIZE as usize);

        unsafe { &mut *(self.as_mut_slice().as_mut_ptr() as *mut _) }
    }

    unsafe fn set_token_length(&mut self, tkl: u8) {
        debug_assert!(tkl <= 8);

        set!(self.as_mut_slice()[VER_T_TKL], tkl, tkl);
    }

    unsafe fn set_version(&mut self, ver: u8) {
        set!(self.as_mut_slice()[VER_T_TKL], ver, ver);
    }
}

impl<B> Message<B, Set>
where
    B: AsSlice<Element = u8>,
{
    /* Public constructors */
    /// Parses bytes into a CoAP message
    pub fn parse(bytes: B) -> Result<Self, B> {
        let len = bytes.as_slice().len();

        if len < usize(HEADER_SIZE) {
            // smaller than header
            return Err(bytes);
        }

        let m = unsafe { Message::<B, Set>::unchecked(bytes) };
        let tkl = m.get_token_length();
        let bytes = m.buffer;

        let opts_start = HEADER_SIZE + tkl;
        if len < usize(opts_start) {
            // smaller than header + token
            return Err(bytes);
        }

        // Scans the slice for options
        //
        // Returns the highest option number and the index of the PAYLOAD_MARKER
        fn scan(bytes: &[u8]) -> Result<(u16, CoreOption<u16>), ()> {
            let len = bytes.len();
            let mut cursor = 0;
            let mut number = 0;

            let marker = loop {
                let head = *match bytes.as_slice().get(usize(cursor)) {
                    Some(b) => b,
                    // end of packet -- no payload marker was found
                    None => break None,
                };

                if head == PAYLOAD_MARKER {
                    // end of options
                    break Some(cursor);
                }
                cursor += 1;

                let delta4 = get!(head, delta);
                let len4 = get!(head, length);

                if delta4 == DELTA8 {
                    let byte = *bytes.as_slice().get(usize(cursor)).ok_or(())?;
                    cursor += 1;

                    number += u16(byte) + OFFSET8;
                } else if delta4 == DELTA16 {
                    if len < usize(cursor) + 1 {
                        return Err(());
                    }

                    let halfword = unsafe {
                        NE::read_u16(
                            &*(bytes.as_slice().as_ptr().add(usize(cursor)) as *const [u8; 2]),
                        )
                    };
                    cursor += 2;

                    number += halfword + OFFSET16;
                } else if delta4 == RESERVED {
                    return Err(());
                } else {
                    number += u16(delta4);
                }

                if len4 == LENGTH8 {
                    let byte = *bytes.as_slice().get(usize(cursor)).ok_or(())?;
                    cursor += 1;

                    cursor += u16(byte) + OFFSET8;
                } else if len4 == LENGTH16 {
                    if len < usize(cursor) + 1 {
                        return Err(());
                    }

                    let halfword = unsafe {
                        NE::read_u16(
                            &*(bytes.as_slice().as_ptr().add(usize(cursor)) as *const [u8; 2]),
                        )
                    };
                    cursor += 2;

                    cursor += halfword + OFFSET16;
                } else if len4 == RESERVED {
                    return Err(());
                } else {
                    cursor += u16(len4);
                }
            };

            Ok((number, marker))
        }

        if let Ok((number, marker)) = unsafe { scan(bytes.as_slice().rf(usize(opts_start)..)) } {
            Ok(Message {
                _payload: PhantomData,
                buffer: bytes,
                number,
                marker: marker.unwrap_or(NO_PAYLOAD),
            })
        } else {
            Err(bytes)
        }
    }

    /// View into the payload
    pub fn payload(&self) -> &[u8] {
        if self.marker == NO_PAYLOAD {
            &[]
        } else {
            unsafe { &self.as_slice().rf(usize(self.marker + 1)..) }
        }
    }
}

impl<B> Message<B, Set>
where
    B: AsMutSlice<Element = u8>,
{
    /// Mutable view into the payload
    pub fn payload_mut(&mut self) -> &mut [u8] {
        if self.marker == NO_PAYLOAD {
            &mut []
        } else {
            let start = self.marker + 1;
            unsafe { self.as_mut_slice().rfm(usize(start)..) }
        }
    }
}

impl<B> Message<B, Unset>
where
    B: AsMutSlice<Element = u8>,
{
    /* Constructors */
    /// Transforms the given buffer into a CoAP message
    ///
    /// This constructor sets the following header fields
    ///
    /// - Version = 1
    /// - Token Length = token_length
    ///
    /// NOTE The CoAP message will span the whole buffer.
    ///
    /// # Panics
    ///
    /// This constructor panics if
    ///
    /// - `token_length` is NOT in the range `0..=8`.
    /// - The buffer is not large enough to contain the CoAP header
    pub fn new(buffer: B, token_length: u8) -> Self {
        assert!(token_length <= 8);
        let len = buffer.as_slice().len();
        let marker = u16(HEADER_SIZE + token_length);
        assert!(len >= usize(marker));

        unsafe {
            let mut m = Message::unchecked(buffer);
            m.set_version(1);
            m.set_token_length(token_length);
            m.marker = marker;
            m
        }
    }

    /// Adds an option to this message
    ///
    /// *HEADS UP* This method will cause the first bytes of the payload to be lost
    ///
    /// # Panics
    ///
    /// This method panics
    ///
    /// - if `number` is smaller than the highest option number already contained in the message
    /// - if there's no space in the message to add the option
    pub fn add_option(&mut self, number: OptionNumber, value: &[u8]) {
        /// Number of bytes required to encode `x`
        fn nbytes(x: u16) -> u16 {
            if x < OFFSET8 {
                0 // 0.5 actually; this fits in a nibble
            } else if x < OFFSET16 {
                1
            } else {
                2
            }
        }

        // we can only add options that have an equal or a higher option number
        let nr: u16 = number.into();
        let delta = nr.checked_sub(self.number).unwrap();

        let len = u16(value.len()).unwrap();
        let sz = 1 + nbytes(delta) + nbytes(len) + len;

        let start = usize(self.marker);
        let mut cursor = start + 1;

        // update the cached highest number
        self.number = nr;

        // move the payload marker
        self.marker += sz;
        let end = usize(self.marker);

        // fill in the delta
        if delta < OFFSET8 {
            set!(self.as_mut_slice()[start], delta, u8(delta).unwrap());
        } else if delta < OFFSET16 {
            set!(self.as_mut_slice()[start], delta, DELTA8);
            self.as_mut_slice()[cursor] = u8(delta - OFFSET8).unwrap();
            cursor += 1;
        } else {
            set!(self.as_mut_slice()[start], delta, DELTA16);
            NE::write_u16(
                &mut self.as_mut_slice()[cursor..cursor + 2],
                delta - OFFSET16,
            );
            cursor += 2;
        }

        // fill in the length
        if len < OFFSET8 {
            set!(self.as_mut_slice()[start], length, u8(len).unwrap());
        } else if len < OFFSET16 {
            set!(self.as_mut_slice()[start], length, LENGTH8);
            self.as_mut_slice()[cursor] = u8(len - OFFSET8).unwrap();
            cursor += 1;
        } else {
            set!(self.as_mut_slice()[start], length, LENGTH16);
            NE::write_u16(&mut self.as_mut_slice()[cursor..cursor + 2], len - OFFSET16);
            cursor += 2;
        }

        // fill in the value
        self.as_mut_slice()[cursor..end].copy_from_slice(value);
    }

    /// Removes all the options this message has
    pub fn clear_options(&mut self) {
        self.number = 0;
        self.marker = u16(self.options_start());
    }
}

impl<B> Message<B, Unset>
where
    B: AsMutSlice<Element = u8> + Truncate<u16>,
{
    /// Fills the payload with the given data and adjusts the length of the CoAP message
    pub fn set_payload(mut self, data: &[u8]) -> Message<B> {
        let mut start = self.marker;
        let len = if !data.is_empty() {
            // add `PAYLOAD_MARKER`
            self.buffer.as_mut_slice()[usize(start)] = PAYLOAD_MARKER;
            start += 1;

            // now add the payload
            let end = start + u16(data.len()).unwrap();
            self.buffer.as_mut_slice()[usize(start)..usize(end)].copy_from_slice(data);
            end
        } else {
            self.marker = NO_PAYLOAD;
            start
        };

        // finally, resize the buffer
        self.buffer.truncate(len);

        Message {
            _payload: PhantomData,
            buffer: self.buffer,
            marker: self.marker,
            number: self.number,
        }
    }
}

// impl<B> Message<B>
// where
//     B: AsSlice<Element = u8>,
// {
//     /* Private */
//     fn payload_len(&self) -> u16 {
//         self.payload_marker
//             .map(|pos| {
//                 // sanity check
//                 debug_assert_eq!(self.as_slice()[pos], PAYLOAD_MARKER);

//                 u16(self.as_slice().len() - pos - 1).unwrap()
//             })
//             .unwrap_or(0)
//     }

// }

// impl<B> Message<B>
// where
//     B: AsSlice<Element = u8> + Resize,
// {
//     /// Truncates the *payload* to the specified length
//     pub fn truncate(&mut self, len: u16) {
//         let old_len = self.payload_len();
//         let start = self.payload_marker;

//         if len < old_len {
//             self.buffer.truncate(start + len + 1)
//         }
//     }
// }

// impl<B> Message<B>
// where
//     B: AsSlice<Element = u8> + AsMutSlice<Element = u8> + Resize,
// {
//     /// Fills the payload with the given data and adjusts the length of the CoAP message
//     pub fn set_payload(&mut self, data: &[u8]) {
//         let len = u16(data.len()).unwrap();
//         assert!(self.payload_len() >= len);

//         self.truncate(len);
//         self.payload_mut().copy_from_slice(data);
//     }
// }

impl<B, P> fmt::Debug for Message<B, P>
where
    B: AsSlice<Element = u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Adapter to format the `Options` iterator as a map
        struct Options<'a, B, P>(&'a Message<B, P>)
        where
            B: AsSlice<Element = u8>,
            P: 'static;
        impl<'a, B, P> fmt::Debug for Options<'a, B, P>
        where
            B: AsSlice<Element = u8>,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut m = f.debug_map();
                for opt in self.0.options() {
                    if let Ok(s) = str::from_utf8(opt.value()) {
                        m.entry(&opt.number(), &s);
                    } else {
                        m.entry(&opt.number(), &opt.value());
                    }
                }
                m.finish()
            }
        }

        struct Prefix<'a, T>(&'a str, T)
        where
            T: fmt::Debug;

        impl<'a, T> fmt::Debug for Prefix<'a, T>
        where
            T: fmt::Debug,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}{:?}", self.0, self.1)
            }
        }

        let mut s = f.debug_struct("coap::Message");
        s.field("version", &self.get_version())
            .field("type", &self.get_type());

        let code = self.get_code();
        if let Ok(method) = Method::try_from(code) {
            s.field("code", &Prefix("Method::", method));
        } else if let Ok(resp) = Response::try_from(code) {
            s.field("code", &Prefix("Response::", resp));
        } else {
            s.field("code", &code);
        }

        s.field("message_id", &self.get_message_id());

        if self.token().len() != 0 {
            s.field("token", &self.token());
        }

        if self.options().count() != 0 {
            s.field("options", &Options(self));
        }

        if typeid!(P == Set) {
            if self.marker != NO_PAYLOAD {
                let payload = unsafe { &self.as_slice().rf(usize(self.marker + 1)..) };

                if let Ok(p) = str::from_utf8(payload) {
                    s.field("payload", &p);
                } else {
                    s.field("payload", &payload);
                }
            }
        }

        s.finish()
    }
}

/// A CoAP option
pub struct Option<'a> {
    number: u16,
    value: &'a [u8],
}

impl<'a> Option<'a> {
    /// Returns the number of this option
    pub fn number(&self) -> OptionNumber {
        self.number.into()
    }

    /// Returns the value of this option
    pub fn value(&self) -> &'a [u8] {
        self.value
    }
}

/// Iterator over the options of a CoAP message
pub struct Options<'a> {
    /// Number of the previous option
    number: u16,
    ptr: &'a [u8],
}

// Helper
struct PtrReader<'a>(&'a [u8]);

impl<'a> PtrReader<'a> {
    fn try_read_u8(&mut self) -> ::core::option::Option<u8> {
        if self.0.len() > 0 {
            Some(unsafe { self.read_u8() })
        } else {
            None
        }
    }

    unsafe fn read_u8(&mut self) -> u8 {
        let byte = *self.0.gu(0);
        self.0 = self.0.rf(1..);
        byte
    }

    unsafe fn read_u16(&mut self) -> u16 {
        let halfword = NE::read_u16(self.0.rt(..2));
        self.0 = self.0.rf(2..);
        halfword
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = Option<'a>;

    fn next(&mut self) -> CoreOption<Option<'a>> {
        let mut ptr = PtrReader(self.ptr);

        let head = ptr.try_read_u8()?;
        if head == PAYLOAD_MARKER {
            None
        } else {
            let delta4 = get!(head, delta);
            let len4 = get!(head, length);

            // Sanity check `Message` invariants
            debug_assert!(delta4 != RESERVED);
            debug_assert!(len4 != RESERVED);

            self.number += if delta4 == DELTA8 {
                u16(unsafe { ptr.read_u8() }) + OFFSET8
            } else if delta4 == DELTA16 {
                unsafe { ptr.read_u16() + OFFSET16 }
            } else {
                u16(delta4)
            };

            let len = if len4 == LENGTH8 {
                u16(unsafe { ptr.read_u8() }) + OFFSET8
            } else if len4 == LENGTH16 {
                unsafe { ptr.read_u16() + OFFSET16 }
            } else {
                u16(len4)
            };

            // move pointer by `len` for the next iteration
            let value = unsafe { ptr.0.rt(..usize(len)) };
            self.ptr = unsafe { ptr.0.rf(usize(len)..) };

            Some(Option {
                number: self.number,
                value: value,
            })
        }
    }
}

/// CoAP Type
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Type {
    /// Confirmable message
    Confirmable,
    /// Non-confirmable message
    NonConfirmable,
    /// Acknowledgement message
    Acknowledgement,
    /// Reset message
    Reset,
}

impl Type {
    fn from(nibble: u8) -> Self {
        match nibble & 0b11 {
            0b00 => Type::Confirmable,
            0b01 => Type::NonConfirmable,
            0b10 => Type::Acknowledgement,
            0b11 => Type::Reset,
            _ => unreachable!(),
        }
    }
}

impl Into<u8> for Type {
    fn into(self) -> u8 {
        match self {
            Type::Confirmable => 0,
            Type::NonConfirmable => 1,
            Type::Acknowledgement => 2,
            Type::Reset => 3,
        }
    }
}

/// CoAP Code
#[derive(Clone, Copy, PartialEq)]
pub struct Code(u8);

mod detail {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = 0;
    pub const SIZE: u8 = 5;
}

mod class {
    pub const MASK: u8 = (1 << SIZE) - 1;
    pub const OFFSET: u8 = 5;
    pub const SIZE: u8 = 3;
}

impl Code {
    /// Empty message
    pub const EMPTY: Self = Code(0b000_00000);

    /// Returns the class of this code
    pub fn class(&self) -> u8 {
        get!(self.0, class)
    }

    /// Returns the detail of this code
    pub fn detail(&self) -> u8 {
        get!(self.0, detail)
    }

    /// Checks if this is a request code
    pub fn is_request(&self) -> bool {
        self.class() == 0 && self.detail() != 0
    }

    /// Checks if this is a reponse code
    pub fn is_response(&self) -> bool {
        match self.class() {
            2..=5 => true,
            _ => false,
        }
    }

    /* Private */
    fn from_parts(class: u8, detail: u8) -> Self {
        let mut code = 0;
        set!(code, class, class);
        set!(code, detail, detail);

        Code(code)
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Code(0b{:03b}_{:05b})", self.class(), self.detail())
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:02}", self.class(), self.detail())
    }
}

code!(
    /// CoAP Method Codes
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum Method {
        /// GET
        Get = (0, 1),
        /// POST
        Post = (0, 2),
        /// PUT
        Put = (0, 3),
        /// DELETE
        Delete = (0, 4),
    }
);

code!(
    /// CoAP Response Codes
    #[derive(Clone, Copy, Debug, PartialEq)]
    pub enum Response {
        // Success
        /// Created
        Created = (2, 1),
        /// Deleted
        Deleted = (2, 2),
        /// Valid
        Valid = (2, 3),
        /// Changed
        Changed = (2, 4),
        /// Content
        Content = (2, 5),

        // Client error
        /// Bad Request
        BadRequest = (4, 0),
        /// Unauthorized
        Unauthorized = (4, 1),
        /// Bad Option
        BadOption = (4, 2),
        /// Forbidden
        Forbidden = (4, 3),
        /// Not Found
        NotFound = (4, 4),
        /// Method Not Allowed
        MethodNotAllowed = (4, 5),
        /// Not Acceptable
        NotAcceptable = (4, 6),
        /// Precondition Failed
        PreconditionFailed = (4, 12),
        /// Request Entity Too Large
        RequestEntityTooLarge = (4, 13),
        /// Unsupported Content-Format
        UnsupportedContentFormat = (4, 15),

        // Server error
        /// Internal Server Error
        InternalServerError = (5, 0),
        /// Not Implemented
        NotImplemented = (5, 1),
        /// Bad Gateway
        BadGateway = (5, 2),
        /// Service Unavailable
        ServiceUnavailable = (5, 3),
        /// Gateway Timeout
        GatewayTimeout = (5, 4),
        /// Proxying Not Supported
        ProxyingNotSupported = (5, 5),
    }
);

full_range!(
    u16,
    /// CoAP Option Numbers
    #[derive(Clone, Copy, Debug, PartialEq, PartialOrd)]
    pub enum OptionNumber {
        /// Reserved
        Reserved0 = 0,
        /// If-Match
        IfMatch = 1,
        /// Uri-Host
        UriHost = 3,
        /// ETag
        ETag = 4,
        /// If-None-Patch
        IfNoneMatch = 5,
        /// Uri-Port
        UriPort = 7,
        /// Location-Path
        LocationPath = 8,
        /// Uri-Path
        UriPath = 11,
        /// Content-Format
        ContentFormat = 12,
        /// Max-Age
        MaxAge = 14,
        /// Uri-Query
        UriQuery = 15,
        /// Accept
        Accept = 17,
        /// Location-Query
        LocationQuery = 20,
        /// Proxy-Uri
        ProxyUri = 35,
        /// Proxy-Scheme
        ProxyScheme = 39,
        /// Size1
        Size1 = 60,
        /// Reserved
        Reserved1 = 128,
        /// Reserved
        Reserved2 = 132,
        /// Reserved
        Reserved3 = 136,
        /// Reserved
        Reserved4 = 140,
    }
);

impl OptionNumber {
    /// Is this a critical option?
    pub fn is_critical(&self) -> bool {
        // odd option numbers are critical
        u16::from(*self) % 2 == 1
    }

    /// Is this an elective option?
    pub fn is_elective(&self) -> bool {
        // even option numbers are elective
        !self.is_critical()
    }

    /// Is this option UnSafe to forward?
    pub fn is_unsafe(&self) -> bool {
        u16::from(*self) & 2 == 1
    }
}

full_range!(
    u16,
    /// CoAP Content-Formats
    pub enum ContentFormat {
        /// text/plain; charset=utf-8
        TextPlain = 0,
        /// application/link-format
        ApplicationLinkFormat = 40,
        /// application/xml
        ApplicationXml = 41,
        /// application/octet-stream
        ApplicationOctetStream = 42,
        /// application/exi
        ApplicationExi = 47,
        /// application/json
        ApplicationJson = 50,
    }
);

#[cfg(test)]
mod tests {
    use cast::usize;
    use rand::{self, Rng, RngCore};

    use crate::coap;

    const URI_HOST: &[u8] = b"www.example.org";
    const URI_PORT: &[u8] = &[22, 51]; // 5683

    #[test]
    fn new() {
        const SZ: usize = super::TOKEN_START;

        let mut chunk = [0; SZ];
        let buf = &mut chunk[..];

        let coap = coap::Message::new(buf, 0);
        assert_eq!(usize(coap.len()), SZ);
        let m = coap.set_payload(&[]);
        assert_eq!(m.payload(), &[]);
        assert_eq!(usize(m.len()), SZ);
    }

    #[test]
    fn new_payload() {
        const BYTE: u8 = 42;
        const SZ: usize = super::TOKEN_START + 1 /* PAYLOAD_MARKER */ + 1 /* BYTE */;

        let mut chunk = [0; SZ];
        let buf = &mut chunk[..];

        let coap = coap::Message::new(buf, 0);
        let m = coap.set_payload(&[BYTE]);
        assert_eq!(m.payload(), &[BYTE]);
        assert_eq!(usize(m.len()), SZ);
    }

    #[test]
    fn options() {
        // NOTE start with randomized array to make sure we set *everything* correctly
        let mut buf = [0; 128];
        rand::thread_rng().fill_bytes(&mut buf);

        let mut coap = coap::Message::new(&mut buf[..], rand::thread_rng().gen::<u8>() % 9);

        coap.add_option(coap::OptionNumber::UriHost, URI_HOST);

        {
            let host = coap.options().next().unwrap();

            assert_eq!(host.number(), coap::OptionNumber::UriHost);
            assert_eq!(host.value(), URI_HOST);
        }

        coap.add_option(coap::OptionNumber::UriPort, URI_PORT);

        {
            let host = coap.options().nth(0).unwrap();
            let port = coap.options().nth(1).unwrap();

            assert_eq!(host.number(), coap::OptionNumber::UriHost);
            assert_eq!(host.value(), URI_HOST);

            assert_eq!(port.number(), coap::OptionNumber::UriPort);
            assert_eq!(port.value(), URI_PORT);
        }

        coap.clear_options();

        assert!(coap.options().next().is_none());
    }

    #[test]
    fn parse() {
        const TYPE: coap::Type = coap::Type::Confirmable;
        const CODE: coap::Code = coap::Code(0b000_00001);
        const MID: u16 = 0xabcd;

        let mut rng = rand::thread_rng();
        let tkl = rng.gen::<u8>() % 9;
        let mut buf = [0; 8];
        rng.fill_bytes(&mut buf[..usize(tkl)]);
        let token = &buf[..usize(tkl)];

        // NOTE start with randomized array to make sure we set *everything* correctly
        let mut buf = [0; 128];
        rng.fill_bytes(&mut buf);

        let mut coap = coap::Message::new(&mut buf[..], tkl);

        coap.set_type(TYPE);
        coap.set_code(CODE);
        coap.set_message_id(MID);
        coap.token_mut().copy_from_slice(token);

        // zero options
        {
            let m = coap::Message::parse(coap.as_bytes()).unwrap();

            assert_eq!(m.get_version(), 1);
            assert_eq!(m.get_type(), TYPE);
            assert_eq!(m.get_token_length(), tkl);
            assert_eq!(m.get_code(), CODE);
            assert_eq!(m.get_message_id(), MID);
            assert_eq!(m.token(), token);
        }

        coap.add_option(coap::OptionNumber::UriHost, URI_HOST);

        // one option
        {
            let m = coap::Message::parse(coap.as_bytes()).unwrap();

            assert_eq!(m.get_version(), 1);
            assert_eq!(m.get_type(), TYPE);
            assert_eq!(m.get_token_length(), tkl);
            assert_eq!(m.get_code(), CODE);
            assert_eq!(m.get_message_id(), MID);
            assert_eq!(m.token(), token);

            let host = m.options().next().unwrap();

            assert_eq!(host.number(), coap::OptionNumber::UriHost);
            assert_eq!(host.value(), URI_HOST);
        }

        coap.add_option(coap::OptionNumber::UriPort, URI_PORT);

        // two options
        {
            let m = coap::Message::parse(coap.as_bytes()).unwrap();

            assert_eq!(m.get_version(), 1);
            assert_eq!(m.get_type(), TYPE);
            assert_eq!(m.get_token_length(), tkl);
            assert_eq!(m.get_code(), CODE);
            assert_eq!(m.get_message_id(), MID);
            assert_eq!(m.token(), token);

            let host = coap.options().nth(0).unwrap();
            let port = coap.options().nth(1).unwrap();

            assert_eq!(host.number(), coap::OptionNumber::UriHost);
            assert_eq!(host.value(), URI_HOST);

            assert_eq!(port.number(), coap::OptionNumber::UriPort);
            assert_eq!(port.value(), URI_PORT);
        }
    }
}
