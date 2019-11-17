//! Serialization

use core::{mem::MaybeUninit, slice, str};

use crate::traits::SliceExt;

/// Serializes the `value` into the given `buffer`
pub fn write<'a, T>(value: &T, buffer: &'a mut [u8]) -> Result<&'a str, ()>
where
    T: Serialize + ?Sized,
{
    let mut cursor = Cursor::new(buffer);
    value.serialize(&mut cursor)?;
    Ok(cursor.finish())
}

// IMPLEMENTATION DETAIL
// fast path: these don't contain unicode
#[doc(hidden)]
pub fn field_name(ident: &[u8], cursor: &mut Cursor<'_>) -> Result<(), ()> {
    cursor.push_byte(b'"')?;
    cursor.push(ident)?;
    cursor.push_byte(b'"')
}

/// Types that can be serialized into JSON
pub trait Serialize {
    // IMPLEMENTATION DETAIL
    #[doc(hidden)]
    fn serialize(&self, cursor: &mut Cursor<'_>) -> Result<(), ()>;
}

impl Serialize for bool {
    fn serialize(&self, cursor: &mut Cursor<'_>) -> Result<(), ()> {
        cursor.push(if *self { b"true" } else { b"false" })
    }
}

unsafe fn uninitialized<T>() -> T {
    MaybeUninit::uninit().assume_init()
}

macro_rules! unsigned {
    ($(($uN:ty, $N:expr),)+) => {
        $(
            impl Serialize for $uN {
                fn serialize(&self, cursor: &mut Cursor<'_>) -> Result<(), ()> {
                    let mut x = *self;

                    let mut buf: [u8; $N] = unsafe { uninitialized() };
                    let mut idx = $N - 1;
                    loop {
                        buf[idx] = b'0' + (x % 10) as u8;
                        x /= 10;

                        if x == 0 {
                            break;
                        }

                        idx -= 1;
                    }

                    cursor.push(&buf[idx..])
                }
            }
        )+
    }
}

unsigned! {
    (u8, 3),
    (u16, 5),
    (u32, 10),
    (u64, 20),
}

macro_rules! signed {
    ($(($iN:ty, $uN:ty, $N:expr),)+) => {
        $(
            impl Serialize for $iN {
                fn serialize(&self, cursor: &mut Cursor<'_>) -> Result<(), ()> {
                    let is_negative = *self < 0;
                    let mut x = self.wrapping_abs() as $uN;

                    let mut buf: [u8; $N] = unsafe { uninitialized() };
                    let mut idx = $N - 1;
                    loop {
                        buf[idx] = b'0' + (x % 10) as u8;
                        x /= 10;

                        if x == 0 {
                            break;
                        }

                        idx -= 1;
                    }

                    if is_negative {
                        idx -= 1;
                        buf[idx] = b'-';
                    }

                    cursor.push(&buf[idx..])
                }
            }
        )+
    }
}

signed! {
    (i8, u8, 4),
    (i16, u16, 6),
    (i32, u32, 11),
    (i64, u64, 20),
}

impl Serialize for str {
    fn serialize(&self, cursor: &mut Cursor<'_>) -> Result<(), ()> {
        cursor.push_byte(b'"')?;

        let bytes = self.as_bytes();
        let mut start = 0;

        for (i, byte) in bytes.iter().enumerate() {
            if let Some(escape) = Escape::from(*byte) {
                if start < i {
                    cursor.push(&bytes[start..i])?;
                }

                match escape {
                    Escape::Backspace => cursor.push(b"\\b")?,
                    Escape::CarriageReturn => cursor.push(b"\\r")?,
                    Escape::FormFeed => cursor.push(b"\\f")?,
                    Escape::LineFeed => cursor.push(b"\\n")?,
                    Escape::QuotationMark => cursor.push(b"\\\"")?,
                    Escape::ReverseSolidus => cursor.push(b"\\\\")?,
                    Escape::Tab => cursor.push(b"\\t")?,
                    Escape::Unicode => {
                        static HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";
                        cursor.push(b"\\u00")?;
                        cursor.push_byte(HEX_DIGITS[(byte >> 4) as usize])?;
                        cursor.push_byte(HEX_DIGITS[(byte & 0xF) as usize])?;
                    }
                }

                start = i + 1;
            }
        }

        if start < bytes.len() {
            cursor.push(&bytes[start..])?;
        }

        cursor.push_byte(b'"')
    }
}

// See RFC8259 Section 7 "Strings"
enum Escape {
    QuotationMark,
    ReverseSolidus,
    // Solidus,
    Backspace,
    FormFeed,
    LineFeed,
    CarriageReturn,
    Tab,
    Unicode,
}

impl Escape {
    fn from(byte: u8) -> Option<Self> {
        Some(if byte == b'"' {
            Escape::QuotationMark
        } else if byte == b'\\' {
            Escape::ReverseSolidus
        // } else if byte == b'/' {
        //     Escape::Solidus
        } else if byte == 0x08 {
            Escape::Backspace
        } else if byte == 0x0c {
            Escape::FormFeed
        } else if byte == 0x0a {
            Escape::LineFeed
        } else if byte == 0x0d {
            Escape::CarriageReturn
        } else if byte == 0x09 {
            Escape::Tab
        } else if byte < 0x20 {
            Escape::Unicode
        } else {
            return None;
        })
    }
}

impl<T> Serialize for [T]
where
    T: Serialize,
{
    fn serialize(&self, cursor: &mut Cursor<'_>) -> Result<(), ()> {
        cursor.push_byte(b'[')?;

        let mut first = true;
        for elem in self {
            if first {
                first = false;
            } else {
                cursor.push_byte(b',')?;
            }

            elem.serialize(cursor)?;
        }

        cursor.push_byte(b']')
    }
}

impl<'a, T> Serialize for &'a T
where
    T: Serialize,
{
    fn serialize(&self, cursor: &mut Cursor<'_>) -> Result<(), ()> {
        T::serialize(*self, cursor)
    }
}

macro_rules! arrays {
    ($($N:expr),+) => {
        $(
            impl<T> Serialize for [T; $N]
                where
                T: Serialize,
            {
                fn serialize(&self, cursor: &mut Cursor<'_>) -> Result<(), ()> {
                    <[T]>::serialize(self, cursor)
                }
            }
        )+
    }
}

arrays!(
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32
);

// IMPLEMENTATION DETAIL
#[doc(hidden)]
pub struct Cursor<'a> {
    buffer: &'a mut [u8],
    index: usize,
}

impl<'a> Cursor<'a> {
    fn new(buffer: &'a mut [u8]) -> Self {
        Cursor { buffer, index: 0 }
    }

    unsafe fn bump(&mut self, n: usize) {
        self.index += n;

        invariant!(dbg!(self.index) <= dbg!(self.buffer.len()));
    }

    // IMPLEMENTATION DETAIL
    #[doc(hidden)]
    pub fn push_byte(&mut self, byte: u8) -> Result<(), ()> {
        let index = self.index;

        *self.buffer.get_mut(index).ok_or(())? = byte;
        unsafe { self.bump(1) }

        Ok(())
    }

    // IMPLEMENTATION DETAIL
    #[doc(hidden)]
    pub fn push(&mut self, slice: &[u8]) -> Result<(), ()> {
        let index = self.index;
        let len = slice.len();

        if len > self.buffer.len() - index {
            return Err(());
        }

        unsafe {
            self.buffer.slice_mut(index, len).copy_from_slice(slice);
            self.bump(len);
        }

        Ok(())
    }

    fn finish(self) -> &'a str {
        unsafe { str::from_utf8_unchecked(slice::from_raw_parts(self.buffer.as_ptr(), self.index)) }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn boolean() {
        assert_eq!(super::write(&false, &mut [0; 5]).unwrap(), "false");
        assert_eq!(super::write(&true, &mut [0; 4]).unwrap(), "true");
    }

    #[test]
    fn u8() {
        assert_eq!(super::write(&0u8, &mut [0; 3]).unwrap(), "0");
        assert_eq!(super::write(&10u8, &mut [0; 3]).unwrap(), "10");
        assert_eq!(super::write(&100u8, &mut [0; 3]).unwrap(), "100");
        assert_eq!(super::write(&255u8, &mut [0; 3]).unwrap(), "255");
    }

    #[test]
    fn i8() {
        assert_eq!(super::write(&0i8, &mut [0; 4]).unwrap(), "0");
        assert_eq!(super::write(&-10i8, &mut [0; 4]).unwrap(), "-10");
        assert_eq!(super::write(&-100i8, &mut [0; 4]).unwrap(), "-100");
        assert_eq!(super::write(&-128i8, &mut [0; 4]).unwrap(), "-128");
    }

    #[test]
    fn seq() {
        assert_eq!(super::write(&[0u8, 1, 2], &mut [0; 8]).unwrap(), "[0,1,2]");
    }

    #[test]
    fn str() {
        assert_eq!(super::write("led", &mut [0; 8]).unwrap(), "\"led\"");
        assert_eq!(
            super::write("こんにちは", &mut [0; 32]).unwrap(),
            "\"こんにちは\""
        );
    }
}
