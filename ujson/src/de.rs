//! Deserialization

use core::str;

use crate::traits::SliceExt;

/// Deserializes `T` from the given `bytes`
pub fn from_bytes<T>(bytes: &[u8]) -> Result<T, ()>
where
    T: Deserialize,
{
    let mut cursor = Cursor::new(bytes);
    cursor.parse_whitespace();
    let x = T::deserialize(&mut cursor)?;
    cursor.finish()?;
    Ok(x)
}

/// Types that can be deserialized into JSON
pub trait Deserialize: Sized {
    // IMPLEMENTATION DETAIL
    #[doc(hidden)]
    fn deserialize(cursor: &mut Cursor<'_>) -> Result<Self, ()>;
}

impl Deserialize for bool {
    fn deserialize(cursor: &mut Cursor<'_>) -> Result<Self, ()> {
        match cursor.peek() {
            Some(b't') => cursor.parse_ident(b"true").map(|_| true),
            Some(b'f') => cursor.parse_ident(b"false").map(|_| false),
            _ => Err(()),
        }
    }
}

macro_rules! unsigned {
    ($($uN:ty),+) => {
        $(
            impl Deserialize for $uN {
                fn deserialize(cursor: &mut Cursor<'_>) -> Result<Self, ()> {
                    let mut out: $uN = 0;

                    let mut is_first = true;
                    for digit in cursor.parse_digits(false)? {
                        if is_first {
                            is_first = false;
                        } else {
                            out = out.checked_mul(10).ok_or(())?;
                        }

                        out = out.checked_add((digit - b'0') as $uN).ok_or(())?;
                    }

                    Ok(out)
                }
            }

        )+
    }
}

unsigned!(u8, u16, u32, u64, usize);

macro_rules! signed {
    ($($iN:ty),+) => {
        $(
            impl Deserialize for $iN {
                fn deserialize(cursor: &mut Cursor<'_>) -> Result<Self, ()> {
                    let mut out: $iN = 0;

                    let digits = cursor.parse_digits(true)?;
                    let is_negative = digits.get(0) == Some(&b'-');
                    let mut is_first = true;
                    for digit in digits.iter().skip(if is_negative { 1 } else { 0 }) {
                        if is_first {
                            is_first = false;
                        } else {
                            out = out.checked_mul(10).ok_or(())?;
                        }

                        let digit = (digit - b'0') as $iN;
                        if is_negative {
                            out = out.checked_sub(digit).ok_or(())?;
                        } else {
                            out = out.checked_add(digit).ok_or(())?;
                        }
                    }

                    Ok(out)
                }
            }

        )+
    }
}

signed!(i8, i16, i32, i64, isize);

// IMPLEMENTATION DETAIL
#[doc(hidden)]
pub struct Cursor<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Cursor { bytes, index: 0 }
    }

    // NOTE(unsafe) caller must ensure that the invariant is not broken
    unsafe fn bump(&mut self) {
        self.index += 1;

        invariant!(dbg!(self.index) <= dbg!(self.bytes.len()));
    }

    // IMPLEMENTATION DETAIL
    #[doc(hidden)]
    pub fn expect(&mut self, byte: u8) -> Result<(), ()> {
        if self.peek() == Some(byte) {
            unsafe { self.bump() }
            Ok(())
        } else {
            Err(())
        }
    }

    fn finish(mut self) -> Result<(), ()> {
        self.parse_whitespace();
        if self.peek() == None {
            Ok(())
        } else {
            Err(())
        }
    }

    // IMPLEMENTATION DETAIL
    #[doc(hidden)]
    pub fn matches_byte_string(&mut self, ident: &[u8]) -> Result<bool, ()> {
        let original = self.index;

        if self.peek() != Some(b'"') {
            return Err(());
        }

        unsafe { self.bump() }

        if self.matches_ident(ident) {
            if self.peek() == Some(b'"') {
                unsafe { self.bump() }
                Ok(true)
            } else {
                self.index = original;
                Ok(false)
            }
        } else {
            self.index = original;
            Ok(false)
        }
    }

    fn matches_ident(&mut self, ident: &[u8]) -> bool {
        let len = ident.len();
        let index = self.index;

        invariant!(dbg!(self.index) <= dbg!(self.bytes.len()));
        if self.bytes.len() - self.index < len {
            return false;
        }

        if unsafe { self.bytes.slice(index, len) } == ident {
            self.index += len;
            invariant!(dbg!(self.index) <= dbg!(self.bytes.len()));

            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        invariant!(dbg!(self.index) <= dbg!(self.bytes.len()));

        self.bytes.get(self.index).cloned()
    }

    #[allow(dead_code)]
    fn parse_unescaped_str(&mut self) -> Result<&str, ()> {
        self.expect(b'"')?;

        let start = self.index;
        let end = loop {
            match self.peek() {
                // EOF,
                None => return Err(()),

                // escaped string
                Some(b'\\') => return Err(()),

                // end of string
                Some(b'"') => {
                    let end = self.index;
                    unsafe { self.bump() }
                    break end;
                }

                // control character
                Some(0..=31) => return Err(()),

                // UTF-8 validation (see RFC3629)
                Some(first) => {
                    unsafe { self.bump() }

                    match first {
                        // UTF8-1 = %x00-7F
                        0..=0x7F => {}

                        // UTF8-2 = %xC2-DF UTF8-tail
                        0xC2..=0xDF => {
                            let next = self.peek().ok_or(())?;

                            if next >> 6 == 0b10 {
                                unsafe { self.bump() }
                            } else {
                                return Err(());
                            }
                        }

                        // UTF8-3 = %xE0 %xA0-BF UTF8-tail /
                        //          %xE1-EC 2( UTF8-tail ) /
                        //          %xED %x80-9F UTF8-tail /
                        //          %xEE-EF 2( UTF8-tail )
                        0xE0..=0xEF => {
                            let next = self.peek().ok_or(())?;

                            match (first, next) {
                                (0xE0, 0xA0..=0xBF)
                                | (0xE1..=0xEC, 0x80..=0xBF)
                                | (0xED, 0x80..=0x9F)
                                | (0xEE..=0xEF, 0x80..=0xBF) => unsafe { self.bump() },
                                _ => return Err(()),
                            }

                            let next = self.peek().ok_or(())?;

                            if next >> 6 == 0b10 {
                                unsafe { self.bump() }
                            } else {
                                return Err(());
                            }
                        }

                        // UTF8-4 = %xF0 %x90-BF 2( UTF8-tail ) /
                        //          %xF1-F3 3( UTF8-tail ) /
                        //          %xF4 %x80-8F 2( UTF8-tail )
                        0xF0..=0xF4 => {
                            let next = self.peek().ok_or(())?;

                            match (first, next) {
                                (0xF0, 0x90..=0xBF)
                                | (0xF1..=0xF3, 0x80..=0xBF)
                                | (0xF4, 0x80..=0x8F) => unsafe { self.bump() },
                                _ => return Err(()),
                            }

                            let next = self.peek().ok_or(())?;

                            if next >> 6 == 0b10 {
                                unsafe { self.bump() }
                            } else {
                                return Err(());
                            }

                            let next = self.peek().ok_or(())?;

                            if next >> 6 == 0b10 {
                                unsafe { self.bump() }
                            } else {
                                return Err(());
                            }
                        }

                        _ => return Err(()),
                    }
                }
            }
        };

        unsafe { Ok(str::from_utf8_unchecked(&self.bytes[start..end])) }
    }

    // NOTE doesn't support floating point number
    fn parse_digits(&mut self, signed: bool) -> Result<&[u8], ()> {
        let start = self.index;

        if signed {
            if self.peek() == Some(b'-') {
                unsafe { self.bump() }
            }
        }

        let end = match self.peek() {
            Some(b'0') => {
                unsafe { self.bump() }
                self.index
            }

            Some(b'1'..=b'9') => {
                unsafe { self.bump() }
                loop {
                    match self.peek() {
                        Some(b'0'..=b'9') => unsafe { self.bump() },

                        _ => break self.index,
                    }
                }
            }

            _ => return Err(()),
        };

        Ok(&self.bytes[start..end])
    }

    // IMPLEMENTATION DETAIL
    #[doc(hidden)]
    pub fn parse_whitespace(&mut self) {
        loop {
            match self.peek() {
                Some(b' ') | Some(b'\n') | Some(b'\t') | Some(b'\r') => unsafe { self.bump() },

                _ => return,
            }
        }
    }

    fn parse_ident(&mut self, ident: &[u8]) -> Result<(), ()> {
        if self.matches_ident(ident) {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Cursor;

    #[test]
    fn boolean() {
        assert_eq!(super::from_bytes::<bool>(b"true").unwrap(), true);
        assert_eq!(super::from_bytes::<bool>(b"false").unwrap(), false);
    }

    #[test]
    fn u8() {
        assert_eq!(super::from_bytes::<u8>(b"0").unwrap(), 0);
        assert_eq!(super::from_bytes::<u8>(b"10").unwrap(), 10);
        assert_eq!(super::from_bytes::<u8>(b"100").unwrap(), 100);
        assert_eq!(super::from_bytes::<u8>(b"255").unwrap(), 255);

        assert!(super::from_bytes::<u8>(b"-0").is_err());
        assert!(super::from_bytes::<u8>(b"-1").is_err());
        assert!(super::from_bytes::<u8>(b"256").is_err());
        assert!(super::from_bytes::<u8>(b"1000").is_err());
    }

    #[test]
    fn i8() {
        assert_eq!(super::from_bytes::<i8>(b"0").unwrap(), 0);
        assert_eq!(super::from_bytes::<i8>(b"10").unwrap(), 10);
        assert_eq!(super::from_bytes::<i8>(b"100").unwrap(), 100);
        assert_eq!(super::from_bytes::<i8>(b"-1").unwrap(), -1);
        assert_eq!(super::from_bytes::<i8>(b"-10").unwrap(), -10);
        assert_eq!(super::from_bytes::<i8>(b"-100").unwrap(), -100);
        assert_eq!(super::from_bytes::<i8>(b"127").unwrap(), 127);
        assert_eq!(super::from_bytes::<i8>(b"-128").unwrap(), -128);

        assert!(super::from_bytes::<i8>(b"128").is_err());
        assert!(super::from_bytes::<i8>(b"-129").is_err());
        assert!(super::from_bytes::<i8>(b"1_000").is_err());
        assert!(super::from_bytes::<i8>(b"-200").is_err());
        assert!(super::from_bytes::<i8>(b"-1_000").is_err());
    }

    #[test]
    fn whitespace() {
        assert_eq!(super::from_bytes::<bool>(b" true").unwrap(), true);
        assert_eq!(super::from_bytes::<bool>(b"true ").unwrap(), true);
        assert_eq!(super::from_bytes::<bool>(b" true ").unwrap(), true);
    }

    #[test]
    fn str() {
        let mut cursor = Cursor::new("\"こんにちは\"".as_bytes());
        assert_eq!(cursor.parse_unescaped_str().unwrap(), "こんにちは");
    }
}
