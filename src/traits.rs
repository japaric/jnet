use core::ops::{Range, RangeFrom, RangeTo};
#[cfg(not(debug_assertions))]
use core::slice;

use cast::usize;

/// IMPLEMENTATION DETAIL
pub trait UncheckedIndex {
    type T;

    // get_unchecked
    unsafe fn gu(&self, i: usize) -> &Self::T;
    // get_unchecked_mut
    unsafe fn gum(&mut self, i: usize) -> &mut Self::T;
    unsafe fn r(&self, r: Range<usize>) -> &Self;
    unsafe fn rm(&mut self, r: Range<usize>) -> &mut Self;
    unsafe fn rt(&self, r: RangeTo<usize>) -> &Self;
    unsafe fn rtm(&mut self, r: RangeTo<usize>) -> &mut Self;
    unsafe fn rf(&self, r: RangeFrom<usize>) -> &Self;
    unsafe fn rfm(&mut self, r: RangeFrom<usize>) -> &mut Self;
}

impl<T> UncheckedIndex for [T] {
    type T = T;

    unsafe fn gu(&self, at: usize) -> &T {
        debug_assert!(at < self.len());

        self.get_unchecked(at)
    }

    unsafe fn gum(&mut self, at: usize) -> &mut T {
        debug_assert!(at < self.len());

        self.get_unchecked_mut(at)
    }

    #[cfg(debug_assertions)]
    unsafe fn r(&self, r: Range<usize>) -> &[T] {
        &self[r]
    }

    #[cfg(not(debug_assertions))]
    unsafe fn r(&self, r: Range<usize>) -> &[T] {
        let o = r.start;
        let l = r.end - o;
        slice::from_raw_parts(self.as_ptr().add(o), l)
    }

    #[cfg(debug_assertions)]
    unsafe fn rm(&mut self, r: Range<usize>) -> &mut [T] {
        &mut self[r]
    }

    #[cfg(not(debug_assertions))]
    unsafe fn rm(&mut self, r: Range<usize>) -> &mut [T] {
        let o = r.start;
        let l = r.end - o;
        slice::from_raw_parts_mut(self.as_mut_ptr().add(o), l)
    }

    #[cfg(debug_assertions)]
    unsafe fn rt(&self, r: RangeTo<usize>) -> &[T] {
        &self[r]
    }

    #[cfg(not(debug_assertions))]
    unsafe fn rt(&self, r: RangeTo<usize>) -> &[T] {
        slice::from_raw_parts(self.as_ptr(), r.end)
    }

    #[cfg(debug_assertions)]
    unsafe fn rtm(&mut self, r: RangeTo<usize>) -> &mut [T] {
        &mut self[r]
    }

    #[cfg(not(debug_assertions))]
    unsafe fn rtm(&mut self, r: RangeTo<usize>) -> &mut [T] {
        slice::from_raw_parts_mut(self.as_mut_ptr(), r.end)
    }

    #[cfg(debug_assertions)]
    unsafe fn rf(&self, r: RangeFrom<usize>) -> &[T] {
        &self[r]
    }

    #[cfg(not(debug_assertions))]
    unsafe fn rf(&self, r: RangeFrom<usize>) -> &[T] {
        let o = r.start;
        let l = self.len() - o;
        slice::from_raw_parts(self.as_ptr().add(o), l)
    }

    #[cfg(debug_assertions)]
    unsafe fn rfm(&mut self, r: RangeFrom<usize>) -> &mut [T] {
        &mut self[r]
    }

    #[cfg(not(debug_assertions))]
    unsafe fn rfm(&mut self, r: RangeFrom<usize>) -> &mut [T] {
        let o = r.start;
        let l = self.len() - o;
        slice::from_raw_parts_mut(self.as_mut_ptr().add(o), l)
    }
}

/// A buffer that can be resized in place
pub trait Resize {
    /// Slices the buffer in place
    fn slice_from(&mut self, offset: u16);

    /// Truncates the buffer to the specified length
    fn truncate(&mut self, len: u16);
}

impl<'a> Resize for &'a [u8] {
    fn slice_from(&mut self, offset: u16) {
        *self = unsafe { self.rf(usize(offset)..) };
    }

    fn truncate(&mut self, len: u16) {
        let len = usize(len);
        if self.len() > len {
            *self = unsafe { self.rt(..len) };
        }
    }
}

impl<'a> Resize for &'a mut [u8] {
    fn slice_from(&mut self, offset: u16) {
        // NOTE(unsafe) side step borrow checker complaints
        *self = unsafe { &mut *(self.rfm(usize(offset)..) as *mut [u8]) };
    }

    fn truncate(&mut self, len: u16) {
        let old = self.len();
        let len = usize(len);
        if old > len {
            *self = unsafe { &mut *(self.rtm(..usize(len)) as *mut [u8]) };
        }
    }
}

pub trait UxxExt {
    type Half;

    fn low(self) -> Self::Half;
    fn high(self) -> Self::Half;
}

impl UxxExt for u16 {
    type Half = u8;

    fn low(self) -> u8 {
        let mask = (1 << 8) - 1;
        (self & mask) as u8
    }

    fn high(self) -> u8 {
        (self >> 8) as u8
    }
}

impl UxxExt for u32 {
    type Half = u16;

    fn low(self) -> u16 {
        let mask = (1 << 16) - 1;
        (self & mask) as u16
    }

    fn high(self) -> u16 {
        (self >> 16) as u16
    }
}

pub trait TryFrom<T>: Sized {
    type Error;

    fn try_from(value: T) -> Result<Self, Self::Error>;
}

pub trait TryInto<T> {
    type Error;
    fn try_into(self) -> Result<T, Self::Error>;
}

impl<T, U> TryInto<U> for T
where
    U: TryFrom<T>,
{
    type Error = U::Error;

    fn try_into(self) -> Result<U, U::Error> {
        U::try_from(self)
    }
}
