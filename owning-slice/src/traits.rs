use core::slice;

use as_slice::AsSlice;

use crate::sealed;

pub trait IntoSlice<I>: AsSlice {
    type Output: AsSlice<Element = <Self as AsSlice>::Element>
        + IntoSlice<I>
        + IntoSliceFrom<I>
        + IntoSliceTo<I>
        + Truncate<I>;

    fn into_slice(self, start: I, length: I) -> Self::Output;
}

impl<'a, T, I> IntoSlice<I> for &'a [T]
where
    I: sealed::Index,
{
    type Output = &'a [T];

    fn into_slice(self, start: I, length: I) -> Self::Output {
        let start = start.into();
        let end = start + length.into();
        &self[start..end]
    }
}

impl<'a, T, I> IntoSlice<I> for &'a mut [T]
where
    I: sealed::Index,
{
    type Output = &'a mut [T];

    fn into_slice(self, start: I, length: I) -> Self::Output {
        let start = start.into();
        let end = start + length.into();
        &mut self[start..end]
    }
}

pub trait IntoSliceFrom<I>: AsSlice {
    type OutputF: AsSlice<Element = <Self as AsSlice>::Element>
        + IntoSlice<I>
        + IntoSliceFrom<I>
        + IntoSliceTo<I>;

    fn into_slice_from(self, start: I) -> Self::OutputF;
}

impl<'a, T, I> IntoSliceFrom<I> for &'a [T]
where
    I: sealed::Index,
{
    type OutputF = &'a [T];

    fn into_slice_from(self, start: I) -> Self::OutputF {
        &self[start.into()..]
    }
}

impl<'a, T, I> IntoSliceFrom<I> for &'a mut [T]
where
    I: sealed::Index,
{
    type OutputF = &'a mut [T];

    fn into_slice_from(self, start: I) -> Self::OutputF {
        &mut self[start.into()..]
    }
}

pub trait IntoSliceTo<I>: AsSlice {
    type OutputT: AsSlice<Element = <Self as AsSlice>::Element>
        + IntoSlice<I>
        + IntoSliceFrom<I>
        + IntoSliceTo<I>
        + Truncate<I>;

    fn into_slice_to(self, end: I) -> Self::OutputT;
}

impl<'a, T, I> IntoSliceTo<I> for &'a [T]
where
    I: sealed::Index,
{
    type OutputT = &'a [T];

    fn into_slice_to(self, end: I) -> Self::OutputT {
        &self[..end.into()]
    }
}

impl<'a, T, I> IntoSliceTo<I> for &'a mut [T]
where
    I: sealed::Index,
{
    type OutputT = &'a mut [T];

    fn into_slice_to(self, end: I) -> Self::OutputT {
        &mut self[..end.into()]
    }
}

pub trait Truncate<I> {
    fn truncate(&mut self, len: I);
}

impl<'a, T, I> Truncate<I> for &'a [T]
where
    I: sealed::Index,
{
    fn truncate(&mut self, len: I) {
        let end = len.into();

        if end < self.len() {
            *self = &self[..end]
        }
    }
}

impl<'a, T, I> Truncate<I> for &'a mut [T]
where
    I: sealed::Index,
{
    fn truncate(&mut self, len: I) {
        let end = len.into();

        if end < self.len() {
            *self = unsafe { slice::from_raw_parts_mut(self.as_mut_ptr(), end) };
        }
    }
}
