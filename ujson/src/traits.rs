use core::slice;

pub trait SliceExt {
    unsafe fn slice(&self, start: usize, len: usize) -> &Self;
    unsafe fn slice_mut(&mut self, start: usize, len: usize) -> &mut Self;
}

impl<T> SliceExt for [T] {
    unsafe fn slice(&self, start: usize, len: usize) -> &[T] {
        debug_assert!(dbg!(start) < dbg!(self.len()) && dbg!(len) <= self.len() - start);

        slice::from_raw_parts(self.as_ptr().add(start), len)
    }

    unsafe fn slice_mut(&mut self, start: usize, len: usize) -> &mut [T] {
        debug_assert!(dbg!(start) < dbg!(self.len()) && dbg!(len) <= self.len() - start);

        slice::from_raw_parts_mut(self.as_mut_ptr().add(start), len)
    }
}
