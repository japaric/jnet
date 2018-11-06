use cast::usize;

// TODO impl Chunk for Box<[u8]>

/// A buffer that can be resized in place
pub trait Resize {
    /// Slices the buffer in place
    fn slice_from(&mut self, offset: u16);

    /// Truncates the buffer to the specified length
    fn truncate(&mut self, len: u16);
}

impl<'a> Resize for &'a [u8] {
    fn slice_from(&mut self, offset: u16) {
        *self = &self[usize(offset)..]
    }

    fn truncate(&mut self, len: u16) {
        let len = usize(len);
        if self.len() > len {
            *self = &self[..len]
        }
    }
}

impl<'a> Resize for &'a mut [u8] {
    fn slice_from(&mut self, offset: u16) {
        // NOTE(unsafe) side step borrow checker complaints
        *self = unsafe { &mut *(&self[usize(offset)..] as *const _ as *mut _) };
    }

    fn truncate(&mut self, len: u16) {
        let old = self.len();
        let len = usize(len);
        if old > len {
            // NOTE(unsafe) side step borrow checker complaints
            *self = unsafe { &mut *(&self[..usize(len)] as *const _ as *mut _) };
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
