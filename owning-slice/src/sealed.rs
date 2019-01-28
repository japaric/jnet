use core::{ops, u16, u8};

pub trait Index:
    ops::Add<Self, Output = Self> + ops::Sub<Self, Output = Self> + Copy + Into<usize> + PartialOrd
{
    fn from_usize(x: usize) -> Self;
    fn max() -> usize;
    fn zero() -> Self;
}

impl Index for u8 {
    fn from_usize(x: usize) -> u8 {
        x as u8
    }

    fn max() -> usize {
        u8::MAX as usize
    }

    fn zero() -> u8 {
        0
    }
}

impl Index for u16 {
    fn from_usize(x: usize) -> u16 {
        x as u16
    }

    fn max() -> usize {
        u16::MAX as usize
    }

    fn zero() -> u16 {
        0
    }
}
