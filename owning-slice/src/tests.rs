use crate::{IntoSlice, IntoSliceFrom, IntoSliceTo, OwningSlice, OwningSliceFrom, OwningSliceTo};

macro_rules! sanity {
    ($buf:expr) => {{
        assert_eq!(*$buf.into_slice(0u8, 0), []);
        assert_eq!(*$buf.into_slice(0u8, 1), [0]);
        assert_eq!(*$buf.into_slice(0u8, 2), [0, 1]);
        assert_eq!(*$buf.into_slice(0u8, 3), [0, 1, 2]);
        assert_eq!(*$buf.into_slice(0u8, 4), [0, 1, 2, 3]);

        assert_eq!(*$buf.into_slice(1u8, 0), []);
        assert_eq!(*$buf.into_slice(1u8, 1), [1]);
        assert_eq!(*$buf.into_slice(1u8, 2), [1, 2]);
        assert_eq!(*$buf.into_slice(1u8, 3), [1, 2, 3]);

        assert_eq!(*$buf.into_slice(2u8, 0), []);
        assert_eq!(*$buf.into_slice(2u8, 1), [2]);
        assert_eq!(*$buf.into_slice(2u8, 2), [2, 3]);

        assert_eq!(*$buf.into_slice(3u8, 0), []);
        assert_eq!(*$buf.into_slice(3u8, 1), [3]);

        assert_eq!(*$buf.into_slice(4u8, 0), []);

        assert_eq!(*$buf.into_slice_from(0u8), [0, 1, 2, 3]);
        assert_eq!(*$buf.into_slice_from(1u8), [1, 2, 3]);
        assert_eq!(*$buf.into_slice_from(2u8), [2, 3]);
        assert_eq!(*$buf.into_slice_from(3u8), [3]);
        assert_eq!(*$buf.into_slice_from(4u8), []);

        assert_eq!(*$buf.into_slice_to(0u8), []);
        assert_eq!(*$buf.into_slice_to(1u8), [0]);
        assert_eq!(*$buf.into_slice_to(2u8), [0, 1]);
        assert_eq!(*$buf.into_slice_to(3u8), [0, 1, 2]);
        assert_eq!(*$buf.into_slice_to(4u8), [0, 1, 2, 3]);
    }};
}

#[test]
fn slice() {
    let slice: &[_] = &[0, 1, 2, 3];

    sanity!(slice);
}

#[test]
fn slice_mut() {
    let slice: &mut [_] = &mut [0, 1, 2, 3];

    sanity!(slice);
}

#[test]
fn owning_slice() {
    let array = &[0xff, 0, 1, 2, 3, 0xff];
    let slice = OwningSlice(array, 1, 4);

    sanity!(slice);
}

#[test]
fn owning_slice_from() {
    let array = &[0xff, 0, 1, 2, 3];
    let slice_from = OwningSliceFrom(array, 1);

    sanity!(slice_from);
}

#[test]
fn owning_slice_to() {
    let array = &[0, 1, 2, 3, 0xff];
    let slice_to = OwningSliceTo(array, 4);

    sanity!(slice_to);
}

#[test]
#[should_panic]
fn oob_slice_1() {
    let buf = &[0, 1, 2, 3];

    OwningSlice(buf, 5u8, 2);
}

#[test]
#[should_panic]
fn oob_slice_2() {
    let buf = &[0, 1, 2, 3];

    OwningSlice(buf, 1u8, 4);
}

#[test]
#[should_panic]
fn oob_slice_from() {
    let buf = &[0, 1, 2, 3];

    OwningSliceFrom(buf, 5u8);
}

#[test]
#[should_panic]
fn oob_slice_to() {
    let buf = &[0, 1, 2, 3];

    OwningSliceTo(buf, 5u8);
}
