#[cfg(not(test))]
macro_rules! dbg {
    ($e:expr) => {
        $e
    }
}

macro_rules! invariant {
    ($cond:expr) => {
        debug_assert!($cond)
    }
}
