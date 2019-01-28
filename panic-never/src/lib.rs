#![no_std]

use core::panic::PanicInfo;

use cortex_m::asm;

#[macro_export]
macro_rules! force_eval {
    ($e:expr) => {
        unsafe { core::ptr::read_volatile(&$e); }
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    // uncomment to debug link errors
    // nop();
    extern "C" {
        #[link_name = "This crate contains at least one panicking branch"]
        fn panic() -> !;
    }

    unsafe { panic() }
}

#[allow(dead_code)]
#[inline(never)]
fn nop() -> ! {
    loop {
        asm::nop();
    }
}
