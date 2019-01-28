#![feature(asm)]
#![feature(maybe_uninit)]
#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::ether;

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut FRAME: MaybeUninit<ether::Frame<&'static mut [u8]>> = MaybeUninit::uninitialized();

#[exception]
unsafe fn SysTick() {
    if let Ok(f) = ether::Frame::parse(&mut BUFFER[..]) {
        FRAME.set(f);
    } else {
        asm!("NOP" : : : : "volatile");
    }
}

#[exception]
unsafe fn SVCall() {
    let f = FRAME.get_mut();

    force_eval!(f.get_destination());
    force_eval!(f.get_source());
    force_eval!(f.get_type());
    force_eval!(f.payload());
}

#[entry]
fn main() -> ! {
    loop {}
}
