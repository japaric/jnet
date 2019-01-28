#![feature(asm)]
#![feature(maybe_uninit)]
#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::coap;

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut MESSAGE: MaybeUninit<coap::Message<&'static mut [u8]>> = MaybeUninit::uninitialized();

#[exception]
unsafe fn SysTick() {
    if let Ok(p) = coap::Message::parse(&mut BUFFER[..]) {
        MESSAGE.set(p);
    } else {
        asm!("NOP" : : : : "volatile");
    }
}

#[exception]
unsafe fn SVCall() {
    let m = MESSAGE.get_mut();

    force_eval!(m.get_version());
    force_eval!(m.get_type());
    force_eval!(m.get_token_length());
    force_eval!(m.get_code());
    force_eval!(m.get_message_id());
    force_eval!(m.token());
    force_eval!(m.payload());
    for opt in m.options() {
        force_eval!(opt.number());
        force_eval!(opt.value());
    }
}

#[entry]
fn main() -> ! {
    loop {}
}
