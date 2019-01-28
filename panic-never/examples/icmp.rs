#![feature(asm)]
#![feature(maybe_uninit)]
#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::{icmp, Unknown, Valid};

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut PACKET: MaybeUninit<icmp::Packet<&'static mut [u8], Unknown, Valid>> =
    MaybeUninit::uninitialized();

#[exception]
unsafe fn SysTick() {
    if let Ok(p) = icmp::Packet::parse(&mut BUFFER[..]) {
        PACKET.set(p);
    } else {
        asm!("NOP" : : : : "volatile");
    }
}

#[exception]
unsafe fn SVCall() {
    let p = PACKET.get_mut();

    force_eval!(p.get_type());
    force_eval!(p.get_code());
    force_eval!(p.payload());
    force_eval!(p.len());
}

#[entry]
fn main() -> ! {
    loop {}
}
