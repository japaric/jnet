#![feature(asm)]
#![feature(maybe_uninit)]
#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::udp;

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut PACKET: MaybeUninit<udp::Packet<&'static mut [u8]>> = MaybeUninit::uninitialized();

#[exception]
unsafe fn SysTick() {
    if let Ok(p) = udp::Packet::parse(&mut BUFFER[..]) {
        PACKET.set(p);
    } else {
        asm!("NOP" : : : : "volatile");
    }
}

#[exception]
unsafe fn SVCall() {
    let p = PACKET.get_mut();

    force_eval!(p.get_source());
    force_eval!(p.get_destination());
    force_eval!(p.get_length());
    force_eval!(p.len());
    force_eval!(p.payload());
}

#[entry]
fn main() -> ! {
    loop {}
}
