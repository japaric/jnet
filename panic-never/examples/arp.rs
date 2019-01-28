#![feature(asm)]
#![feature(maybe_uninit)]
#![no_std]
#![no_main]

use core::mem::MaybeUninit;

use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::arp;

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut PACKET: MaybeUninit<arp::Packet<&'static mut [u8]>> = MaybeUninit::uninitialized();

#[exception]
unsafe fn SysTick() {
    if let Ok(p) = arp::Packet::parse(&mut BUFFER[..]) {
        match p.downcast() {
            Ok(p) => {
                PACKET.set(p);
            }
            Err(p) => {
                force_eval!(p.get_sha());
                force_eval!(p.get_spa());
                force_eval!(p.get_tha());
                force_eval!(p.get_tpa());
            }
        }
    } else {
        asm!("NOP" : : : : "volatile");
    }
}

#[exception]
unsafe fn SVCall() {
    let p = PACKET.get_mut();

    force_eval!(p.get_sha());
    force_eval!(p.get_spa());
    force_eval!(p.get_tha());
    force_eval!(p.get_tpa());
    force_eval!(p.is_a_probe());
}

#[entry]
fn main() -> ! {
    loop {}
}
