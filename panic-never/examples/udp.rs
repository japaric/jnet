#![no_std]
#![no_main]

use cortex_m::asm;
use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::udp;

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut PACKET: Option<udp::Packet<&'static mut [u8]>> = None;

#[exception]
unsafe fn SysTick() {
    if let Ok(p) = udp::Packet::parse(&mut BUFFER[..]) {
        PACKET = Some(p);
    } else {
        asm::nop();
    }
}

#[exception]
unsafe fn SVCall() {
    if let Some(p) = PACKET.take() {
        force_eval!(p.get_source());
        force_eval!(p.get_destination());
        force_eval!(p.get_length());
        force_eval!(p.len());
        force_eval!(p.payload());
    }
}

#[entry]
fn main() -> ! {
    loop {}
}
