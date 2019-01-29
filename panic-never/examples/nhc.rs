#![no_std]
#![no_main]

use cortex_m::asm;
use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::sixlowpan::nhc;

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut PACKET: Option<nhc::UdpPacket<&'static mut [u8]>> = None;

#[exception]
unsafe fn SysTick() {
    if let Ok(p) = nhc::UdpPacket::parse(&mut BUFFER[..]) {
        PACKET = Some(p);
    } else {
        asm::nop();
    }
}

#[exception]
unsafe fn SVCall() {
    if let Some(mut p) = PACKET.take() {
        force_eval!(p.get_source());
        force_eval!(p.get_destination());
        force_eval!(p.get_checksum());
        force_eval!(p.payload());
        force_eval!(p.payload_mut());
    }
}

#[entry]
fn main() -> ! {
    loop {}
}
