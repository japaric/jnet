#![no_std]
#![no_main]

use cortex_m::asm;
use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::{icmp, Unknown, Valid};

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut PACKET: Option<icmp::Packet<&'static mut [u8], Unknown, Valid>> = None;

#[exception]
unsafe fn SysTick() {
    if let Ok(p) = icmp::Packet::parse(&mut BUFFER[..]) {
        PACKET = Some(p);
    } else {
        asm::nop();
    }
}

#[exception]
unsafe fn SVCall() {
    if let Some(p) = PACKET.take() {
        force_eval!(p.get_type());
        force_eval!(p.get_code());
        force_eval!(p.payload());
        force_eval!(p.len());
    }
}

#[entry]
fn main() -> ! {
    loop {}
}
