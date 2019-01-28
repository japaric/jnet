#![no_std]
#![no_main]

use cortex_m::asm;
use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::{ipv4, Valid};

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut PACKET: Option<ipv4::Packet<&'static mut [u8], Valid>> = None;

#[exception]
unsafe fn SysTick() {
    if let Ok(p) = ipv4::Packet::parse(&mut BUFFER[..]) {
        PACKET = Some(p);
    } else {
        asm::nop();
    }
}

#[exception]
unsafe fn SVCall() {
    if let Some(p) = PACKET.take() {
        force_eval!(p.get_version());
        force_eval!(p.get_ihl());
        force_eval!(p.get_dscp());
        force_eval!(p.get_ecn());
        force_eval!(p.get_total_length());
        force_eval!(p.len());
        force_eval!(p.get_identification());
        force_eval!(p.get_df());
        force_eval!(p.get_mf());
        force_eval!(p.get_fragment_offset());
        force_eval!(p.get_ttl());
        force_eval!(p.get_protocol());
        force_eval!(p.get_source());
        force_eval!(p.get_destination());
        force_eval!(p.payload());
    }
}

#[entry]
fn main() -> ! {
    loop {}
}
