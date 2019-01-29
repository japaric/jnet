#![no_std]
#![no_main]

use cortex_m::asm;
use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::sixlowpan::iphc;

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut PACKET: Option<iphc::Packet<&'static mut [u8]>> = None;

#[exception]
unsafe fn SysTick() {
    if let Ok(p) = iphc::Packet::parse(&mut BUFFER[..]) {
        PACKET = Some(p);
    } else {
        asm::nop();
    }
}

#[exception]
unsafe fn SVCall() {
    if let Some(p) = PACKET.take() {
        force_eval!(p.get_next_header());
        force_eval!(p.get_hop_limit());
        force_eval!(p.get_source());
        force_eval!(p.get_destination());
        force_eval!(p.payload());
        force_eval!(p.get_tf());
        force_eval!(p.get_nh());
        force_eval!(p.get_hlim());
        force_eval!(p.get_cid());
        force_eval!(p.get_sac());
        force_eval!(p.get_sam());
        force_eval!(p.get_m());
        force_eval!(p.get_dac());
        force_eval!(p.get_dam());
    }
}

#[entry]
fn main() -> ! {
    loop {}
}
