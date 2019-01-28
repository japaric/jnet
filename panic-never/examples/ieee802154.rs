#![no_std]
#![no_main]

use cortex_m::asm;
use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::ieee802154;

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut FRAME: Option<ieee802154::Frame<&'static mut [u8]>> = None;

#[exception]
unsafe fn SysTick() {
    if let Ok(p) = ieee802154::Frame::parse(&mut BUFFER[..]) {
        FRAME = Some(p);
    } else {
        asm::nop();
    }
}

#[exception]
unsafe fn SVCall() {
    if let Some(f) = FRAME.take() {
        force_eval!(f.get_type());
        force_eval!(f.get_security_enabled());
        force_eval!(f.get_frame_pending());
        force_eval!(f.get_ack_request());
        force_eval!(f.get_intra_pan());
        force_eval!(f.get_dest_addr_mode());
        force_eval!(f.get_src_addr_mode());
        force_eval!(f.get_sequence_number());
        force_eval!(f.get_dest_pan_id());
        force_eval!(f.get_dest_addr());
        force_eval!(f.get_src_pan_id());
        force_eval!(f.get_src_addr());
        force_eval!(f.header());
        force_eval!(f.payload());
    }
}

#[entry]
fn main() -> ! {
    loop {}
}
