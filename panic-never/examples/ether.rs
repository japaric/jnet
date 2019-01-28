#![no_std]
#![no_main]

use cortex_m::asm;
use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::ether;

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut FRAME: Option<ether::Frame<&'static mut [u8]>> = None;

#[exception]
unsafe fn SysTick() {
    if let Ok(f) = ether::Frame::parse(&mut BUFFER[..]) {
        FRAME = Some(f);
    } else {
        asm::nop();
    }
}

#[exception]
unsafe fn SVCall() {
    if let Some(f) = FRAME.take() {
        force_eval!(f.get_destination());
        force_eval!(f.get_source());
        force_eval!(f.get_type());
        force_eval!(f.payload());
    }
}

#[entry]
fn main() -> ! {
    loop {}
}
