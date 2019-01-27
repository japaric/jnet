#![feature(asm)]
#![no_std]
#![no_main]

use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::ether;

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];

#[exception]
unsafe fn SysTick() {
    if let Ok(f) = ether::Frame::parse(&mut BUFFER[..]) {
        force_eval!(f.get_destination());
        force_eval!(f.get_source());
        force_eval!(f.get_type());
        force_eval!(f.payload());
        force_eval!(f.len());
    } else {
        asm!("NOP" : : : : "volatile");
    }
}

#[entry]
fn main() -> ! {
    loop {}
}
