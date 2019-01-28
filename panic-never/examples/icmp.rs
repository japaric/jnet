#![no_std]
#![no_main]

use cortex_m::asm;
use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::{icmp, Unknown, Valid};

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut MESSAGE: Option<icmp::Message<&'static mut [u8], Unknown, Valid>> = None;

#[exception]
unsafe fn SysTick() {
    if let Ok(m) = icmp::Message::parse(&mut BUFFER[..]) {
        MESSAGE = Some(m);
    } else {
        asm::nop();
    }
}

#[exception]
unsafe fn SVCall() {
    if let Some(m) = MESSAGE.take() {
        force_eval!(m.get_type());
        force_eval!(m.get_code());
        force_eval!(m.payload());
        force_eval!(m.len());
    }
}

#[entry]
fn main() -> ! {
    loop {}
}
