#![no_std]
#![no_main]

use cortex_m::asm;
use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::coap;

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut MESSAGE: Option<coap::Message<&'static mut [u8]>> = None;

#[exception]
unsafe fn SysTick() {
    if let Ok(p) = coap::Message::parse(&mut BUFFER[..]) {
        MESSAGE = Some(p);
    } else {
        asm::nop();
    }
}

#[exception]
unsafe fn SVCall() {
    if let Some(m) = MESSAGE.take() {
        force_eval!(m.get_version());
        force_eval!(m.get_type());
        force_eval!(m.get_token_length());
        force_eval!(m.get_code());
        force_eval!(m.get_message_id());
        force_eval!(m.token());
        force_eval!(m.payload());
        for opt in m.options() {
            force_eval!(opt.number());
            force_eval!(opt.value());
        }
    }
}

#[entry]
fn main() -> ! {
    loop {}
}
