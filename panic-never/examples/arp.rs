#![no_std]
#![no_main]

use cortex_m::asm;
use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::{arp, mac, ipv4};

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut PACKET: Option<arp::Packet<&'static mut [u8]>> = None;

#[exception]
unsafe fn SysTick() {
    if let Ok(p) = arp::Packet::parse(&mut BUFFER[..]) {
        match p.downcast() {
            Ok(p) => {
                PACKET = Some(p);
            }
            Err(p) => {
                force_eval!(p.get_sha());
                force_eval!(p.get_spa());
                force_eval!(p.get_tha());
                force_eval!(p.get_tpa());
            }
        }
    } else {
        asm::nop();
    }
}

#[exception]
unsafe fn SVCall() {
    if let Some(mut p) = PACKET.take() {
        force_eval!(p.get_sha());
        force_eval!(p.get_spa());
        force_eval!(p.get_tha());
        force_eval!(p.get_tpa());
        force_eval!(p.is_a_probe());

        force_eval!(p.set_sha(mac::Addr::BROADCAST));
        force_eval!(p.set_spa(ipv4::Addr::UNSPECIFIED));
        force_eval!(p.set_tha(mac::Addr::BROADCAST));
        force_eval!(p.set_tpa(ipv4::Addr::UNSPECIFIED));
    }
}

#[entry]
fn main() -> ! {
    loop {}
}
