#![deny(rust_2018_compatibility)]
#![deny(rust_2018_idioms)]
#![deny(warnings)]
#![no_std]

use cortex_m::peripheral::ITM;
use stlog::GlobalLog;

pub struct ItmLogger;

impl GlobalLog for ItmLogger {
    #[allow(unsafe_code)]
    fn log(&self, addr: u8) {
        // as written this will sometimes lose traces but we are fine with that
        unsafe { (*ITM::ptr()).stim[0].write_u8(addr) }
    }
}
