#![feature(proc_macro_hygiene)]
#![no_main]
#![no_std]

extern crate panic_abort;
extern crate stm32f103xx_hal;

use blue_pill::ItmLogger;
use cortex_m_rt::entry;
use stlog::{global_logger, spanned::info};

#[global_logger]
static LOGGER: ItmLogger = ItmLogger;

#[entry]
fn main() -> ! {
    info!("Hello, world!");

    loop {}
}
