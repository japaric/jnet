#![deny(rust_2018_compatibility)]
#![deny(rust_2018_idioms)]
#![deny(warnings)]
#![feature(proc_macro_hygiene)]
#![no_std]

use cortex_m::interrupt;
use cortex_m::peripheral::ITM;
use enc28j60::{Enc28j60, Error, Unconnected};
use heapless::consts;
use jnet::{ipv4, mac};
use stlog::spanned::{error, info};
use stlog::GlobalLog;
use stm32f103xx_hal::{
    delay::Delay,
    gpio::{
        gpioa::{PA3, PA4, PA5, PA6, PA7},
        gpioc::PC13,
        Alternate, Floating, Input, Output, PushPull,
    },
    prelude::*,
    spi::Spi,
    stm32f103xx::{self, SPI1},
};

/* Configuration */
pub const MAC: mac::Addr = mac::Addr([0x20, 0x19, 0x01, 0x30, 0x23, 0x59]);
pub const IP: ipv4::Addr = ipv4::Addr([192, 168, 1, 33]);
#[allow(non_camel_case_types)]
pub type ARP_CACHE_SIZE = consts::U8;

/* Constants */
const KB: u16 = 1024; // bytes

pub type Ethernet = Enc28j60<
    Spi<
        SPI1,
        (
            PA5<Alternate<PushPull>>,
            PA6<Input<Floating>>,
            PA7<Alternate<PushPull>>,
        ),
    >,
    PA4<Output<PushPull>>,
    Unconnected,
    PA3<Output<PushPull>>,
>;

pub type Led = PC13<Output<PushPull>>;

pub fn init(core: cortex_m::Peripherals, device: stm32f103xx::Peripherals) -> (Ethernet, Led) {
    let mut rcc = device.RCC.constrain();
    let mut afio = device.AFIO.constrain(&mut rcc.apb2);
    let mut flash = device.FLASH.constrain();
    let mut gpioa = device.GPIOA.split(&mut rcc.apb2);

    let clocks = rcc.cfgr.freeze(&mut flash.acr);

    // LED
    let mut gpioc = device.GPIOC.split(&mut rcc.apb2);
    let mut led = gpioc.pc13.into_push_pull_output(&mut gpioc.crh);
    // turn the LED off during initialization
    led.set_high();

    // SPI
    let mut ncs = gpioa.pa4.into_push_pull_output(&mut gpioa.crl);
    ncs.set_high();
    let sck = gpioa.pa5.into_alternate_push_pull(&mut gpioa.crl);
    let miso = gpioa.pa6;
    let mosi = gpioa.pa7.into_alternate_push_pull(&mut gpioa.crl);
    let spi = Spi::spi1(
        device.SPI1,
        (sck, miso, mosi),
        &mut afio.mapr,
        enc28j60::MODE,
        1.mhz(),
        clocks,
        &mut rcc.apb2,
    );

    // ENC28J60
    let mut reset = gpioa.pa3.into_push_pull_output(&mut gpioa.crl);
    reset.set_low(); // held in reset
    let mut delay = Delay::new(core.SYST, clocks);
    let enc28j60 = Enc28j60::new(spi, ncs, Unconnected, reset, &mut delay, 7 * KB, MAC.0)
        .unwrap_or_else(|e| {
            match e {
                Error::ErevidIsZero => {
                    error!("EREVID = 0");
                }
                _ => {
                    error!("Enc28j60::new failed");
                }
            }

            fatal()
        });

    // LED on after initialization
    led.set_low();

    info!("Done with initialization");

    (enc28j60, led)
}

pub struct ItmLogger;

impl GlobalLog for ItmLogger {
    #[allow(unsafe_code)]
    fn log(&self, addr: u8) {
        // as written this will sometimes lose traces but we are fine with that
        unsafe { (*ITM::ptr()).stim[0].write_u8(addr) }
    }
}

pub fn fatal() -> ! {
    interrupt::disable();

    // (I wish this board had more than one LED)
    error!("fatal error");

    loop {}
}
