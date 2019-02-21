#![deny(rust_2018_compatibility)]
#![deny(rust_2018_idioms)]
#![deny(warnings)]
#![feature(proc_macro_hygiene)]
#![no_std]

use cortex_m::interrupt;
use cortex_m::peripheral::ITM;
use enc28j60::{Enc28j60, Error};
use heapless::consts;
use jnet::{ieee802154, ipv4, mac};
use mrf24j40::{Channel, Mrf24j40, Role};
use stlog::spanned::error;
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
pub const MAC: mac::Addr = mac::Addr([0x20, 0x19, 0x02, 0x01, 0x23, 0x59]);
pub const IP: ipv4::Addr = ipv4::Addr([192, 168, 1, 33]);
#[allow(non_camel_case_types)]
pub type CACHE_SIZE = consts::U8;

pub const PAN_ID: ieee802154::PanId = ieee802154::PanId(0xbeef);
pub const EXTENDED_ADDRESS: ieee802154::ExtendedAddr =
    ieee802154::ExtendedAddr(0x20_19_02_20_00_23_59_59);

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
    enc28j60::Unconnected,
    PA3<Output<PushPull>>,
>;

pub type Led = PC13<Output<PushPull>>;

pub fn init_enc28j60(
    core: cortex_m::Peripherals,
    device: stm32f103xx::Peripherals,
) -> (Ethernet, Led) {
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
    let enc28j60 = Enc28j60::new(
        spi,
        ncs,
        enc28j60::Unconnected,
        reset,
        &mut delay,
        7 * KB,
        MAC.0,
    )
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

    (enc28j60, led)
}

// TODO
pub type Radio = Mrf24j40<
    Spi<
        SPI1,
        (
            PA5<Alternate<PushPull>>,
            PA6<Input<Floating>>,
            PA7<Alternate<PushPull>>,
        ),
    >,
    PA4<Output<PushPull>>,
    mrf24j40::Unconnected,
    PA3<Output<PushPull>>,
>;

pub fn init_mrf24j40(
    core: cortex_m::Peripherals,
    device: stm32f103xx::Peripherals,
) -> (Radio, Led) {
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
        mrf24j40::MODE,
        1.mhz(),
        clocks,
        &mut rcc.apb2,
    );

    // MRF24J40
    let mut reset = gpioa.pa3.into_push_pull_output(&mut gpioa.crl);
    reset.set_low(); // held in reset
    let mut delay = Delay::new(core.SYST, clocks);
    let mut mrf24j40 = Mrf24j40::new(
        Role::Device,
        Channel::_22,
        spi,
        ncs,
        mrf24j40::Unconnected,
        reset,
        &mut delay,
    )
    .unwrap_or_else(|_| {
        error!("Enc28j60::new failed");

        fatal()
    });

    mrf24j40.set_pan_id(PAN_ID.0).unwrap_or_else(|_| {
        error!("Mrf24j40::set_pan_id failed");

        fatal()
    });
    mrf24j40
        .set_extended_address(EXTENDED_ADDRESS.0)
        .unwrap_or_else(|_| {
            error!("Mrf24j40::set_extended_address failed");

            fatal()
        });

    // LED on after initialization
    led.set_low();

    (mrf24j40, led)
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
