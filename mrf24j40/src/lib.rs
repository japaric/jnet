//! MRF24J40
//!
//! # References
//!
//! - [MRF24J40 data sheet][ds]
//! - [IEEE 802.15.4-2003 standard][standard]
//!
//! [ds]: http://ww1.microchip.com/downloads/en/DeviceDoc/39776C.pdf
//! [standard]: https://www.iith.ac.in/~tbr/teaching/docs/802.15.4-2003.pdf

#![deny(rust_2018_compatibility)]
#![deny(rust_2018_idioms)]
#![deny(warnings)]
#![no_std]

use core::fmt;

use as_slice::{AsMutSlice, AsSlice};
use byteorder::{ByteOrder, BE, LE};
use embedded_hal::{
    blocking::{
        self,
        delay::{DelayMs, DelayUs},
    },
    digital::{InputPin, OutputPin},
    spi::{Mode, Phase, Polarity},
};
use owning_slice::IntoSliceTo;

pub mod long;
pub mod reg;
pub mod short;

#[derive(Debug)]
pub enum Error<E> {
    Spi(E),
    TxRetryCountExceeded,
}

impl<E> From<E> for Error<E> {
    fn from(e: E) -> Self {
        Error::Spi(e)
    }
}

/// SPI mode = (0, 0)
pub const MODE: Mode = Mode {
    phase: Phase::CaptureOnFirstTransition,
    polarity: Polarity::IdleLow,
};

pub unsafe trait IntPin {}

pub struct Unconnected;

unsafe impl IntPin for Unconnected {}

unsafe impl<IP> IntPin for IP where IP: InputPin {}

pub struct Mrf24j40<SPI, NCS, INT, RESET> {
    _int: INT,
    ncs: NCS,
    pending_interrupts: PendingInterrupts,
    reset: RESET,
    spi: SPI,
    write_in_progress: bool,
}

enum Action {
    Read = 0,
    Write = 1,
}

pub enum Role {
    Coordinator,
    Device,
    Monitor,
}

enum Register {
    Short(short::Register),
    Long(long::Register),
}

impl<E, SPI, NCS, INT, RESET> Mrf24j40<SPI, NCS, INT, RESET>
where
    SPI: blocking::spi::Transfer<u8, Error = E> + blocking::spi::Write<u8, Error = E>,
    NCS: OutputPin,
    RESET: OutputPin,
{
    pub fn new<D>(
        role: Role,
        channel: Channel,
        spi: SPI,
        mut ncs: NCS,
        _int: INT,
        mut reset: RESET,
        delay: &mut D,
    ) -> Result<Self, E>
    where
        D: DelayMs<u8> + DelayUs<u8>,
        INT: IntPin,
    {
        ncs.set_high();
        reset.set_high();

        let mut mrf24j40 = Mrf24j40 {
            _int,
            pending_interrupts: PendingInterrupts::new(),
            ncs,
            reset,
            spi,
            write_in_progress: false,
        };

        // reset the MRF24J40
        // Section 3.1 says that we should wait 250 us for the reset to be registered, and then to
        // wait 2 ms before accessing the device
        mrf24j40.reset.set_low();
        mrf24j40.reset.set_high();
        delay.delay_us(250);
        delay.delay_ms(3);

        /* Initialization as per "Example 3-1" in the data sheet */
        // TODO remove sanity checks

        // FIFOEN = 1, TXONTS = 0x6
        mrf24j40.write_register(reg::PACON2, 0x98)?;

        // RFSTBL = 0x9
        mrf24j40.write_register(reg::TXSTBL, 0x95)?;

        // RFOPT = 0x03
        mrf24j40.write_register(reg::RFCON0, 0x03)?;

        // VCOOPT = 0x02 (NOTE "Example 3-1" says RFCON1 = 0x1, but data sheet says that 0x2 is the
        // optimal value)
        mrf24j40.write_register(reg::RFCON1, 0x02)?;

        // Enable PLL (PLLEN = 1)
        mrf24j40.write_register(reg::RFCON2, 0x80)?;

        // TXFIL = 1, 20MRECVR = 1
        mrf24j40.write_register(reg::RFCON6, 0x90)?;

        // SLPCLKSEL = 0x2 (100 KHz internal oscillator)
        mrf24j40.write_register(reg::RFCON7, 0x80)?;

        // RFVCO = 1
        mrf24j40.write_register(reg::RFCON8, 0x10)?;

        // CLKOUTEN = 1, SLPCLKDIV = 0x01
        mrf24j40.write_register(reg::SLPCON1, 0x21)?;

        match role {
            // 3.8.2.1 Configuring Nonbeacon-enabled PAN coordinator
            Role::Coordinator => {
                // PANCOORD = 1
                mrf24j40.write_register(reg::RXMCR, reg::RXMCR_PANCOORD)?;

                // BO = 0xF, SO = 0xF (default)
                debug_assert_eq!(mrf24j40.read_register(reg::ORDER).ok().unwrap(), 0xFF);
                // mrf24j40.write_register(reg::ORDER, 0xFF)?;
            }
            // 3.8.2.2 Configuring Nonbeacon-enabled device
            Role::Device => {
                // PANCOORD = 0
            }
            Role::Monitor => {
                // PROMI = 1
                mrf24j40.write_register(reg::RXMCR, reg::RXMCR_PROMI)?;

                // XXX include packets with CRC errors?
                // mrf24j40.write_register(reg::RXMCR, reg::RXMCR_ERRPKT)?;
            }
        }

        // SLOTTED = 0 (default value)
        debug_assert_eq!(
            mrf24j40.read_register(reg::TXMCR).ok().unwrap(),
            0b0001_1100
        );

        // CCAMODE = ED (0b10)
        mrf24j40.write_register(reg::BBREG2, 0x80)?;

        // set CCA ED threshold to the recommended value
        mrf24j40.write_register(reg::CCAEDTH, 0x60)?;

        // append RSSI value to RXFIFO
        mrf24j40.write_register(reg::BBREG6, 0x40)?;

        mrf24j40.write_register(reg::RFCON0, ((channel as u8) << 4) | 0x03)?;

        // TODO lower TX power?

        // Reset RF state machine
        mrf24j40.write_register(reg::RFCTL, 0x04)?;
        mrf24j40.write_register(reg::RFCTL, 0x00)?;
        delay.delay_us(192);

        Ok(mrf24j40)
    }

    /* Getters */
    pub fn get_extended_address(&mut self) -> Result<u64, E> {
        let buf = [
            self.read_register(reg::EADR0)?,
            self.read_register(reg::EADR1)?,
            self.read_register(reg::EADR2)?,
            self.read_register(reg::EADR3)?,
            self.read_register(reg::EADR4)?,
            self.read_register(reg::EADR5)?,
            self.read_register(reg::EADR6)?,
            self.read_register(reg::EADR7)?,
        ];

        Ok(LE::read_u64(&buf))
    }

    pub fn get_pan_id(&mut self) -> Result<u16, E> {
        let buf = [
            self.read_register(reg::PANIDL)?,
            self.read_register(reg::PANIDH)?,
        ];

        Ok(LE::read_u16(&buf))
    }

    pub fn get_short_address(&mut self) -> Result<u16, E> {
        let buf = [
            self.read_register(reg::SADRL)?,
            self.read_register(reg::SADRH)?,
        ];

        Ok(LE::read_u16(&buf))
    }

    pub fn pending_interrupts(&mut self) -> Result<PendingInterrupts, E> {
        self.pending_interrupts.byte |= self.read_register(reg::INTSTAT)?;
        Ok(self.pending_interrupts)
    }

    pub fn write_in_progress(&self) -> bool {
        self.write_in_progress
    }

    /* Setters */
    pub fn set_pan_id(&mut self, id: u16) -> Result<(), E> {
        let mut buf: [u8; 2] = [0; 2];
        LE::write_u16(&mut buf, id);

        self.write_register(reg::PANIDL, buf[0])?;
        self.write_register(reg::PANIDH, buf[1])?;

        Ok(())
    }

    pub fn set_extended_address(&mut self, addr: u64) -> Result<(), E> {
        let mut buf = [0; 8];
        LE::write_u64(&mut buf, addr);

        self.write_register(reg::EADR0, buf[0])?;
        self.write_register(reg::EADR1, buf[1])?;
        self.write_register(reg::EADR2, buf[2])?;
        self.write_register(reg::EADR3, buf[3])?;
        self.write_register(reg::EADR4, buf[4])?;
        self.write_register(reg::EADR5, buf[5])?;
        self.write_register(reg::EADR6, buf[6])?;
        self.write_register(reg::EADR7, buf[7])?;

        Ok(())
    }

    pub fn set_short_addr(&mut self, addr: u16) -> Result<(), E> {
        let mut buf: [u8; 2] = [0; 2];
        LE::write_u16(&mut buf, addr);

        self.write_register(reg::SADRL, buf[0])?;
        self.write_register(reg::SADRH, buf[1])?;

        Ok(())
    }

    /* I/O */
    pub fn flush(&mut self) -> Result<(), Error<E>> {
        if self.write_in_progress {
            let pending_interrupts = self.pending_interrupts;

            // if transfer not done
            if !pending_interrupts.txn() {
                // wait until transfer is done
                while !self.pending_interrupts()?.txn() {}
            }

            self.write_in_progress = false;
            self.pending_interrupts.clear_txn();
            let stat = self.read_register(reg::TXSTAT)?;

            if stat & reg::TXSTAT_TXNSTAT == 0 {
                Ok(())
            } else {
                Err(Error::TxRetryCountExceeded)
            }
        } else {
            Ok(())
        }
    }

    pub fn receive<B>(&mut self, buffer: B) -> Result<Rx<B::SliceTo>, E>
    where
        B: IntoSliceTo<u8, Element = u8>,
        B::SliceTo: AsMutSlice<Element = u8>
    {
        // See "Example 3-2 Steps to read RX FIFO"
        // if no frame ready to read
        if !self.pending_interrupts.rx() {
            // wait for a new frame
            while !self.pending_interrupts()?.rx() {}
        }

        // Set RXDECINV = 1; disable receiving packets off air
        self.write_register(reg::BBREG1, 1 << 2)?;

        let rx = self.with_ncs_low(move |spi| {
            let mut opcode: [u8; 2] = [0; 2];
            BE::write_u16(&mut opcode, long::opcode(long::RX_FIFO, Action::Read));

            spi.write(&opcode)?;

            // NOTE(& 0b1111111) hint the compiler that `len`, including the footer (FCS), is less
            // than 128 (127 is the maximum size for MAC frames according to the IEEE spec)
            let frame_size = spi.transfer(&mut [0])?[0];
            debug_assert!(frame_size < 128 && frame_size > 2);
            let len = (frame_size - 2) & 0b1111111;

            let mut frame = buffer.into_slice_to(len);
            spi.transfer(frame.as_mut_slice())?;

            let mut fcs: [u8; 2] = [0; 2];
            spi.transfer(&mut fcs)?;
            let fcs = BE::read_u16(&fcs);

            let lqi = spi.transfer(&mut [0])?[0];
            let rssi = spi.transfer(&mut [0])?[0];

            Ok(Rx {
                frame,
                fcs,
                lqi,
                rssi,
            })
        })?;

        // Set RXDECINV = 0; enable receiving packets
        self.write_register(reg::BBREG1, 0)?;

        self.pending_interrupts.clear_rx();
        Ok(rx)
    }

    pub fn transmit(&mut self, buffer: &[u8]) -> Result<(), Error<E>> {
        assert!(buffer.len() <= 125);

        self.flush()?;

        self.with_ncs_low(|spi| {
            let mut opcode: [u8; 2] = [0; 2];
            BE::write_u16(
                &mut opcode,
                long::opcode(long::TX_NORMAL_FIFO, Action::Write),
            );

            spi.write(&opcode)?;

            // Header length: don't care in unsecured mode
            spi.write(&[0])?;

            // Frame length
            spi.write(&[buffer.len() as u8])?;

            spi.write(buffer)
        })?;

        // TXNTRIG = 1, start transmission
        self.modify_register(reg::TXNCON, |r| r | reg::TXNCON_TXNTRIG)?;

        self.write_in_progress = true;

        Ok(())
    }

    fn read_register<R>(&mut self, reg: R) -> Result<u8, E>
    where
        R: Into<Register>,
    {
        match reg.into() {
            Register::Short(reg) => self.short_read_register(reg),
            Register::Long(reg) => self.long_read_register(reg),
        }
    }

    fn modify_register<R, F>(&mut self, reg: R, f: F) -> Result<(), E>
    where
        F: FnOnce(u8) -> u8,
        R: Into<Register>,
    {
        match reg.into() {
            Register::Short(reg) => self.short_modify_register(reg, f),
            Register::Long(reg) => self.long_modify_register(reg, f),
        }
    }

    fn write_register<R>(&mut self, reg: R, value: u8) -> Result<(), E>
    where
        R: Into<Register>,
    {
        match reg.into() {
            Register::Short(reg) => self.short_write_register(reg, value),
            Register::Long(reg) => self.long_write_register(reg, value),
        }
    }

    fn long_read_register(&mut self, reg: long::Register) -> Result<u8, E> {
        let mut buf: [u8; 1] = [0];
        self.long_read_memory(reg.addr(), &mut buf)?;
        Ok(buf[0])
    }

    pub fn long_read_memory<'b>(&mut self, addr: u16, mut buf: &'b mut [u8]) -> Result<(), E> {
        self.with_ncs_low(move |spi| {
            let mut opcode: [u8; 2] = [0; 2];
            BE::write_u16(&mut opcode, long::opcode(addr, Action::Read));

            spi.write(&opcode)?;
            spi.transfer(&mut buf)?;
            Ok(())
        })
    }

    fn long_modify_register<F>(&mut self, reg: long::Register, f: F) -> Result<(), E>
    where
        F: FnOnce(u8) -> u8,
    {
        let curr = self.long_read_register(reg)?;
        let new = f(curr);
        self.long_write_register(reg, new)
    }

    pub fn long_write_memory<'b>(&mut self, addr: u16, buf: &'b [u8]) -> Result<(), E> {
        self.with_ncs_low(|spi| {
            let mut opcode: [u8; 2] = [0; 2];
            BE::write_u16(&mut opcode, long::opcode(addr, Action::Write));

            spi.write(&opcode)?;
            spi.write(buf)?;
            Ok(())
        })
    }

    fn long_write_register(&mut self, reg: long::Register, value: u8) -> Result<(), E> {
        self.long_write_memory(reg.addr(), &[value])
    }

    fn short_read_memory(&mut self, addr: u8, buf: &mut [u8]) -> Result<(), E> {
        self.with_ncs_low(|spi| {
            spi.write(&[short::opcode(addr, Action::Read)])?;
            spi.transfer(buf)?;
            Ok(())
        })
    }

    fn short_read_register(&mut self, reg: short::Register) -> Result<u8, E> {
        let mut buf: [u8; 1] = [0];
        self.short_read_memory(reg.addr(), &mut buf)?;
        Ok(buf[0])
    }

    fn short_modify_register<F>(&mut self, reg: short::Register, f: F) -> Result<(), E>
    where
        F: FnOnce(u8) -> u8,
    {
        let curr = self.short_read_register(reg)?;
        let new = f(curr);
        self.short_write_register(reg, new)
    }

    fn short_write_memory(&mut self, addr: u8, buf: &[u8]) -> Result<(), E> {
        self.with_ncs_low(|spi| {
            spi.write(&[short::opcode(addr, Action::Write)])?;
            spi.write(buf)
        })
    }

    fn short_write_register(&mut self, reg: short::Register, value: u8) -> Result<(), E> {
        self.short_write_memory(reg.addr(), &[value])
    }

    fn with_ncs_low<F, R>(&mut self, f: F) -> Result<R, E>
    where
        F: FnOnce(&mut SPI) -> Result<R, E>,
    {
        self.ncs.set_low();
        let ret = f(&mut self.spi);
        self.ncs.set_high();
        ret
    }
}

impl<E, SPI, NCS, INT, RESET> Mrf24j40<SPI, NCS, INT, RESET>
where
    SPI: blocking::spi::Transfer<u8, Error = E> + blocking::spi::Write<u8, Error = E>,
    NCS: OutputPin,
    RESET: OutputPin,
    INT: InputPin,
{
    pub fn listen(&mut self, events: &[Event]) -> Result<(), E> {
        if events.is_empty() {
            return Ok(());
        }

        let mut intcon = self.read_register(reg::INTCON)?;

        for event in events {
            match *event {
                Event::Rx => intcon &= !reg::INTCON_RXIE,
                Event::Txn => intcon &= !reg::INTCON_TXNIE,
            }
        }

        self.write_register(reg::INTCON, intcon)
    }

    pub fn unlisten(&mut self, events: &[Event]) -> Result<(), E> {
        if events.is_empty() {
            return Ok(());
        }

        let mut intcon = self.read_register(reg::INTCON)?;

        for event in events {
            match *event {
                Event::Rx => intcon |= reg::INTCON_RXIE,
                Event::Txn => intcon |= reg::INTCON_TXNIE,
            }
        }

        self.write_register(reg::INTCON, intcon)
    }
}

#[derive(Clone, Copy)]
pub struct PendingInterrupts {
    byte: u8,
}

impl PendingInterrupts {
    fn new() -> PendingInterrupts {
        PendingInterrupts { byte: 0 }
    }

    pub fn rx(&self) -> bool {
        self.byte & reg::INTSTAT_RXIF != 0
    }

    pub fn txn(&self) -> bool {
        self.byte & reg::INTSTAT_TXNIF != 0
    }

    fn clear_rx(&mut self) {
        self.byte &= !reg::INTSTAT_RXIF;
    }

    fn clear_txn(&mut self) {
        self.byte &= !reg::INTSTAT_TXNIF;
    }
}

pub struct Rx<F>
where
    F: AsSlice<Element = u8>,
{
    pub frame: F,

    /// Frame Control Sequence
    pub fcs: u16,

    /// Link Quality Indication
    pub lqi: u8,

    /// Received Signal Strength Indicator
    pub rssi: u8,
}

impl<F> fmt::Debug for Rx<F>
where
    F: AsSlice<Element = u8>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rx")
            .field("frame", &self.frame.as_slice())
            .field("fcs", &self.fcs)
            .field("lqi", &self.lqi)
            .field("rssi", &self.rssi)
            .finish()
    }
}

#[derive(Clone, Copy)]
pub enum Channel {
    /// 2405 MHz
    _11 = 0b0000,
    _12 = 0b0001,
    _13 = 0b0010,
    _14 = 0b0011,
    _15 = 0b0100,
    _16 = 0b0101,
    _17 = 0b0110,
    _18 = 0b0111,
    _19 = 0b1000,
    _20 = 0b1001,
    _21 = 0b1010,
    _22 = 0b1011,
    _23 = 0b1100,
    _24 = 0b1101,
    _25 = 0b1110,
    /// 2480 MHz
    _26 = 0b1111,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Event {
    /// Normal TX (transmission)
    Txn,
    /// RX (reception)
    Rx,
}
