pub use crate::long::Register::*;
pub use crate::short::Register::*;

pub const RXMCR_PANCOORD: u8 = 1 << 3;
pub const RXMCR_PROMI: u8 = 1 << 0;
pub const RXMCR_ERRPKT: u8 = 1 << 1;

pub const TXMCR_SLOTTED: u8 = 1 << 5;

pub const TXNCON_TXNTRIG: u8 = 1 << 0;

pub const INTCON_RXIE: u8 = 1 << 3;
pub const INTCON_TXNIE: u8 = 1 << 0;

pub const INTSTAT_TXNIF: u8 = 1 << 0;
pub const INTSTAT_RXIF: u8 = 1 << 3;

pub const TXSTAT_TXNSTAT: u8 = 1 << 0;
