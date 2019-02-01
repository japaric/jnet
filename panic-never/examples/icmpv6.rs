#![no_std]
#![no_main]

use cortex_m::asm;
use cortex_m_rt::{entry, exception};
use panic_never::force_eval;

use jnet::{
    icmpv6::{self, EchoReply, EchoRequest, NeighborAdvertisement, NeighborSolicitation},
    ipv6, Unknown,
};

const LEN: usize = 128;
static mut BUFFER: [u8; LEN] = [0; LEN];
static mut NA: Option<icmpv6::Message<&'static mut [u8], NeighborAdvertisement>> = None;
static mut NS: Option<icmpv6::Message<&'static mut [u8], NeighborSolicitation>> = None;
static mut ERQ: Option<icmpv6::Message<&'static mut [u8], EchoRequest>> = None;
static mut ERP: Option<icmpv6::Message<&'static mut [u8], EchoReply>> = None;
static mut U: Option<icmpv6::Message<&'static mut [u8], Unknown>> = None;

#[exception]
unsafe fn SysTick() {
    if let Ok(m) = icmpv6::Message::parse(&mut BUFFER[..]) {
        match m.downcast::<NeighborAdvertisement>() {
            Ok(na) => NA = Some(na),
            Err(m) => match m.downcast::<NeighborSolicitation>() {
                Ok(ns) => NS = Some(ns),
                Err(m) => match m.downcast::<EchoRequest>() {
                    Ok(erq) => ERQ = Some(erq),
                    Err(m) => match m.downcast::<EchoReply>() {
                        Ok(erp) => ERP = Some(erp),
                        Err(u) => U = Some(u),
                    },
                },
            },
        }
    } else {
        asm::nop();
    }
}

#[exception]
unsafe fn SVCall() {
    if let Some(na) = NA.take() {
        force_eval!(na.get_type());
        force_eval!(na.get_code());
        force_eval!(na.get_checksum());
        force_eval!(na.get_router());
        force_eval!(na.get_solicited());
        force_eval!(na.get_override());
        force_eval!(na.get_target());
        force_eval!(na.get_target_ll());
    }

    if let Some(ns) = NS.take() {
        force_eval!(ns.get_type());
        force_eval!(ns.get_code());
        force_eval!(ns.get_checksum());
        force_eval!(ns.get_target());
        force_eval!(ns.get_source_ll());
    }

    if let Some(erq) = ERQ.take() {
        force_eval!(erq.get_type());
        force_eval!(erq.get_code());
        force_eval!(erq.get_checksum());
        force_eval!(erq.get_identifier());
        force_eval!(erq.get_sequence_number());
        force_eval!(erq.payload());
    }

    if let Some(erp) = ERP.take() {
        force_eval!(erp.get_type());
        force_eval!(erp.get_code());
        force_eval!(erp.get_checksum());
        force_eval!(erp.get_identifier());
        force_eval!(erp.get_sequence_number());
        force_eval!(erp.payload());
    }

    if let Some(u) = U.take() {
        force_eval!(u.get_type());
        force_eval!(u.get_code());
        force_eval!(u.get_checksum());
        force_eval!(u.verify_checksum(
            ipv6::Addr::ALL_NODES,
            ipv6::Addr::ALL_NODES
        ));
    }
}

#[entry]
fn main() -> ! {
    loop {}
}
