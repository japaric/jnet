//! Simplified IPv6 stack
//!
//! This stack responds to "ping"s and echoes back UDP packets.

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_mut)]
#![allow(unused_variables)]
#![deny(rust_2018_compatibility)]
#![deny(rust_2018_idioms)]
#![deny(unsafe_code)]
#![deny(warnings)]
#![feature(never_type)]
#![feature(proc_macro_hygiene)]
#![no_main]
#![no_std]

#[allow(unused_extern_crates)]
extern crate panic_abort;
// extern crate panic_semihosting; // alternative panic handler

use blue_pill::{Ethernet, Led, ARP_CACHE_SIZE, IP, MAC};
use cast::usize;
use cortex_m_rt::entry;
use enc28j60::Packet;
use heapless::FnvIndexMap;
use jnet::{ether, icmpv6, ipv6, mac, udp};
use owning_slice::OwningSliceTo;
use stlog::{
    global_logger,
    spanned::{error, info, warning},
};
use stm32f103xx_hal::{prelude::*, stm32f103xx};

const BUF_SZ: u8 = 255;

#[global_logger]
static LOGGER: blue_pill::ItmLogger = blue_pill::ItmLogger;
// static LOGGER: stlog::NullLogger = stlog::NullLogger; // alt: no logs

fn our_nl_addr() -> ipv6::Addr {
    MAC.into_link_local_address()
}

#[entry]
fn main() -> ! {
    info!("Initializing ..");

    let core = cortex_m::Peripherals::take().unwrap_or_else(|| {
        error!("cortex_m::Peripherals::take failed");

        blue_pill::fatal();
    });

    let device = stm32f103xx::Peripherals::take().unwrap_or_else(|| {
        error!("stm32f103xx::Peripherals::take failed");

        blue_pill::fatal();
    });

    let (mut ethernet, led) = blue_pill::init(core, device);

    ethernet.accept(&[Packet::Multicast]).unwrap_or_else(|_| {
        error!("receive filter configuration failed");

        blue_pill::fatal();
    });

    // we are dealing only with IPv6 and IPv6 never uses the broadcast address
    ethernet.ignore(&[Packet::Broadcast]).unwrap_or_else(|_| {
        error!("receive filter configuration failed");

        blue_pill::fatal();
    });

    run(ethernet, led).unwrap_or_else(|| {
        error!("`run` failed");

        blue_pill::fatal()
    });
}

// main logic
fn run(mut ethernet: Ethernet, mut led: Led) -> Option<!> {
    let mut cache = FnvIndexMap::new();
    let mut buf = [0; BUF_SZ as usize];

    loop {
        let packet = if let Some(packet) = ethernet
            .next_packet()
            .map_err(|_| error!("Enc28j60::next_packet failed"))
            .ok()?
        {
            if usize(packet.len()) > usize::from(BUF_SZ) {
                error!("packet too big for our buffer");

                packet
                    .ignore()
                    .map_err(|_| error!("Packet::ignore failed"))
                    .ok()?;

                continue;
            } else {
                packet
                    .read(OwningSliceTo(&mut buf, BUF_SZ))
                    .map_err(|_| error!("Packet::read failed"))
                    .ok()?
            }
        } else {
            continue;
        };

        info!("new packet");

        match on_new_packet(packet, &mut cache) {
            Action::EchoReply(eth) => {
                info!("sending Echo Reply");

                led.toggle();

                ethernet
                    .transmit(eth.as_bytes())
                    .map_err(|_| error!("Enc28j60::transmit failed"))
                    .ok()?;
            }

            Action::Nop => {}

            Action::SolicitedNeighborAdvertisement(eth) => {
                info!("sending solicited Neighbor Advertisement");

                ethernet
                    .transmit(eth.as_bytes())
                    .map_err(|_| error!("Enc28j60::transmit failed"))
                    .ok()?;
            }

            Action::UdpReply(eth) => {
                info!("sending UDP packet");

                led.toggle();

                ethernet
                    .transmit(eth.as_bytes())
                    .map_err(|_| error!("Enc28j60::transmit failed"))
                    .ok()?;
            }
        }
    }
}

// IO-less / "pure" logic
fn on_new_packet<'a>(
    bytes: OwningSliceTo<&'a mut [u8; 255], u8>,
    cache: &mut FnvIndexMap<ipv6::Addr, mac::Addr, ARP_CACHE_SIZE>,
) -> Action<'a> {
    let mut eth = if let Ok(f) = ether::Frame::parse(bytes) {
        info!("valid Ethernet frame");

        f
    } else {
        error!("not a valid Ethernet frame");

        return Action::Nop;
    };

    let src_ll_addr = eth.get_source();
    let dest_ll_addr = eth.get_destination();

    if src_ll_addr.is_multicast() {
        error!("Ether: source address is a multicast address");

        return Action::Nop;
    }

    if !dest_ll_addr.is_unicast() & !dest_ll_addr.is_ipv6_multicast() {
        info!("not unicast packet or IPv6 multicast packet; ignoring");

        return Action::Nop;
    }

    match eth.get_type() {
        ether::Type::Ipv6 => {
            info!("EtherType: IPv6");

            let mut ip = if let Ok(ip) = ipv6::Packet::parse(eth.payload_mut()) {
                info!("valid IPv6 packet");

                ip
            } else {
                error!("not a valid IPv6 packet");

                return Action::Nop;
            };

            let src_nl_addr = ip.get_source();
            let dest_nl_addr = ip.get_destination();
            let our_nl_addr = our_nl_addr();

            // XXX we probably shouldn't do this
            if src_nl_addr.is_link_local() {
                info!("Updating the Neighbor cache");

                if cache.insert(src_nl_addr, src_ll_addr).is_err() {
                    warning!("Neighbor cache is full");
                }
            }

            if dest_nl_addr != our_nl_addr && dest_nl_addr != our_nl_addr.into_solicited_node() {
                info!("IPv6 not addressed to us; ignoring");

                return Action::Nop;
            }

            match ip.get_next_header() {
                ipv6::NextHeader::Ipv6Icmp => {
                    info!("IPv6 next-header: ICMPv6");

                    let hop_limit = ip.get_hop_limit();
                    let icmp = if let Ok(icmp) = icmpv6::Message::parse(ip.payload_mut()) {
                        info!("valid ICMPv6 message");

                        icmp
                    } else {
                        error!("not a valid ICMP message");

                        return Action::Nop;
                    };

                    match icmp.get_type() {
                        icmpv6::Type::NeighborSolicitation => {
                            info!("ICMPv6 type: NeighborSolicitation");

                            // RFC 4861 - Section 7.1.1 Validation of Neighbor Solicitations
                            // "The IP Hop Limit field has a value of 255"
                            if hop_limit != 255 {
                                error!("NeighborSolicitation: hop limit is not 255");

                                return Action::Nop;
                            }

                            let icmp =
                                if let Ok(m) = icmp.downcast::<icmpv6::NeighborSolicitation>() {
                                    m
                                } else {
                                    error!("not a valid NeighborSolicitation message");

                                    return Action::Nop;
                                };

                            // "ICMP Checksum is valid"
                            if !icmp.verify_checksum(src_nl_addr, dest_nl_addr) {
                                error!("NeighborSolicitation: invalid checksum");

                                return Action::Nop;
                            }

                            // "If the IP source address is the unspecified address, ..
                            if src_nl_addr.is_unspecified() {
                                // ".. the IP destination address is a solicited-node multicast
                                // address"
                                if !dest_nl_addr.is_solicited_node() {
                                    error!(
                                        "NeighborSolicitation: IP source = UNSPECIFIED but \
                                         IP destination was not a solicited node multicast address"
                                    );

                                    return Action::Nop;
                                }

                                // ".. there is no source link-layer address option in the message"
                                if icmp.get_source_ll().is_some() {
                                    error!(
                                        "NeighborSolicitation: IP source = UNSPECIFIED but \
                                         message includes the source link-layer address option"
                                    );

                                    return Action::Nop;
                                }
                            }

                            let target_addr = icmp.get_target();
                            if target_addr == our_nl_addr {
                                // they are asking for our ll address; prepare a reply
                                info!("NeighborSolicitation target address matches our address");

                                if src_nl_addr.is_unspecified() {
                                    // This is part of the DAD protocol, which we don't support
                                    warning!("DAD protocol detected; ignoring");

                                    return Action::Nop;
                                } else {
                                    // send back a solicited Neighbor Advertisement
                                    // see RFC4861 - Section 7.2.4. Sending Solicited Neighbor
                                    // Advertisements

                                    // retrieve the original buffer
                                    let buf = eth.free().unslice();

                                    let mut eth = ether::Frame::new(OwningSliceTo(buf, BUF_SZ));

                                    eth.set_source(MAC);
                                    eth.set_destination(src_ll_addr);

                                    eth.ipv6(|ip| {
                                        ip.set_next_header(ipv6::NextHeader::Ipv6Icmp);
                                        ip.set_source(our_nl_addr);
                                        ip.set_destination(src_nl_addr);

                                        ip.neighbor_advertisement(Some(MAC), |na| {
                                            na.set_override(true);
                                            na.set_solicited(true);
                                            na.set_router(false);

                                            na.set_target(target_addr);
                                        });
                                    });

                                    return Action::SolicitedNeighborAdvertisement(eth);
                                }
                            }
                        }

                        icmpv6::Type::EchoRequest => {
                            info!("ICMPv6 type: EchoRequest");

                            let src_mac = if let Some(mac) = cache.get(&src_nl_addr) {
                                mac
                            } else {
                                error!("IP address not in the neighbor cache");

                                return Action::Nop;
                            };

                            let request =
                                if let Ok(request) = icmp.downcast::<icmpv6::EchoRequest>() {
                                    request
                                } else {
                                    error!("not a valid NeighborSolicitation message");

                                    return Action::Nop;
                                };

                            // "ICMP Checksum is valid"
                            if !request.verify_checksum(src_nl_addr, dest_nl_addr) {
                                error!("EchoRequest: invalid checksum");

                                return Action::Nop;
                            }

                            // construct a reply in-place
                            // (the reply will have the same size as the request)
                            let mut reply: icmpv6::Message<_, icmpv6::EchoReply> = request.into();
                            reply.update_checksum(our_nl_addr, src_nl_addr);

                            // update the IP header
                            ip.set_source(our_nl_addr);
                            ip.set_destination(src_nl_addr);

                            // update the Ethernet header
                            eth.set_destination(*src_mac);
                            eth.set_source(MAC);

                            return Action::EchoReply(eth);
                        }

                        _ => {
                            info!("unexpected ICMPv6 type; ignoring");
                        }
                    }
                }

                ipv6::NextHeader::Udp => {
                    info!("IPv6 next-header: UDP");

                    let mut udp = if let Ok(udp) = udp::Packet::parse(ip.payload_mut()) {
                        info!("valid UDP packet");

                        if !udp.verify_ipv6_checksum(src_nl_addr, dest_nl_addr) {
                            error!("UDP: invalid checksum");

                            return Action::Nop;
                        }

                        udp
                    } else {
                        error!("not a valid UDP packet");

                        return Action::Nop;
                    };

                    if let Some(src_mac) = cache.get(&src_nl_addr) {
                        // echo back the packet
                        let src_port = udp.get_source();
                        let dst_port = udp.get_destination();

                        // we build the response in-place
                        // update the UDP header
                        udp.set_source(dst_port);
                        udp.set_destination(src_port);
                        udp.update_ipv6_checksum(our_nl_addr, src_nl_addr);

                        // update the IP header
                        ip.set_source(our_nl_addr);
                        ip.set_destination(src_nl_addr);

                        // update the Ethernet header
                        eth.set_destination(*src_mac);
                        eth.set_source(MAC);

                        return Action::UdpReply(eth);
                    } else {
                        error!("IP address not in the neighbor cache");

                        return Action::Nop;
                    }
                }

                _ => {
                    info!("unexpected IPv6 protocol; ignoring");
                }
            }
        }

        ether::Type::Ipv4 => {
            info!("EtherType: IPv4; ignoring");
        }

        _ => {
            info!("unexpected EtherType; ignoring");
        }
    }

    Action::Nop
}

enum Action<'a> {
    EchoReply(ether::Frame<OwningSliceTo<&'a mut [u8; BUF_SZ as usize], u8>>),
    Nop,
    SolicitedNeighborAdvertisement(ether::Frame<OwningSliceTo<&'a mut [u8; BUF_SZ as usize], u8>>),
    UdpReply(ether::Frame<OwningSliceTo<&'a mut [u8; BUF_SZ as usize], u8>>),
}
