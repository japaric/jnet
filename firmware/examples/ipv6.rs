//! Simplified IPv6 stack
//!
//! This stack responds to "ping"s and echoes back UDP packets.

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

use blue_pill::{Ethernet, Led, CACHE_SIZE, MAC};
use cast::usize;
use cortex_m_rt::entry;
use enc28j60::Packet;
use heapless::FnvIndexMap;
use jnet::{coap, ether, icmpv6, ipv6, mac, udp};
use owning_slice::OwningSliceTo;
use stlog::{
    global_logger,
    spanned::{error, info, warning},
};
use stm32f103xx_hal::{prelude::*, stm32f103xx};
use ujson::{uDeserialize, uSerialize};

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

    let (mut ethernet, led) = blue_pill::init_enc28j60(core, device);

    ethernet.accept(&[Packet::Multicast]).unwrap_or_else(|_| {
        error!("receive filter configuration failed");

        blue_pill::fatal();
    });

    // we are dealing only with IPv6 and IPv6 never uses the broadcast address
    ethernet.ignore(&[Packet::Broadcast]).unwrap_or_else(|_| {
        error!("receive filter configuration failed");

        blue_pill::fatal();
    });

    info!("Done with initialization");

    run(ethernet, led).unwrap_or_else(|| {
        error!("`run` failed");

        blue_pill::fatal()
    });
}

const BUF_SZ: u8 = 255;

// main logic
fn run(mut ethernet: Ethernet, mut led: Led) -> Option<!> {
    let mut cache = FnvIndexMap::new();
    let mut buf = [0; BUF_SZ as usize];
    let mut extra_buf = [0; BUF_SZ as usize];

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

        match on_new_packet(
            &State {
                led: led.is_set_low(),
            },
            packet,
            &mut extra_buf,
            &mut cache,
        ) {
            Action::CoAP(change, eth) => {
                if let Some(on) = change {
                    info!("changing LED state");

                    if on {
                        led.set_low()
                    } else {
                        led.set_high()
                    }
                }

                info!("sending CoAP message");

                ethernet
                    .transmit(eth.as_bytes())
                    .map_err(|_| error!("Enc28j60::transmit failed"))
                    .ok()?;
            }

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

struct State {
    led: bool,
}

#[derive(uDeserialize, uSerialize)]
struct Payload {
    led: bool,
}

// IO-less / "pure" logic (NB logging does IO but it's easy to remove using `GLOBAL_LOGGER`)
fn on_new_packet<'a>(
    state: &State,
    bytes: OwningSliceTo<&'a mut [u8; BUF_SZ as usize], u8>,
    extra_buf: &'a mut [u8; BUF_SZ as usize],
    cache: &mut FnvIndexMap<ipv6::Addr, mac::Addr, CACHE_SIZE>,
) -> Action<'a> {
    let mut eth = if let Ok(f) = ether::Frame::parse(bytes) {
        info!("valid Ethernet frame");

        f
    } else {
        error!("invalid Ethernet frame");

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
                        error!("invalid ICMPv6 message");

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
                        error!("invalid UDP packet");

                        return Action::Nop;
                    };

                    let src_mac = if let Some(mac) = cache.get(&src_nl_addr) {
                        mac
                    } else {
                        error!("IP address not in the neighbor cache");

                        return Action::Nop;
                    };

                    let dst_port = udp.get_destination();
                    let src_port = udp.get_source();

                    if dst_port == coap::PORT {
                        info!("UDP: destination port is our CoAP port");

                        let coap = if let Ok(m) = coap::Message::parse(udp.payload()) {
                            info!("valid CoAP message");

                            m
                        } else {
                            warning!("invalid CoAP message; ignoring");

                            return Action::Nop;
                        };

                        if !coap.get_code().is_request()
                            || match coap.get_type() {
                                coap::Type::Confirmable | coap::Type::NonConfirmable => false,
                                _ => true,
                            }
                        {
                            warning!("CoAP message is not a valid request; ignoring");

                            return Action::Nop;
                        }

                        // prepare a response
                        let mut eth = ether::Frame::new(OwningSliceTo(extra_buf, BUF_SZ));
                        eth.set_destination(*src_mac);
                        eth.set_source(MAC);

                        let mut change = None;
                        eth.ipv6(|ip| {
                            ip.set_source(our_nl_addr);
                            ip.set_destination(src_nl_addr);

                            ip.udp(|udp| {
                                udp.set_source(coap::PORT);
                                udp.set_destination(src_port);

                                udp.coap(0, |resp| on_coap_request(state, coap, resp, &mut change))
                            });
                        });

                        return Action::CoAP(change, eth);
                    } else {
                        // echo back the packet

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

fn on_coap_request<'a>(
    state: &State,
    req: coap::Message<&[u8]>,
    mut resp: coap::Message<&'a mut [u8], coap::Unset>,
    change: &mut Option<bool>,
) -> coap::Message<&'a mut [u8]> {
    let code = req.get_code();

    resp.set_message_id(req.get_message_id());
    resp.set_type(if req.get_type() == coap::Type::Confirmable {
        coap::Type::Acknowledgement
    } else {
        coap::Type::NonConfirmable
    });

    if code == coap::Method::Get.into() {
        info!("CoAP: GET request");

        let mut opts = req.options();
        while let Some(opt) = opts.next() {
            if opt.number() == coap::OptionNumber::UriPath {
                if opt.value() == b"led" && opts.next().is_none() {
                    info!("CoAP: GET /led");

                    let mut tmp = [0; 13];
                    let payload =
                        ujson::write(&Payload { led: state.led }, &mut tmp).expect("unreachable");

                    resp.set_code(coap::Response::Content);
                    return resp.set_payload(payload.as_bytes());
                } else {
                    // fall-through: Not Found
                    break;
                }
            } else {
                error!("CoAP: Bad Option");

                resp.set_code(coap::Response::BadOption);
                return resp.no_payload();
            }
        }
    } else if code == coap::Method::Put.into() {
        info!("CoAP: PUT request");

        let mut opts = req.options();
        while let Some(opt) = opts.next() {
            if opt.number() == coap::OptionNumber::UriPath {
                if opt.value() == b"led" && opts.next().is_none() {
                    info!("CoAP: PUT /led");

                    if let Ok(payload) = ujson::from_bytes::<Payload>(req.payload()) {
                        info!("CoAP: Changed");

                        *change = Some(payload.led);

                        resp.set_code(coap::Response::Changed);
                        return resp.no_payload();
                    } else {
                        error!("CoAP: Bad Request");

                        resp.set_code(coap::Response::BadRequest);
                        return resp.no_payload();
                    }
                } else {
                    // fall-through: Not Found
                    break;
                }
            } else {
                error!("CoAP: Bad Option");

                resp.set_code(coap::Response::BadOption);
                return resp.no_payload();
            }
        }
    } else {
        info!("CoAP: Method Not Allowed");

        resp.set_code(coap::Response::MethodNotAllowed);
        return resp.no_payload();
    }

    error!("CoAP: Not Found");

    resp.set_code(coap::Response::NotFound);
    resp.no_payload()
}

enum Action<'a> {
    CoAP(
        Option<bool>,
        ether::Frame<OwningSliceTo<&'a mut [u8; BUF_SZ as usize], u8>>,
    ),

    EchoReply(ether::Frame<OwningSliceTo<&'a mut [u8; BUF_SZ as usize], u8>>),

    Nop,

    SolicitedNeighborAdvertisement(ether::Frame<OwningSliceTo<&'a mut [u8; BUF_SZ as usize], u8>>),

    UdpReply(ether::Frame<OwningSliceTo<&'a mut [u8; BUF_SZ as usize], u8>>),
}
