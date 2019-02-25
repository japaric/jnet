//! Simplified IPv4 stack
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

use blue_pill::{Ethernet, Led, CACHE_SIZE, IP, MAC};
use cast::usize;
use cortex_m_rt::entry;
use heapless::FnvIndexMap;
use jnet::{arp, coap, ether, icmp, ipv4, mac, udp};
use stlog::{
    global_logger,
    spanned::{error, info, warning},
};
use stm32f103xx_hal::{prelude::*, stm32f103xx};
use ujson::{uDeserialize, uSerialize};

#[global_logger]
static LOGGER: blue_pill::ItmLogger = blue_pill::ItmLogger;
// static LOGGER: stlog::NullLogger = stlog::NullLogger; // alt: no logs
// NOTE(^) LLD errors with `NullLogger` so you have to switch to GNU LD (see .cargo/config)

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

    let (ethernet, led) = blue_pill::init_enc28j60(core, device);

    info!("Done with initialization");

    run(ethernet, led).unwrap_or_else(|| {
        error!("`run` failed");

        blue_pill::fatal()
    });
}

const BUF_SZ: usize = 256;

// main logic
fn run(mut ethernet: Ethernet, mut led: Led) -> Option<!> {
    let mut cache = FnvIndexMap::new();
    let mut buf = [0; BUF_SZ];
    let mut extra_buf = [0; BUF_SZ];
    loop {
        let packet = if let Some(packet) = ethernet
            .next_packet()
            .map_err(|_| error!("Enc28j60::next_packet failed"))
            .ok()?
        {
            if usize(packet.len()) > buf.len() {
                error!("packet too big for our buffer");

                packet
                    .ignore()
                    .map_err(|_| error!("Packet::ignore failed"))
                    .ok()?;

                continue;
            } else {
                packet
                    .read(&mut buf[..])
                    .map_err(|_| error!("Packet::read failed"))
                    .ok()?
            }
        } else {
            continue;
        };

        info!("new packet");

        let eth = match on_new_packet(
            &State {
                led: led.is_set_low(),
            },
            packet,
            &mut cache,
            &mut extra_buf,
        ) {
            Action::ArpReply(eth) => {
                info!("sending ARP reply");

                eth
            }

            Action::EchoReply(eth) => {
                info!("sending 'Echo Reply' ICMP message");

                led.toggle();

                eth
            }

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

                eth
            }

            Action::UdpReply(eth) => {
                info!("sending UDP packet");

                led.toggle();

                eth
            }

            Action::Nop => continue,
        };

        let bytes = eth.as_bytes();
        if bytes.len() <= usize::from(ethernet.mtu()) {
            ethernet
                .transmit(eth.as_bytes())
                .map_err(|_| error!("Enc28j60::transmit failed"))
                .ok()?;
        } else {
            error!("Ethernet frame exceeds MTU");
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
    bytes: &'a mut [u8],
    cache: &mut FnvIndexMap<ipv4::Addr, mac::Addr, CACHE_SIZE>,
    extra_buf: &'a mut [u8],
) -> Action<'a> {
    let mut eth = if let Ok(f) = ether::Frame::parse(bytes) {
        info!("valid Ethernet frame");
        f
    } else {
        error!("not a valid Ethernet frame");
        return Action::Nop;
    };

    let src_mac = eth.get_source();

    match eth.get_type() {
        ether::Type::Arp => {
            info!("EtherType: ARP");

            if let Ok(arp) = arp::Packet::parse(eth.payload_mut()) {
                info!("valid ARP packet");

                if let Ok(mut arp) = arp.downcast() {
                    info!("valid IPv4-over-Ethernet ARP packet");

                    if !arp.is_a_probe() {
                        info!("update ARP cache");

                        if cache.insert(arp.get_spa(), arp.get_sha()).is_err() {
                            warning!("ARP cache is full");
                        }
                    }

                    // are they asking for our MAC address?
                    if arp.get_oper() == arp::Operation::Request && arp.get_tpa() == IP {
                        info!("ARP request addressed to us");

                        // construct a reply in-place
                        // (the reply will have the same size as the request)
                        let tha = arp.get_sha();
                        let tpa = arp.get_spa();

                        arp.set_oper(arp::Operation::Reply);
                        arp.set_sha(MAC);
                        arp.set_spa(IP);
                        arp.set_tha(tha);
                        arp.set_tpa(tpa);

                        // update the Ethernet header
                        eth.set_destination(tha);
                        eth.set_source(MAC);

                        return Action::ArpReply(eth);
                    }
                } else {
                    error!("not an IPv4-over-Ethernet ARP packet");
                }
            } else {
                error!("invalid ARP packet");
            }
        }

        ether::Type::Ipv4 => {
            info!("EtherType: IPv4");

            let mut ip = if let Ok(ip) = ipv4::Packet::parse(eth.payload_mut()) {
                info!("valid IPv4 packet");

                ip
            } else {
                error!("not a valid IPv4 packet");

                return Action::Nop;
            };

            let src_ip = ip.get_source();

            if !src_mac.is_broadcast() {
                if cache.insert(src_ip, src_mac).is_err() {
                    warning!("ARP cache is full");
                }
            }

            match ip.get_protocol() {
                ipv4::Protocol::Icmp => {
                    info!("IPv4 protocol: ICMP");

                    let icmp = if let Ok(icmp) = icmp::Message::parse(ip.payload_mut()) {
                        info!("valid ICMP message");

                        icmp
                    } else {
                        error!("not a valid ICMP message");

                        return Action::Nop;
                    };

                    if let Ok(request) = icmp.downcast::<icmp::EchoRequest>() {
                        info!("ICMP message has type 'Echo Request'");

                        let src_mac = if let Some(mac) = cache.get(&src_ip) {
                            mac
                        } else {
                            error!("IP address not in the ARP cache");

                            return Action::Nop;
                        };

                        // construct a reply in-place
                        // (the reply will have the same size as the request)
                        let _reply: icmp::Message<_, icmp::EchoReply, _> = request.into();

                        // update the IP header
                        let mut ip = ip.set_source(IP);
                        ip.set_destination(src_ip);
                        let _ip = ip.update_checksum();

                        // update the Ethernet header
                        eth.set_destination(*src_mac);
                        eth.set_source(MAC);

                        return Action::EchoReply(eth);
                    } else {
                        error!("not a 'Echo Request' ICMP message");
                    }
                }

                ipv4::Protocol::Udp => {
                    info!("IPv4 protocol: UDP");

                    if let Ok(mut udp) = udp::Packet::parse(ip.payload_mut()) {
                        info!("valid UDP packet");

                        let src_mac = if let Some(mac) = cache.get(&src_ip) {
                            mac
                        } else {
                            error!("the IP address of the sender is not in the ARP cache");

                            return Action::Nop;
                        };

                        let dst_port = udp.get_destination();

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

                            let src_port = udp.get_source();

                            // prepare a response
                            let mut eth = ether::Frame::new(extra_buf);
                            eth.set_destination(*src_mac);
                            eth.set_source(MAC);

                            let mut change = None;
                            eth.ipv4(|ip| {
                                ip.set_source(IP);
                                ip.set_destination(src_ip);

                                ip.udp(|udp| {
                                    udp.set_source(coap::PORT);
                                    udp.set_destination(src_port);

                                    udp.coap(0, |resp| {
                                        on_coap_request(state, coap, resp, &mut change)
                                    })
                                });
                            });

                            return Action::CoAP(change, eth);
                        } else {
                            // echo back the packet
                            let src_port = udp.get_source();

                            // we build the response in-place
                            // update the UDP header
                            udp.set_source(dst_port);
                            udp.set_destination(src_port);
                            udp.zero_checksum();

                            // update the IP header
                            let mut ip = ip.set_source(IP);
                            ip.set_destination(src_ip);
                            let _ip = ip.update_checksum();

                            // update the Ethernet header
                            eth.set_destination(*src_mac);
                            eth.set_source(MAC);

                            return Action::UdpReply(eth);
                        }
                    } else {
                        error!("not a valid UDP packet");

                        return Action::Nop;
                    }
                }

                _ => {
                    info!("unexpected IPv4 protocol");
                }
            }
        }

        _ => {
            info!("unexpected EtherType");
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
    ArpReply(ether::Frame<&'a mut [u8]>),
    EchoReply(ether::Frame<&'a mut [u8]>),
    CoAP(Option<bool>, ether::Frame<&'a mut [u8]>),
    Nop,
    UdpReply(ether::Frame<&'a mut [u8]>),
}
