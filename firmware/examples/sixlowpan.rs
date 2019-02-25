//! # References
//!
//! - [RFC4944 Transmission of IPv6 Packets over IEEE 802.15.4 Networks][rfc4944]
//!
//! [rfc4944]: https://tools.ietf.org/html/rfc4944
//!
//! - [RFC6775 Neighbor Discovery Optimization for IPv6 over Low-Power Wireless Personal Area
//! Networks (6LoWPANs)][rfc6775]
//!
//! [rfc6775]: https://tools.ietf.org/html/rfc6775

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

use blue_pill::{Led, Radio, CACHE_SIZE, EXTENDED_ADDRESS, PAN_ID};
use cortex_m_rt::entry;
use heapless::FnvIndexMap;
use jnet::{
    coap, icmpv6,
    ieee802154::{self, SrcDest},
    ipv6,
    ipv6::NextHeader,
    sixlowpan::{iphc, nhc},
};
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
    EXTENDED_ADDRESS.into_link_local_address()
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

    let (radio, led) = blue_pill::init_mrf24j40(core, device);

    info!("Done with initialization");

    // NOTE as per RFC6775 we don't need to do Duplicate Address Detection since we are using an
    // extended address (EUI-64) to derive our IPv6 address

    run(radio, led).unwrap_or_else(|| {
        error!("`run` failed");

        blue_pill::fatal()
    });
}

// main logic
const BUF_SZ: u8 = 128;
fn run(mut radio: Radio, mut led: Led) -> Option<!> {
    let mut cache = FnvIndexMap::new();
    let mut buf = [0; BUF_SZ as usize];
    let mut extra_buf = [0; BUF_SZ as usize];

    loop {
        let rx = radio
            .receive(OwningSliceTo(&mut buf, BUF_SZ))
            .map_err(|_| error!("Mrf24j40::receive failed"))
            .ok()?;

        info!("new packet");

        match on_new_frame(
            &State {
                led: led.is_set_low(),
            },
            rx.frame,
            &mut extra_buf,
            &mut cache,
        ) {
            Action::CoAP(change, mac) => {
                if let Some(on) = change {
                    info!("changing LED state");

                    if on {
                        led.set_low()
                    } else {
                        led.set_high()
                    }
                }

                info!("sending CoAP message");

                radio
                    .transmit(mac.as_bytes())
                    .map_err(|_| error!("Mrf24j40::transmit failed"))
                    .ok()?;
            }

            Action::EchoReply(mac) => {
                info!("sending Echo Reply");

                led.toggle();

                radio
                    .transmit(mac.as_bytes())
                    .map_err(|_| error!("Mrf24j40::transmit failed"))
                    .ok()?;
            }

            Action::Nop => {}

            Action::SolicitedNeighborAdvertisement(mac) => {
                info!("sending solicited Neighbor Advertisement");

                radio
                    .transmit(mac.as_bytes())
                    .map_err(|_| error!("Mrf24j40::transmit failed"))
                    .ok()?;
            }

            Action::UdpReply(mac) => {
                info!("sending UDP packet");

                led.toggle();

                radio
                    .transmit(mac.as_bytes())
                    .map_err(|_| error!("Mrf24j40::transmit failed"))
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
fn on_new_frame<'a>(
    state: &State,
    bytes: OwningSliceTo<&'a mut [u8; BUF_SZ as usize], u8>,
    extra_buf: &'a mut [u8; BUF_SZ as usize],
    cache: &mut FnvIndexMap<ipv6::Addr, ieee802154::Addr, CACHE_SIZE>,
) -> Action<'a> {
    let mut mac = if let Ok(f) = ieee802154::Frame::parse(bytes) {
        info!("valid MAC frame");

        f
    } else {
        error!("invalid MAC frame");

        return Action::Nop;
    };

    if mac.get_type() != ieee802154::Type::Data {
        info!("not a data frame");

        return Action::Nop;
    }

    if mac.get_security_enabled() {
        warning!("Security mode not supported; ignoring");

        return Action::Nop;
    }

    if !mac.get_intra_pan() {
        warning!("Not an intra-PAN frame; ignoring");

        return Action::Nop;
    }

    let src_ll_addr = if let Some(addr) = mac.get_src_addr() {
        addr
    } else {
        error!("malformed intra-PAN frame: it doesn't contain the source address");

        return Action::Nop;
    };
    let dest_ll_addr = if let Some(addr) = mac.get_dest_addr() {
        addr
    } else {
        error!("malformed intra-PAN frame: it doesn't contain the destination address");

        return Action::Nop;
    };

    let mut ip = if let Ok(ip) = iphc::Packet::parse(mac.payload_mut()) {
        info!("valid 6LoWPAN packet");

        ip
    } else {
        warning!("payload is not LOWPAN_IHC encoded; ignoring");

        return Action::Nop;
    };

    let src_nl_addr = match ip.get_source() {
        iphc::Addr::Complete(addr) => addr,
        iphc::Addr::Elided(ea) => ea.complete(src_ll_addr),
    };
    let dest_nl_addr = match ip.get_destination() {
        iphc::Addr::Complete(addr) => addr,
        iphc::Addr::Elided(ea) => ea.complete(dest_ll_addr),
    };
    let our_nl_addr = our_nl_addr();

    // XXX we probably shouldn't do this
    if src_nl_addr.is_link_local() {
        info!("Updating the Neighbor cache");

        if cache.insert(src_nl_addr, src_ll_addr).is_err() {
            warning!("Neighbor cache is full");
        }
    }

    if let Some(nh) = ip.get_next_header() {
        match nh {
            NextHeader::Ipv6Icmp => {
                info!("IPv6 next-header: ICMPv6");

                let hop_limit = ip.get_hop_limit();
                let icmp = if let Ok(icmp) = icmpv6::Message::parse(ip.payload_mut()) {
                    info!("valid ICMPv6 message");

                    icmp
                } else {
                    error!("invalid ICMPv6 message");

                    return Action::Nop;
                };

                // FIXME this is pretty much a copy paste of examples/ipv6.rs
                match icmp.get_type() {
                    icmpv6::Type::NeighborSolicitation => {
                        info!("ICMPv6 type: NeighborSolicitation");

                        // RFC 4861 - Section 7.1.1 Validation of Neighbor Solicitations
                        // "The IP Hop Limit field has a value of 255"
                        if hop_limit != 255 {
                            error!("NeighborSolicitation: hop limit is not 255");

                            return Action::Nop;
                        }

                        let icmp = if let Ok(m) = icmp.downcast::<icmpv6::NeighborSolicitation>() {
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
                                let buf = mac.free().unslice();

                                let pan_id = PAN_ID;
                                let src_addr = EXTENDED_ADDRESS.into();
                                let dest_addr = src_ll_addr;
                                let mut mac = ieee802154::Frame::data(
                                    OwningSliceTo(buf, BUF_SZ),
                                    SrcDest::IntraPan {
                                        pan_id,
                                        src_addr,
                                        dest_addr,
                                    },
                                );

                                mac.neighbor_advertisement(
                                    our_nl_addr,
                                    src_nl_addr,
                                    Some(EXTENDED_ADDRESS),
                                    |na| {
                                        na.set_override(true);
                                        na.set_solicited(true);
                                        na.set_router(false);

                                        na.set_target(target_addr);
                                    },
                                );

                                return Action::SolicitedNeighborAdvertisement(mac);
                            }
                        }
                    }

                    icmpv6::Type::EchoRequest => {
                        info!("ICMPv6 type: EchoRequest");

                        let request = if let Ok(request) = icmp.downcast::<icmpv6::EchoRequest>() {
                            request
                        } else {
                            error!("not a valid NeighborSolicitation message");

                            return Action::Nop;
                        };

                        let dest_addr = if let Some(addr) = cache.get(&src_nl_addr) {
                            *addr
                        } else {
                            error!("IP address not in the neighbor cache");

                            return Action::Nop;
                        };

                        let pan_id = PAN_ID;
                        let src_addr = EXTENDED_ADDRESS.into();
                        let mut mac = ieee802154::Frame::data(
                            OwningSliceTo(extra_buf, BUF_SZ),
                            SrcDest::IntraPan {
                                pan_id,
                                src_addr,
                                dest_addr,
                            },
                        );

                        mac.echo_reply(dest_nl_addr, src_nl_addr, |er| {
                            er.set_identifier(request.get_identifier());
                            er.set_sequence_number(request.get_sequence_number());
                            er.set_payload(request.payload());
                        });

                        return Action::EchoReply(mac);
                    }

                    _ => {
                        info!("unexpected ICMPv6 type; ignoring");
                    }
                }
            }

            _ => {
                warning!("unexpected next-header field; ignoring");
            }
        }
    } else {
        info!("payload is LOWPAN_NHC encoded");

        let udp = if let Ok(udp) = nhc::UdpPacket::parse(ip.payload()) {
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

        let dest_addr = if let Some(addr) = cache.get(&src_nl_addr) {
            *addr
        } else {
            error!("IP address not in the neighbor cache");

            return Action::Nop;
        };

        let dest_port = udp.get_destination();
        let src_port = udp.get_source();

        if dest_port == coap::PORT {
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
            let pan_id = PAN_ID;
            let src_addr = EXTENDED_ADDRESS.into();
            let mut mac = ieee802154::Frame::data(
                OwningSliceTo(extra_buf, BUF_SZ),
                SrcDest::IntraPan {
                    pan_id,
                    src_addr,
                    dest_addr,
                },
            );

            let mut change = None;
            mac.udp(our_nl_addr, dest_port, src_nl_addr, src_port, false, |u| {
                u.coap(0, |resp| on_coap_request(state, coap, resp, &mut change))
            });

            return Action::CoAP(change, mac);
        } else {
            // echo back the packet
            let pan_id = PAN_ID;
            let src_addr = EXTENDED_ADDRESS.into();
            let mut mac = ieee802154::Frame::data(
                OwningSliceTo(extra_buf, BUF_SZ),
                SrcDest::IntraPan {
                    pan_id,
                    src_addr,
                    dest_addr,
                },
            );

            mac.udp(our_nl_addr, dest_port, src_nl_addr, src_port, false, |u| {
                u.set_payload(udp.payload())
            });

            return Action::UdpReply(mac);
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
        ieee802154::Frame<OwningSliceTo<&'a mut [u8; BUF_SZ as usize], u8>>,
    ),

    EchoReply(ieee802154::Frame<OwningSliceTo<&'a mut [u8; BUF_SZ as usize], u8>>),

    Nop,

    SolicitedNeighborAdvertisement(
        ieee802154::Frame<OwningSliceTo<&'a mut [u8; BUF_SZ as usize], u8>>,
    ),

    UdpReply(ieee802154::Frame<OwningSliceTo<&'a mut [u8; BUF_SZ as usize], u8>>),
}
