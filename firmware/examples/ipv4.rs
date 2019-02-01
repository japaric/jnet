//! Simplified IPv4 stack
//!
//! This stack responds to "ping"s and echoes back UDP packets.
//!
//! ## Caveats
//!
//! - IP address is statically configured and hardcoded in the firmware
//! - Device does *not* announce or probe its IP address on boot
//! - Device will *not* attempt to ARP request IP addresses it doesn't know about
//!
//! # Testing
//!
//! ## `ping`
//!
//! On a Linux host issue these commands
//!
//! ``` text
//! $ sudo ip -s -s neigh flush all
//!
//! $ ping -c2 192.168.1.33
//! ```
//!
//! You should see the LED on the board blink twice. In the logs you should see something like this:
//!
//! ``` text
//! Jan 31 20:56:13.001 INFO Initializing .., loc: examples/ipv4.rs:41
//! Jan 31 20:56:13.003 INFO Done with initialization, loc: examples/ipv4.rs:114
//! Jan 31 20:56:15.641 INFO new packet, loc: examples/ipv4.rs:141
//! Jan 31 20:56:15.641 INFO valid Ethernet frame, loc: examples/ipv4.rs:178
//! Jan 31 20:56:15.641 INFO EtherType: ARP, loc: examples/ipv4.rs:189
//! Jan 31 20:56:15.641 INFO valid ARP packet, loc: examples/ipv4.rs:192
//! Jan 31 20:56:15.641 INFO valid IPv4-over-Ethernet ARP packet, loc: examples/ipv4.rs:195
//! Jan 31 20:56:15.641 INFO update ARP cache, loc: examples/ipv4.rs:198
//! Jan 31 20:56:15.641 INFO ARP request addressed to us, loc: examples/ipv4.rs:206
//! Jan 31 20:56:15.642 INFO sending ARP reply, loc: examples/ipv4.rs:145
//! Jan 31 20:56:15.667 INFO new packet, loc: examples/ipv4.rs:141
//! Jan 31 20:56:15.667 INFO valid Ethernet frame, loc: examples/ipv4.rs:178
//! Jan 31 20:56:15.667 INFO EtherType: IPv4, loc: examples/ipv4.rs:234
//! Jan 31 20:56:15.667 INFO valid IPv4 packet, loc: examples/ipv4.rs:237
//! Jan 31 20:56:15.667 INFO IPv4 protocol: ICMP, loc: examples/ipv4.rs:254
//! Jan 31 20:56:15.667 INFO valid ICMP message, loc: examples/ipv4.rs:257
//! Jan 31 20:56:15.667 INFO ICMP message has type 'Echo Request', loc: examples/ipv4.rs:260
//! Jan 31 20:56:15.667 INFO sending 'Echo Reply' ICMP message, loc: examples/ipv4.rs:153
//! Jan 31 20:56:16.643 INFO new packet, loc: examples/ipv4.rs:141
//! Jan 31 20:56:16.643 INFO valid Ethernet frame, loc: examples/ipv4.rs:178
//! Jan 31 20:56:16.643 INFO EtherType: IPv4, loc: examples/ipv4.rs:234
//! Jan 31 20:56:16.643 INFO valid IPv4 packet, loc: examples/ipv4.rs:237
//! Jan 31 20:56:16.643 INFO IPv4 protocol: ICMP, loc: examples/ipv4.rs:254
//! Jan 31 20:56:16.643 INFO valid ICMP message, loc: examples/ipv4.rs:257
//! Jan 31 20:56:16.643 INFO ICMP message has type 'Echo Request', loc: examples/ipv4.rs:260
//! Jan 31 20:56:16.643 INFO sending 'Echo Reply' ICMP message, loc: examples/ipv4.rs:153
//! ```
//!
//!  # `nc`
//!
//! On a Linux host issue these commands
//!
//! ``` text
//! nc -u 192.168.1.33 1337
//! hello
//! hello
//! world
//! world
//! ```
//!
//! You should see the LED on the board blink each time you send a message. You should also see the
//! message being echoed back. In the logs you should see something like this:
//!
//! ``` text
//! Jan 31 21:17:37.829 INFO new packet, loc: examples/ipv4.rs:192
//! Jan 31 21:17:37.829 INFO valid Ethernet frame, loc: examples/ipv4.rs:238
//! Jan 31 21:17:37.829 INFO EtherType: IPv4, loc: examples/ipv4.rs:294
//! Jan 31 21:17:37.829 INFO valid IPv4 packet, loc: examples/ipv4.rs:297
//! Jan 31 21:17:37.829 INFO IPv4 protocol: UDP, loc: examples/ipv4.rs:353
//! Jan 31 21:17:37.829 INFO valid UDP packet, loc: examples/ipv4.rs:356
//! Jan 31 21:17:37.829 INFO sending UDP packet, loc: examples/ipv4.rs:213
//! Jan 31 21:17:40.653 INFO new packet, loc: examples/ipv4.rs:192
//! Jan 31 21:17:40.654 INFO valid Ethernet frame, loc: examples/ipv4.rs:238
//! Jan 31 21:17:40.654 INFO EtherType: IPv4, loc: examples/ipv4.rs:294
//! Jan 31 21:17:40.654 INFO valid IPv4 packet, loc: examples/ipv4.rs:297
//! Jan 31 21:17:40.654 INFO IPv4 protocol: UDP, loc: examples/ipv4.rs:353
//! Jan 31 21:17:40.654 INFO valid UDP packet, loc: examples/ipv4.rs:356
//! Jan 31 21:17:40.654 INFO sending UDP packet, loc: examples/ipv4.rs:213
//! ```

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
use heapless::FnvIndexMap;
use jnet::{arp, ether, icmp, ipv4, mac, udp};
use stlog::{
    global_logger,
    spanned::{error, info, warning},
};
use stm32f103xx_hal::{prelude::*, stm32f103xx};

#[global_logger]
static LOGGER: blue_pill::ItmLogger = blue_pill::ItmLogger;
// static LOGGER: stlog::NullLogger = stlog::NullLogger; // alt: no logs

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

    let (ethernet, led) = blue_pill::init(core, device);

    run(ethernet, led).unwrap_or_else(|| {
        error!("`run` failed");

        blue_pill::fatal()
    });
}

// main logic
fn run(mut ethernet: Ethernet, mut led: Led) -> Option<!> {
    let mut cache = FnvIndexMap::new();
    let mut buf = [0; 256];
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

        match on_new_packet(packet, &mut cache) {
            Action::ArpReply(eth) => {
                info!("sending ARP reply");

                ethernet
                    .transmit(eth.as_bytes())
                    .map_err(|_| error!("Enc28j60::transmit failed"))
                    .ok()?;
            }

            Action::EchoReply(eth) => {
                info!("sending 'Echo Reply' ICMP message");

                led.toggle();

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

            Action::Nop => {}
        }
    }
}

// IO-less / "pure" logic
fn on_new_packet<'a>(
    bytes: &'a mut [u8],
    cache: &mut FnvIndexMap<ipv4::Addr, mac::Addr, ARP_CACHE_SIZE>,
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

                        if let Some(src_mac) = cache.get(&src_ip) {
                            // echo back the packet
                            let src_port = udp.get_source();
                            let dst_port = udp.get_destination();

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
                        } else {
                            error!("IP address not in the ARP cache");

                            return Action::Nop;
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

enum Action<'a> {
    ArpReply(ether::Frame<&'a mut [u8]>),
    EchoReply(ether::Frame<&'a mut [u8]>),
    UdpReply(ether::Frame<&'a mut [u8]>),
    Nop,
}
