//! JNeT: japaric's network thingies
//!
//! There's no IO stuff in this crate. If you are looking for sockets and the like check out the
//! [`smoltcp`] crate.
//!
//! [`smoltcp`]: https://crates.io/crates/smoltcp
//!
//! This crate mainly contains an API to work with frames and packets in `no_std` context.
//!
//! It doesn't provide you any real *parser* though; it simply provides an API to mutate or access
//! the header and the payload of a frame / packet *in place*. This approach is the same as the one
//! used in `smoltcp`. The difference is that the API of this crate uses type state to (a) avoid
//! foot guns like sending an IPv4 packet with an invalid header checksum, and to (b) provide
//! specialized APIs when the packet type, e.g. ICMP EchoRequest, is known.
//!
//! If type state is not your cup of tea check out `smoltcp`'s [wire module]; do note that, as of
//! v0.4.0, `smoltcp` doesn't provide an API to work with CoAP messages whereas this crate does.
//!
//! [wire module]: https://docs.rs/smoltcp/0.4.0/smoltcp/wire/index.html
//!
//! # Examples
//!
//! - Parsing an ARP packet
//!
//! ```
//! use jnet::{arp, ether};
//!
//! let bytes = &[
//!     255, 255, 255, 255, 255, 255, // eth: destination
//!     120, 68, 118, 217, 106, 124, // eth: source
//!     8, 6, // eth: type
//!     0, 1, // arp: HTYPE = Ethernet
//!     8, 0, // arp: PTYPE = IPv4
//!     6, // arp: HLEN
//!     4, // arp: PLEN
//!     0, 2, // arp: OPER = Reply
//!     120, 68, 118, 217, 106, 124, // arp: SHA
//!     192, 168, 1, 1, // arp: SPA
//!     32, 24, 3, 1, 0, 0, // arp: THA
//!     192, 168, 1, 33, // arp: TPA
//!     0, 0, 0, 0, // eth: padding
//! ];
//!
//! let eth = ether::Frame::parse(&bytes[..]).unwrap();
//! let arp = arp::Packet::parse(eth.payload()).unwrap();
//!
//! assert_eq!(arp.get_htype(), arp::HardwareType::Ethernet);
//! assert_eq!(arp.get_ptype(), ether::Type::Ipv4);
//! assert_eq!(arp.get_oper(), arp::Operation::Reply);
//! ```
//!
//! - Constructing a CoAP message
//!
//! The general principle to building frames / packets / messages is to start with an (slightly)
//! oversized buffer and then proceed to shrink it to the right length.
//!
//! ```
//! use jnet::{coap, ether, ipv4, mac, udp};
//!
//! const MAC_SRC: mac::Addr = mac::Addr([0x20, 0x18, 0x03, 0x01, 0x00, 0x00]);
//! const MAC_DST: mac::Addr = mac::Addr([0x20, 0x18, 0x03, 0x13, 0x00, 0x00]);
//!
//! const IP_SRC: ipv4::Addr = ipv4::Addr([192, 168, 1, 11]);
//! const IP_DST: ipv4::Addr = ipv4::Addr([192, 168, 1, 33]);
//!
//! let mut bytes = [0; 60];
//! let mut buf = &mut bytes[..];
//!
//! // clean slate Ethernet frame with a total length of 60 bytes
//! let mut eth = ether::Frame::new(buf);
//! eth.set_destination(MAC_DST);
//! eth.set_source(MAC_SRC);
//!
//! eth.ipv4(|ip| {
//!     ip.set_source(IP_SRC);
//!     ip.set_destination(IP_DST);
//!     ip.udp(|udp| {
//!         udp.set_destination(coap::PORT);
//!         udp.coap(0, |mut coap| {
//!             coap.set_type(coap::Type::Confirmable);
//!             coap.set_code(coap::Method::Put);
//!             coap.add_option(coap::OptionNumber::UriPath, b"led");
//!             coap.set_payload(b"on")
//!         })
//!     });
//! });
//!
//! // At this point the Ethernet frame has shrunk to the size of its contents
//! // The excess memory is inaccessible
//! assert_eq!(eth.len(), 53);
//! ```

#![deny(missing_docs)]
#![deny(rust_2018_compatibility)]
#![deny(rust_2018_idioms)]
#![deny(warnings)]
#![no_std]

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

#[macro_use]
mod macros;

mod fmt;
mod traits;

// Medium Access Control layer
pub mod ether;
pub mod ieee802154;
pub mod mac;

pub mod arp;

// Network layer
pub mod ipv4;
pub mod ipv6;
// pub mod sixlowpan;

pub mod icmp;
// pub mod icmp6;

// Transport layer
pub mod udp;

// Application layer
pub mod coap;

/// [Type State] Unknown
pub enum Unknown {}

/// [Type State] Valid checksum
pub enum Valid {}

/// [Type State] Invalid checksum
pub enum Invalid {}
