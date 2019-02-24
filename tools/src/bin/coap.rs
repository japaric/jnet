//! Very simple IPv4 CoAP client

#![deny(rust_2018_compatibility)]
#![deny(rust_2018_idioms)]

use std::{
    ffi::CString,
    io::{self, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
    str,
    time::Duration,
};

use clap::{App, Arg};
use failure::{bail, Error, ResultExt};
use jnet::coap;
use rand::{
    distributions::{Distribution, Uniform},
    Rng,
};
use url::{Host, Url};

/* Transmission parameters */
const ACK_RANDOM_FACTOR: f64 = 1.5;
const ACK_TIMEOUT: u16 = 2_000; // ms
const MAX_RETRANSMIT: u8 = 4;

fn main() -> Result<(), Error> {
    let matches = App::new("coap")
        .arg(
            Arg::with_name("port")
                .help("local UDP port to bind (if omitted a random one will be chosen)")
                .required(false)
                .short("p")
                .takes_value(true)
                .value_name("PORT"),
        )
        .arg(
            Arg::with_name("interface")
                .help("IPv6 interface to bind the client to")
                .required(false)
                .short("I")
                .takes_value(true)
                .value_name("IFACE"),
        )
        .arg(
            Arg::with_name("method")
                .help("one of DELETE, GET, POST or PUT")
                .required(true)
                .value_name("METHOD"),
        )
        .arg(
            Arg::with_name("url")
                .help("The scheme must be 'coap'")
                .required(true)
                .value_name("URL"),
        )
        .arg(
            Arg::with_name("payload")
                .help("The payload of the request")
                .value_name("PAYLOAD"),
        )
        .get_matches();

    let method = match matches.value_of("method").unwrap() {
        "DELETE" => coap::Method::Delete,
        "GET" => coap::Method::Get,
        "POST" => coap::Method::Post,
        "PUT" => coap::Method::Put,
        _ => panic!(),
    };

    let url = Url::parse(matches.value_of("url").unwrap()).context("parsing URL")?;
    if url.scheme() != "coap" {
        bail!("URL scheme must be 'coap'")
    }

    let mut rng = rand::thread_rng();

    static M: &str = "URL host must be an IP address";
    let port = url.port().unwrap_or(coap::PORT);
    let (client, server): (_, SocketAddr) = match url.host() {
        Some(Host::Domain(s)) => (
            UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?,
            SocketAddrV4::new(s.parse::<Ipv4Addr>().context(M)?, port).into(),
        ),

        Some(Host::Ipv6(ip)) => {
            let scope_id = if let Some(iface) = matches.value_of("interface") {
                let cstr = CString::new(iface)?;
                let out = unsafe { libc::if_nametoindex(cstr.as_ptr()) };

                if out == 0 {
                    return Err(io::Error::last_os_error().into());
                } else {
                    out
                }
            } else {
                0
            };

            (
                // TODO use a port that results in port compression (6LoWPAN)
                UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, scope_id))?,
                SocketAddrV6::new(ip, port, 0, scope_id).into(),
            )
        }

        _ => bail!(M),
    };

    client.connect(server)?;

    // construct outgoing message
    let mut buf = [0; 256];
    let mut mtx = coap::Message::new(&mut buf[..], 0);
    // FIXME multicast messages must be Non-Confirmable
    mtx.set_type(coap::Type::Confirmable);
    let mid = rng.gen();
    mtx.set_code(method);
    mtx.set_message_id(mid);
    if let Some(segments) = url.path_segments() {
        for segment in segments {
            mtx.add_option(coap::OptionNumber::UriPath, segment.as_bytes());
        }
    }
    let mtx = mtx.set_payload(
        matches
            .value_of("payload")
            .map(|s| s.as_bytes())
            .unwrap_or(&[]),
    );

    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut stdout = stdout.lock();
    let mut stderr = stderr.lock();
    let mut rx_buf = [0; 256];
    let between = Uniform::new(1.0, ACK_RANDOM_FACTOR);
    let mut timeout = Duration::from_millis((between.sample(&mut rng) * ACK_TIMEOUT as f64) as u64);

    client.connect(server)?;
    for _ in 0..MAX_RETRANSMIT {
        writeln!(stderr, "-> {:?}", mtx).ok();
        client.send(mtx.as_bytes()).unwrap();

        client.set_read_timeout(Some(timeout))?;

        let n = match client.recv(&mut rx_buf) {
            Ok(n) => n,
            Err(e) => {
                if e.kind() == io::ErrorKind::TimedOut {
                    // try again
                    timeout *= 2;

                    continue;
                } else {
                    return Err(e.into());
                }
            }
        };

        if let Ok(mrx) = coap::Message::parse(&rx_buf[..n]) {
            if mrx.get_type() == coap::Type::Acknowledgement && mrx.get_message_id() == mid {
                writeln!(stderr, "<- {:?}", mrx).ok();
                let payload = mrx.payload();
                if !payload.is_empty() {
                    if let Ok(s) = str::from_utf8(payload) {
                        writeln!(stdout, "{}", s).ok();
                    } else {
                        writeln!(stdout, "{:?}", payload).ok();
                    }
                }

                return Ok(());
            } else {
                bail!("received unrelated response");
            }
        } else {
            bail!("parsing incoming CoAP message")
        }
    }

    bail!("timed out")
}
