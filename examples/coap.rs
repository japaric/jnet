//! Very simple CoAP client

extern crate clap;
#[macro_use]
extern crate failure;
extern crate jnet;
extern crate rand;
extern crate url;

use std::{
    io::{self, Write},
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    str,
    time::{Duration, Instant},
};

use clap::{App, Arg};
use failure::{Error, ResultExt};
use jnet::coap;
use rand::Rng;
use url::{Host, Url};

/* Transmission parameters */
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

    const M: &str = "URL host must be an IP address";
    let ip = match url.host() {
        Some(Host::Ipv4(ip)) => ip,
        Some(Host::Domain(ip)) => ip.parse::<Ipv4Addr>().context(M)?,
        _ => bail!(M),
    };

    let mut rng = rand::thread_rng();
    let mut sock = None;
    let mut client = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 0);
    if let Some(port) = matches.value_of("port") {
        client.set_port(port.parse()?);
        sock = Some(UdpSocket::bind(client)?);
    } else {
        // Randomly pick a port
        const NTRIES: usize = 3;
        for i in 0..NTRIES {
            client.set_port(rng.gen());

            if i == NTRIES - 1 {
                // last try
                sock = Some(UdpSocket::bind(client)?);
            } else {
                if let Ok(s) = UdpSocket::bind(client) {
                    sock = Some(s);
                    break;
                }
            }
        }
    }

    let sock = sock.unwrap();

    // construct outgoing message
    let mut buf = [0; 128];
    let tx_buf = &mut buf[..];
    let mut mtx = coap::Message::new(tx_buf, 0);
    mtx.set_type(coap::Type::Confirmable);
    let mid = 0;
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
    let mut rx_buf = [0; 128];
    let mut timeout =
        Duration::from_millis(((1. + rng.next_f64() / 2.) * ACK_TIMEOUT as f64) as u64);

    let port = url.port().unwrap_or(coap::PORT);
    let server = SocketAddrV4::new(ip, port);
    sock.connect(server)?;
    for _ in 0..MAX_RETRANSMIT {
        writeln!(stderr, "-> {:?}", mtx).ok();
        sock.send(mtx.as_bytes()).unwrap();

        let start = Instant::now();
        let end = start + timeout;

        let mut acked = false;
        loop {
            let now = Instant::now();
            if now > end {
                break;
            }

            sock.set_read_timeout(Some(end - now))?;
            match sock.recv_from(&mut rx_buf) {
                Err(e) => assert_eq!(e.kind(), io::ErrorKind::WouldBlock),
                Ok((n, addr)) => {
                    if addr.ip() == *server.ip() && addr.port() == server.port() {
                        if let Ok(mrx) = coap::Message::parse(&rx_buf[..n]) {
                            if mrx.get_type() == coap::Type::Acknowledgement
                                && mrx.get_message_id() == mid
                            {
                                writeln!(stderr, "<- {:?}", mrx).ok();
                                let payload = mrx.payload();
                                if !payload.is_empty() {
                                    if let Ok(s) = str::from_utf8(payload) {
                                        writeln!(stdout, "{}", s).ok();
                                    } else {
                                        writeln!(stdout, "{:?}", payload).ok();
                                    }
                                }

                                acked = true;
                                break;
                            }
                        } else {
                            bail!("parsing incoming CoAP message")
                        }
                    }
                }
            }
        }

        if acked {
            break;
        } else {
            // try again
            timeout *= 2;
        }
    }

    Ok(())
}
