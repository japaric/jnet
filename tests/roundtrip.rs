use jnet::{coap, ether, ipv4, mac, udp};

#[test]
fn coap4() {
    static PAYLOAD: &[u8] = b"Hello";

    let buffer: &mut [u8] = &mut [0; 256];

    let mut m = ether::Frame::new(buffer);
    m.set_source(mac::Addr::BROADCAST);
    m.set_destination(mac::Addr::BROADCAST);

    m.ipv4(|ip| {
        ip.set_source(ipv4::Addr::UNSPECIFIED);
        ip.set_destination(ipv4::Addr::UNSPECIFIED);

        ip.udp(|udp| {
            udp.set_source(coap::PORT);
            udp.set_destination(coap::PORT);

            udp.coap(0, |mut coap| {
                coap.set_code(coap::Response::Content);
                coap.set_payload(PAYLOAD)
            });
        });
    });

    let bytes = m.as_bytes();

    let eth = ether::Frame::parse(bytes).unwrap();
    assert_eq!(eth.get_source(), mac::Addr::BROADCAST);
    assert_eq!(eth.get_destination(), mac::Addr::BROADCAST);

    let ip = ipv4::Packet::parse(eth.payload()).unwrap();
    assert_eq!(ip.get_source(), ipv4::Addr::UNSPECIFIED);
    assert_eq!(ip.get_destination(), ipv4::Addr::UNSPECIFIED);

    let udp = udp::Packet::parse(ip.payload()).unwrap();
    assert_eq!(udp.get_source(), coap::PORT);
    assert_eq!(udp.get_destination(), coap::PORT);

    let coap = coap::Message::parse(udp.payload()).unwrap();
    assert_eq!(coap.get_code(), coap::Response::Content.into());
    assert_eq!(coap.payload(), PAYLOAD);
}
