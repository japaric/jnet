use ujson::uDeserialize;

#[test]
fn one_field() {
    #[derive(uDeserialize, Debug, PartialEq)]
    struct Led {
        led: bool,
    }

    assert_eq!(
        ujson::from_bytes::<Led>("{\"led\":true}".as_bytes()).unwrap(),
        Led { led: true }
    );

    assert_eq!(
        ujson::from_bytes::<Led>("{\"led\":false}".as_bytes()).unwrap(),
        Led { led: false }
    );

    // with whitespace
    assert_eq!(
        ujson::from_bytes::<Led>("{ \"led\" : true }".as_bytes()).unwrap(),
        Led { led: true }
    );
}

#[test]
fn two_fields() {
    #[derive(uDeserialize, Debug, PartialEq)]
    struct Pair {
        x: u8,
        y: u16,
    }

    assert_eq!(
        ujson::from_bytes::<Pair>("{\"x\":0,\"y\":1}".as_bytes()).unwrap(),
        Pair { x: 0, y: 1 }
    );

    // reverse order
    assert_eq!(
        ujson::from_bytes::<Pair>("{\"y\":0,\"x\":1}".as_bytes()).unwrap(),
        Pair { y: 0, x: 1 }
    );
}
