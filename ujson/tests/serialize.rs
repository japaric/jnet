use ujson::uSerialize;

#[test]
fn one_field() {
    #[derive(uSerialize)]
    struct Led {
        led: bool,
    }

    assert_eq!(
        ujson::write(&Led { led: true }, &mut [0; 16]).unwrap(),
        "{\"led\":true}"
    );
}

#[test]
fn two_fields() {
    #[derive(uSerialize)]
    struct Pair {
        x: u8,
        y: u16,
    }

    assert_eq!(
        ujson::write(&Pair { x: 0, y: 42 }, &mut [0; 16]).unwrap(),
        "{\"x\":0,\"y\":42}"
    );
}

#[test]
fn array() {
    #[derive(uSerialize)]
    struct X {
        x: [u8; 33],
    }

    assert_eq!(
        ujson::write(&X { x: [0; 33] }, &mut [0; 128]).unwrap(),
        "{\"x\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"
    );
}
