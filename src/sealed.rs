use crate::icmp::{EchoReply, EchoRequest};

// [Type State] EchoReply or EchoRequest
pub trait Echo: 'static {}

impl Echo for EchoReply {}
impl Echo for EchoRequest {}
