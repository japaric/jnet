# Firmware examples

This directory contains firmware examples that make use of the `jnet` crate.

All these examples feature:

- Proper error handling. No `unwrap`-ing `Result`s or `Option`s. Exception: pure
  operations that are known to not fail (e.g. `"0".parse::<u8>()`).

- Fatal I/O errors are handled using a "fatal error" handler rather than the
  panic handler, which is reserved for programmer errors (AKA bugs).

- Extensive (but super cheap) logging.

- Very few panicking branches after optimization. These are actually unreachable
  but the optimizer is not able to remove them.

List of examples:

- [`ipv4`](#ipv4), a simplified IPv4 over Ethernet stack.
- [`ipv6`](#ipv6), a simplified IPv6 over Ethernet stack.
- [`sixlowpan`](#sixlowpan), a simplified IPv6 over 802.15.4 stack.

## `ipv4`

A simplified IPv4 stack. This stack responds to "ping"s, echoes back UDP packets
and exposes an LED as a CoAP resource.

### Caveats

- The IP address is statically configured and hardcoded in the firmware

- The device does *not* announce or probe its IP address on boot

- The device will *not* attempt to ARP request IP addresses it doesn't know
about

### `ping` test

On a Linux host issue these commands:

``` console
$ # flush the ARP cache
$ sudo ip -s -s neigh flush all

$ arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.1.1              ether   xx:xx:xx:xx:xx:xx   C                     wlan0

$ ping -c2 192.168.1.33
PING 192.168.1.33 (192.168.1.33) 56(84) bytes of data.
64 bytes from 192.168.1.33: icmp_seq=1 ttl=64 time=71.9 ms
64 bytes from 192.168.1.33: icmp_seq=2 ttl=64 time=36.2 ms

--- 192.168.1.33 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 2ms
rtt min/avg/max/mdev = 36.215/54.072/71.930/17.859 ms
```

You should see the LED on the board blink twice. The ARP cache should now
include the device:

``` console
$ arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
192.168.1.1              ether   xx:xx:xx:xx:xx:xx   C                     wlan0
192.168.1.33             ether   20:19:02:01:23:59   C                     wlan0
```

In the logs you should see something like this:

``` text
Feb 20 00:20:38.680 INFO Initializing .., loc: examples/ipv4.rs:67
Feb 20 00:20:38.680 INFO Done with initialization, loc: src/lib.rs:102

Feb 20 00:20:50.686 INFO new packet, loc: examples/ipv4.rs:119
Feb 20 00:20:50.686 INFO valid Ethernet frame, loc: examples/ipv4.rs:164
Feb 20 00:20:50.686 INFO EtherType: ARP, loc: examples/ipv4.rs:175
Feb 20 00:20:50.686 INFO valid ARP packet, loc: examples/ipv4.rs:178
Feb 20 00:20:50.686 INFO valid IPv4-over-Ethernet ARP packet, loc: examples/ipv4.rs:181
Feb 20 00:20:50.686 INFO update ARP cache, loc: examples/ipv4.rs:184
Feb 20 00:20:50.686 INFO ARP request addressed to us, loc: examples/ipv4.rs:193
Feb 20 00:20:50.686 INFO sending ARP reply, loc: examples/ipv4.rs:123

Feb 20 00:20:50.717 INFO new packet, loc: examples/ipv4.rs:119
Feb 20 00:20:50.717 INFO valid Ethernet frame, loc: examples/ipv4.rs:164
Feb 20 00:20:50.717 INFO EtherType: IPv4, loc: examples/ipv4.rs:221
Feb 20 00:20:50.717 INFO valid IPv4 packet, loc: examples/ipv4.rs:224
Feb 20 00:20:50.717 INFO IPv4 protocol: ICMP, loc: examples/ipv4.rs:243
Feb 20 00:20:50.717 INFO valid ICMP message, loc: examples/ipv4.rs:246
Feb 20 00:20:50.717 INFO ICMP message has type 'Echo Request', loc: examples/ipv4.rs:256
Feb 20 00:20:50.717 INFO sending 'Echo Reply' ICMP message, loc: examples/ipv4.rs:132

Feb 20 00:20:51.688 INFO new packet, loc: examples/ipv4.rs:119
Feb 20 00:20:51.688 INFO valid Ethernet frame, loc: examples/ipv4.rs:164
Feb 20 00:20:51.688 INFO EtherType: IPv4, loc: examples/ipv4.rs:221
Feb 20 00:20:51.688 INFO valid IPv4 packet, loc: examples/ipv4.rs:224
Feb 20 00:20:51.688 INFO IPv4 protocol: ICMP, loc: examples/ipv4.rs:243
Feb 20 00:20:51.688 INFO valid ICMP message, loc: examples/ipv4.rs:246
Feb 20 00:20:51.688 INFO ICMP message has type 'Echo Request', loc: examples/ipv4.rs:256
Feb 20 00:20:51.688 INFO sending 'Echo Reply' ICMP message, loc: examples/ipv4.rs:132
```

### `nc` test

On a Linux host issue these commands

``` console
$ nc -u 192.168.1.33 1337
hello
hello
world
world
```
You should see the LED on the board blink each time you send a message. You
should also see the message being echoed back.

In the logs you should see something like this:

``` text
Feb 20 00:22:40.210 INFO new packet, loc: examples/ipv4.rs:119
Feb 20 00:22:40.210 INFO valid Ethernet frame, loc: examples/ipv4.rs:164
Feb 20 00:22:40.210 INFO EtherType: IPv4, loc: examples/ipv4.rs:221
Feb 20 00:22:40.210 INFO valid IPv4 packet, loc: examples/ipv4.rs:224
Feb 20 00:22:40.210 INFO IPv4 protocol: UDP, loc: examples/ipv4.rs:286
Feb 20 00:22:40.210 INFO valid UDP packet, loc: examples/ipv4.rs:289
Feb 20 00:22:40.210 INFO sending UDP packet, loc: examples/ipv4.rs:143

Feb 20 00:22:42.354 INFO new packet, loc: examples/ipv4.rs:119
Feb 20 00:22:42.354 INFO valid Ethernet frame, loc: examples/ipv4.rs:164
Feb 20 00:22:42.354 INFO EtherType: IPv4, loc: examples/ipv4.rs:221
Feb 20 00:22:42.354 INFO valid IPv4 packet, loc: examples/ipv4.rs:224
Feb 20 00:22:42.354 INFO IPv4 protocol: UDP, loc: examples/ipv4.rs:286
Feb 20 00:22:42.354 INFO valid UDP packet, loc: examples/ipv4.rs:289
Feb 20 00:22:42.354 INFO sending UDP packet, loc: examples/ipv4.rs:143
```

### `coap` test

The `coap` tool is in the `/tools` directory. Install it first.

On a Linux host issue these commands:

- `GET /led`, returns the state of the LED

``` console
$ coap GET coap://192.168.1.33/led
-> coap::Message { version: 1, type: Confirmable, code: Method::Get, message_id: 19248, options: {UriPath: "led"} }
<- coap::Message { version: 1, type: Acknowledgement, code: Response::Content, message_id: 19248 }
{"led":true}
```

``` text
Feb 22 21:58:56.041 INFO new packet, loc: examples/ipv4.rs:93
Feb 22 21:58:56.041 INFO valid Ethernet frame, loc: examples/ipv4.rs:178
Feb 22 21:58:56.041 INFO EtherType: IPv4, loc: examples/ipv4.rs:235
Feb 22 21:58:56.041 INFO valid IPv4 packet, loc: examples/ipv4.rs:238
Feb 22 21:58:56.041 INFO IPv4 protocol: UDP, loc: examples/ipv4.rs:300
Feb 22 21:58:56.041 INFO valid UDP packet, loc: examples/ipv4.rs:303
Feb 22 21:58:56.041 INFO UDP: destination port is our CoAP port, loc: examples/ipv4.rs:316
Feb 22 21:58:56.041 INFO valid CoAP message, loc: examples/ipv4.rs:319
Feb 22 21:58:56.041 INFO CoAP: GET request, loc: examples/ipv4.rs:421
Feb 22 21:58:56.041 INFO CoAP: GET /led, loc: examples/ipv4.rs:427
Feb 22 21:58:56.041 INFO sending CoAP message, loc: examples/ipv4.rs:134
```

- `GET /brightness`, returns "Not Found" because this resource doesn't exist

``` console
$ coap GET coap://192.168.1.33/brightness
-> coap::Message { version: 1, type: Confirmable, code: Method::Get, message_id: 7984, options: {UriPath: "brightness"} }
<- coap::Message { version: 1, type: Acknowledgement, code: Response::NotFound, message_id: 7984 }
```

``` text
Feb 22 21:59:56.825 INFO new packet, loc: examples/ipv4.rs:93
Feb 22 21:59:56.825 INFO valid Ethernet frame, loc: examples/ipv4.rs:178
Feb 22 21:59:56.825 INFO EtherType: IPv4, loc: examples/ipv4.rs:235
Feb 22 21:59:56.825 INFO valid IPv4 packet, loc: examples/ipv4.rs:238
Feb 22 21:59:56.825 INFO IPv4 protocol: UDP, loc: examples/ipv4.rs:300
Feb 22 21:59:56.825 INFO valid UDP packet, loc: examples/ipv4.rs:303
Feb 22 21:59:56.825 INFO UDP: destination port is our CoAP port, loc: examples/ipv4.rs:316
Feb 22 21:59:56.825 INFO valid CoAP message, loc: examples/ipv4.rs:319
Feb 22 21:59:56.825 INFO CoAP: GET request, loc: examples/ipv4.rs:421
Feb 22 21:59:56.825 ERRO CoAP: Not Found, loc: examples/ipv4.rs:486
Feb 22 21:59:56.825 INFO sending CoAP message, loc: examples/ipv4.rs:134
```

- `PUT /led`, changes the state of the LED

``` console
$ coap PUT coap://192.168.1.33/led '{"led":false}'
-> coap::Message { version: 1, type: Confirmable, code: Method::Put, message_id: 4030, options: {UriPath: "led"} }
<- coap::Message { version: 1, type: Acknowledgement, code: Response::Changed, message_id: 4030 }
```

``` text
Feb 22 22:02:02.330 INFO new packet, loc: examples/ipv4.rs:93
Feb 22 22:02:02.331 INFO valid Ethernet frame, loc: examples/ipv4.rs:178
Feb 22 22:02:02.331 INFO EtherType: IPv4, loc: examples/ipv4.rs:235
Feb 22 22:02:02.331 INFO valid IPv4 packet, loc: examples/ipv4.rs:238
Feb 22 22:02:02.331 INFO IPv4 protocol: UDP, loc: examples/ipv4.rs:300
Feb 22 22:02:02.331 INFO valid UDP packet, loc: examples/ipv4.rs:303
Feb 22 22:02:02.331 INFO UDP: destination port is our CoAP port, loc: examples/ipv4.rs:316
Feb 22 22:02:02.331 INFO valid CoAP message, loc: examples/ipv4.rs:319
Feb 22 22:02:02.331 INFO CoAP: PUT request, loc: examples/ipv4.rs:447
Feb 22 22:02:02.331 INFO CoAP: PUT /led, loc: examples/ipv4.rs:453
Feb 22 22:02:02.331 INFO CoAP: Changed, loc: examples/ipv4.rs:456
Feb 22 22:02:02.331 INFO changing LED state, loc: examples/ipv4.rs:125
Feb 22 22:02:02.331 INFO sending CoAP message, loc: examples/ipv4.rs:134
```

## `ipv6`

A simplified IPv6 stack. This stack responds to "ping"s echoes back UDP packets
and exposes an LED as a CoAP resource.

### Caveats

- The device does *not* perform Duplicate Address Detection (DAD) on boot

- The device will *not* send Neighbor Solicitations for IP addresses it doesn't
  know about.

### `ping` test

On a Linux host issue these commands:

``` console
$ # flush the neighbor cache
$ sudo ip -s -s neigh flush all

$ ip -6 neigh show

$ ping -6 -c2 fe80::2219:2ff:fe01:2359%wlan0
PING fe80::2219:2ff:fe01:2359%wlan0(fe80::2219:2ff:fe01:2359%wlan0) 56 data bytes
64 bytes from fe80::2219:2ff:fe01:2359%wlan0: icmp_seq=1 ttl=64 time=32.10 ms
64 bytes from fe80::2219:2ff:fe01:2359%wlan0: icmp_seq=2 ttl=64 time=26.10 ms

--- fe80::2219:2ff:fe01:2359%wlan0 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 2ms
rtt min/avg/max/mdev = 26.992/29.979/32.966/2.987 ms
```

You should see the LED on the board blink twice. The neighbor cache should now
include the device:

``` console
$ ip -6 neigh show
fe80::2219:2ff:fe01:2359 dev wlan0 lladdr 20:19:02:01:23:59 REACHABLE
```

In the logs you should see something like this:

``` text
Feb 20 00:28:00.148 INFO Initializing .., loc: examples/ipv6.rs:47
Feb 20 00:28:00.148 INFO Done with initialization, loc: src/lib.rs:102

Feb 20 00:28:10.444 INFO new packet, loc: examples/ipv6.rs:113
Feb 20 00:28:10.444 INFO valid Ethernet frame, loc: examples/ipv6.rs:158
Feb 20 00:28:10.444 INFO EtherType: IPv6, loc: examples/ipv6.rs:184
Feb 20 00:28:10.444 INFO valid IPv6 packet, loc: examples/ipv6.rs:187
Feb 20 00:28:10.444 INFO Updating the Neighbor cache, loc: examples/ipv6.rs:202
Feb 20 00:28:10.444 INFO IPv6 next-header: ICMPv6, loc: examples/ipv6.rs:217
Feb 20 00:28:10.444 INFO valid ICMPv6 message, loc: examples/ipv6.rs:221
Feb 20 00:28:10.444 INFO ICMPv6 type: NeighborSolicitation, loc: examples/ipv6.rs:232
Feb 20 00:28:10.444 INFO NeighborSolicitation target address matches our address, loc: examples/ipv6.rs:285
Feb 20 00:28:10.444 INFO sending solicited Neighbor Advertisement, loc: examples/ipv6.rs:130

Feb 20 00:28:10.460 INFO new packet, loc: examples/ipv6.rs:113
Feb 20 00:28:10.460 INFO valid Ethernet frame, loc: examples/ipv6.rs:158
Feb 20 00:28:10.460 INFO EtherType: IPv6, loc: examples/ipv6.rs:184
Feb 20 00:28:10.460 INFO valid IPv6 packet, loc: examples/ipv6.rs:187
Feb 20 00:28:10.460 INFO Updating the Neighbor cache, loc: examples/ipv6.rs:202
Feb 20 00:28:10.460 INFO IPv6 next-header: ICMPv6, loc: examples/ipv6.rs:217
Feb 20 00:28:10.460 INFO valid ICMPv6 message, loc: examples/ipv6.rs:221
Feb 20 00:28:10.460 INFO ICMPv6 type: EchoRequest, loc: examples/ipv6.rs:325
Feb 20 00:28:10.460 INFO sending Echo Reply, loc: examples/ipv6.rs:117

Feb 20 00:28:11.445 INFO new packet, loc: examples/ipv6.rs:113
Feb 20 00:28:11.445 INFO valid Ethernet frame, loc: examples/ipv6.rs:158
Feb 20 00:28:11.445 INFO EtherType: IPv6, loc: examples/ipv6.rs:184
Feb 20 00:28:11.445 INFO valid IPv6 packet, loc: examples/ipv6.rs:187
Feb 20 00:28:11.445 INFO Updating the Neighbor cache, loc: examples/ipv6.rs:202
Feb 20 00:28:11.445 INFO IPv6 next-header: ICMPv6, loc: examples/ipv6.rs:217
Feb 20 00:28:11.445 INFO valid ICMPv6 message, loc: examples/ipv6.rs:221
Feb 20 00:28:11.445 INFO ICMPv6 type: EchoRequest, loc: examples/ipv6.rs:325
Feb 20 00:28:11.445 INFO sending Echo Reply, loc: examples/ipv6.rs:117
```

### `nc` test

On a Linux host issue these commands

``` console
$ nc -u fe80::2219:2ff:fe01:2359%wlan0 1337
hello
hello
world
world
```

You should see the LED on the board blink each time you send a message. You
should also see the message being echoed back.

In the logs you should see something like this:

``` text
Feb 20 00:32:05.903 INFO new packet, loc: examples/ipv6.rs:113
Feb 20 00:32:05.903 INFO valid Ethernet frame, loc: examples/ipv6.rs:158
Feb 20 00:32:05.903 INFO EtherType: IPv6, loc: examples/ipv6.rs:184
Feb 20 00:32:05.903 INFO valid IPv6 packet, loc: examples/ipv6.rs:187
Feb 20 00:32:05.904 INFO Updating the Neighbor cache, loc: examples/ipv6.rs:202
Feb 20 00:32:05.904 INFO IPv6 next-header: UDP, loc: examples/ipv6.rs:374
Feb 20 00:32:05.904 INFO valid UDP packet, loc: examples/ipv6.rs:377
Feb 20 00:32:05.904 INFO sending UDP packet, loc: examples/ipv6.rs:139

Feb 20 00:32:07.495 INFO new packet, loc: examples/ipv6.rs:113
Feb 20 00:32:07.495 INFO valid Ethernet frame, loc: examples/ipv6.rs:158
Feb 20 00:32:07.495 INFO EtherType: IPv6, loc: examples/ipv6.rs:184
Feb 20 00:32:07.495 INFO valid IPv6 packet, loc: examples/ipv6.rs:187
Feb 20 00:32:07.495 INFO Updating the Neighbor cache, loc: examples/ipv6.rs:202
Feb 20 00:32:07.495 INFO IPv6 next-header: UDP, loc: examples/ipv6.rs:374
Feb 20 00:32:07.495 INFO valid UDP packet, loc: examples/ipv6.rs:377
Feb 20 00:32:07.495 INFO sending UDP packet, loc: examples/ipv6.rs:139
```

### `coap` test

The `coap` tool is in the `/tools` directory. Install it first.

On a Linux host issue these commands:

- `GET /led`, returns the state of the LED

``` console
$ coap -I wlan0 GET 'coap://[fe80::2219:2ff:fe01:2359]/led'
-> coap::Message { version: 1, type: Confirmable, code: Method::Get, message_id: 4226, options: {UriPath: "led"} }
<- coap::Message { version: 1, type: Acknowledgement, code: Response::Content, message_id: 4226 }
{"led":false}
```

``` text
Feb 24 22:52:54.526 INFO new packet, loc: examples/ipv6.rs:113
Feb 24 22:52:54.526 INFO valid Ethernet frame, loc: examples/ipv6.rs:195
Feb 24 22:52:54.526 INFO EtherType: IPv6, loc: examples/ipv6.rs:221
Feb 24 22:52:54.526 INFO valid IPv6 packet, loc: examples/ipv6.rs:224
Feb 24 22:52:54.526 INFO Updating the Neighbor cache, loc: examples/ipv6.rs:239
Feb 24 22:52:54.526 INFO IPv6 next-header: UDP, loc: examples/ipv6.rs:410
Feb 24 22:52:54.526 INFO valid UDP packet, loc: examples/ipv6.rs:413
Feb 24 22:52:54.526 INFO UDP: destination port is our CoAP port, loc: examples/ipv6.rs:439
Feb 24 22:52:54.526 INFO valid CoAP message, loc: examples/ipv6.rs:442
Feb 24 22:52:54.526 INFO CoAP: GET request, loc: examples/ipv6.rs:540
Feb 24 22:52:54.526 INFO CoAP: GET /led, loc: examples/ipv6.rs:546
Feb 24 22:52:54.526 INFO sending CoAP message, loc: examples/ipv6.rs:134
```

- `GET /brightness`, returns "Not Found" because this resource doesn't exist

``` console
$ coap -I wlan0 GET 'coap://[fe80::2219:2ff:fe01:2359]/brightness'
-> coap::Message { version: 1, type: Confirmable, code: Method::Get, message_id: 3536, options: {UriPath: "brightness"} }
<- coap::Message { version: 1, type: Acknowledgement, code: Response::NotFound, message_id: 3536 }
```

``` text
Feb 24 22:54:37.543 INFO new packet, loc: examples/ipv6.rs:113
Feb 24 22:54:37.543 INFO valid Ethernet frame, loc: examples/ipv6.rs:195
Feb 24 22:54:37.543 INFO EtherType: IPv6, loc: examples/ipv6.rs:221
Feb 24 22:54:37.543 INFO valid IPv6 packet, loc: examples/ipv6.rs:224
Feb 24 22:54:37.543 INFO Updating the Neighbor cache, loc: examples/ipv6.rs:239
Feb 24 22:54:37.543 INFO IPv6 next-header: UDP, loc: examples/ipv6.rs:410
Feb 24 22:54:37.543 INFO valid UDP packet, loc: examples/ipv6.rs:413
Feb 24 22:54:37.543 INFO UDP: destination port is our CoAP port, loc: examples/ipv6.rs:439
Feb 24 22:54:37.543 INFO valid CoAP message, loc: examples/ipv6.rs:442
Feb 24 22:54:37.543 INFO CoAP: GET request, loc: examples/ipv6.rs:540
Feb 24 22:54:37.543 ERRO CoAP: Not Found, loc: examples/ipv6.rs:605
Feb 24 22:54:37.543 INFO sending CoAP message, loc: examples/ipv6.rs:134
```

- `PUT /led`, changes the state of the LED

``` console
$ coap -I wlan0 PUT 'coap://[fe80::2219:2ff:fe01:2359]/led' '{"led":true}'
-> coap::Message { version: 1, type: Confirmable, code: Method::Put, message_id: 16052, options: {UriPath: "led"} }
<- coap::Message { version: 1, type: Acknowledgement, code: Response::Changed, message_id: 16052 }
```

``` text
Feb 24 22:55:37.487 INFO new packet, loc: examples/ipv6.rs:113
Feb 24 22:55:37.487 INFO valid Ethernet frame, loc: examples/ipv6.rs:195
Feb 24 22:55:37.487 INFO EtherType: IPv6, loc: examples/ipv6.rs:221
Feb 24 22:55:37.487 INFO valid IPv6 packet, loc: examples/ipv6.rs:224
Feb 24 22:55:37.487 INFO Updating the Neighbor cache, loc: examples/ipv6.rs:239
Feb 24 22:55:37.487 INFO IPv6 next-header: UDP, loc: examples/ipv6.rs:410
Feb 24 22:55:37.487 INFO valid UDP packet, loc: examples/ipv6.rs:413
Feb 24 22:55:37.487 INFO UDP: destination port is our CoAP port, loc: examples/ipv6.rs:439
Feb 24 22:55:37.487 INFO valid CoAP message, loc: examples/ipv6.rs:442
Feb 24 22:55:37.487 INFO CoAP: PUT request, loc: examples/ipv6.rs:566
Feb 24 22:55:37.487 INFO CoAP: PUT /led, loc: examples/ipv6.rs:572
Feb 24 22:55:37.487 INFO CoAP: Changed, loc: examples/ipv6.rs:575
Feb 24 22:55:37.487 INFO changing LED state, loc: examples/ipv6.rs:125
Feb 24 22:55:37.487 INFO sending CoAP message, loc: examples/ipv6.rs:134
```

## `sixlowpan`

A simplified 6LoWPAN stack. This stack responds to "ping"s, echoes back UDP
packets and exposes an LED as a CoAP resource.

### Caveats

- The device will *not* send Neighbor Solicitations for IP addresses it doesn't
  know about.

### Setup

First set up a 6lowpan device on the Linux host. You'll need an 802.15.4
transceiver like the ATUSB.

``` console
$ # install wpan-tools
$ yay -S wpan-tools

$ # connect the device and confirm its presence
$ ip link | tail -n2
53: wpan0: <BROADCAST,NOARP,UP,LOWER_UP> mtu 123 qdisc fq_codel state UNKNOWN mode DEFAULT group default qlen 300
    link/ieee802.15.4 xx:xx:xx:xx:xx:xx:xx:xx brd ff:ff:ff:ff:ff:ff:ff:ff

$ # turn off the interface so we can configure it
$ sudo ifconfig wpan0 down

$ # check the supported channels
$ iwpan phy phy0 info | head -n5
wpan_phy phy0
supported channels:
        page 0: 11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26
current_page: 0
current_channel: 11,  2405 MHz

$ # change the channel to match the device's
$ sudo iwpan phy phy0 set channel 0 22

$ # change the PAN ID to match the device's
$ sudo iwpan dev wpan0 set pan_id 0xbeef

$ # create a 6LoWPAN interface
$ sudo ip link add link wpan0 name lowpan0 type lowpan

$ # the new interface should now appear under `ip link`
$ ip link | tail -n4
53: wpan0: <BROADCAST,NOARP> mtu 123 qdisc fq_codel state DOWN mode DEFAULT group default qlen 300
    link/ieee802.15.4 10:e2:d5:ff:ff:00:02:28 brd ff:ff:ff:ff:ff:ff:ff:ff
54: lowpan0@wpan0: <BROADCAST,MULTICAST,M-DOWN> mtu 1280 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/6lowpan 10:e2:d5:ff:ff:00:02:28 brd ff:ff:ff:ff:ff:ff:ff:ff

$ # bring the interfaces up
$ sudo ifconfig wpan0 up
$ sudo ifconfig lowpan0 up
```

If you run into trouble check: http://wpan.cakelab.org/

### `ping` test

On a Linux host issue these commands:

``` console
$ # flush the neighbor cache
$ sudo  ip -s -s neigh flush all

$ ip -6 neigh show

$ ping -6 -c2 fe80::2219:220:23:5959%lowpan0
PING fe80::2219:220:23:5959%lowpan0(fe80::2219:220:23:5959%lowpan0) 56 data bytes
64 bytes from fe80::2219:220:23:5959%lowpan0: icmp_seq=1 ttl=64 time=35.6 ms
64 bytes from fe80::2219:220:23:5959%lowpan0: icmp_seq=2 ttl=64 time=14.8 ms

--- fe80::2219:220:23:5959%lowpan0 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 3ms
rtt min/avg/max/mdev = 14.775/25.204/35.633/10.429 ms
```

You should see the LED on the board blink twice. The neighbor cache should now
include the device:

``` console
$ ip -6 neigh show
fe80::2219:220:23:5959 dev lowpan0 lladdr 20:19:02:20:00:23:59:59 REACHABLE
```

In the logs you should see something like this:

``` text
Feb 21 00:52:56.916 INFO Initializing .., loc: examples/sixlowpan.rs:52
Feb 21 00:52:56.920 INFO Done with initialization, loc: examples/sixlowpan.rs:68

Feb 21 00:53:01.903 INFO new packet, loc: examples/sixlowpan.rs:93
Feb 21 00:53:01.903 INFO valid MAC frame, loc: examples/sixlowpan.rs:130
Feb 21 00:53:01.903 INFO valid 6LoWPAN packet, loc: examples/sixlowpan.rs:173
Feb 21 00:53:01.903 INFO Updating the Neighbor cache, loc: examples/sixlowpan.rs:194
Feb 21 00:53:01.903 INFO IPv6 next-header: ICMPv6, loc: examples/sixlowpan.rs:204
Feb 21 00:53:01.903 INFO valid ICMPv6 message, loc: examples/sixlowpan.rs:208
Feb 21 00:53:01.903 INFO ICMPv6 type: NeighborSolicitation, loc: examples/sixlowpan.rs:220
Feb 21 00:53:01.903 INFO NeighborSolicitation target address matches our address, loc: examples/sixlowpan.rs:272
Feb 21 00:53:01.903 INFO sending solicited Neighbor Advertisement, loc: examples/sixlowpan.rs:111

Feb 21 00:53:01.919 INFO new packet, loc: examples/sixlowpan.rs:93
Feb 21 00:53:01.919 INFO valid MAC frame, loc: examples/sixlowpan.rs:130
Feb 21 00:53:01.919 INFO valid 6LoWPAN packet, loc: examples/sixlowpan.rs:173
Feb 21 00:53:01.919 INFO Updating the Neighbor cache, loc: examples/sixlowpan.rs:194
Feb 21 00:53:01.919 INFO IPv6 next-header: ICMPv6, loc: examples/sixlowpan.rs:204
Feb 21 00:53:01.919 INFO valid ICMPv6 message, loc: examples/sixlowpan.rs:208
Feb 21 00:53:01.919 INFO ICMPv6 type: EchoRequest, loc: examples/sixlowpan.rs:318
Feb 21 00:53:01.919 INFO sending Echo Reply, loc: examples/sixlowpan.rs:97

Feb 21 00:53:02.900 INFO new packet, loc: examples/sixlowpan.rs:93
Feb 21 00:53:02.900 INFO valid MAC frame, loc: examples/sixlowpan.rs:130
Feb 21 00:53:02.900 INFO valid 6LoWPAN packet, loc: examples/sixlowpan.rs:173
Feb 21 00:53:02.900 INFO Updating the Neighbor cache, loc: examples/sixlowpan.rs:194
Feb 21 00:53:02.900 INFO IPv6 next-header: ICMPv6, loc: examples/sixlowpan.rs:204
Feb 21 00:53:02.900 INFO valid ICMPv6 message, loc: examples/sixlowpan.rs:208
Feb 21 00:53:02.900 INFO ICMPv6 type: EchoRequest, loc: examples/sixlowpan.rs:318
Feb 21 00:53:02.900 INFO sending Echo Reply, loc: examples/sixlowpan.rs:97
```

### `nc` test

On a Linux host issue these commands

``` console
nc -u fe80::2219:220:23:5959%lowpan0 1337
hello
hello
world
world
```

You should see the LED on the board blink each time you send a message. You
should also see the message being echoed back.

In the logs you should see something like this:

``` text
Feb 21 20:26:31.224 INFO new packet, loc: examples/sixlowpan.rs:93
Feb 21 20:26:31.224 INFO valid MAC frame, loc: examples/sixlowpan.rs:140
Feb 21 20:26:31.224 INFO valid 6LoWPAN packet, loc: examples/sixlowpan.rs:183
Feb 21 20:26:31.224 INFO Updating the Neighbor cache, loc: examples/sixlowpan.rs:204
Feb 21 20:26:31.224 INFO payload is LOWPAN_NHC encoded, loc: examples/sixlowpan.rs:377
Feb 21 20:26:31.224 INFO valid UDP packet, loc: examples/sixlowpan.rs:380
Feb 21 20:26:31.224 INFO sending UDP packet, loc: examples/sixlowpan.rs:119

Feb 21 20:26:32.160 INFO new packet, loc: examples/sixlowpan.rs:93
Feb 21 20:26:32.160 INFO valid MAC frame, loc: examples/sixlowpan.rs:140
Feb 21 20:26:32.160 INFO valid 6LoWPAN packet, loc: examples/sixlowpan.rs:183
Feb 21 20:26:32.160 INFO Updating the Neighbor cache, loc: examples/sixlowpan.rs:204
Feb 21 20:26:32.160 INFO payload is LOWPAN_NHC encoded, loc: examples/sixlowpan.rs:377
Feb 21 20:26:32.160 INFO valid UDP packet, loc: examples/sixlowpan.rs:380
Feb 21 20:26:32.160 INFO sending UDP packet, loc: examples/sixlowpan.rs:119
```

### `coap` test

The `coap` tool is in the `/tools` directory. Install it first.

On a Linux host issue these commands:

- `GET /led`, returns the state of the LED

``` console
$ coap -I lowpan0 GET 'coap://[fe80::2219:220:23:5959]/led'
-> coap::Message { version: 1, type: Confirmable, code: Method::Get, message_id: 17288, options: {UriPath: "led"} }
<- coap::Message { version: 1, type: Acknowledgement, code: Response::Content, message_id: 17288 }
{"led":true}
```

``` text
Feb 25 02:51:45.784 INFO new packet, loc: examples/sixlowpan.rs:94
Feb 25 02:51:45.784 INFO valid MAC frame, loc: examples/sixlowpan.rs:176
Feb 25 02:51:45.784 INFO valid 6LoWPAN packet, loc: examples/sixlowpan.rs:219
Feb 25 02:51:45.784 INFO Updating the Neighbor cache, loc: examples/sixlowpan.rs:240
Feb 25 02:51:45.784 INFO payload is LOWPAN_NHC encoded, loc: examples/sixlowpan.rs:413
Feb 25 02:51:45.784 INFO valid UDP packet, loc: examples/sixlowpan.rs:416
Feb 25 02:51:45.784 INFO UDP: destination port is our CoAP port, loc: examples/sixlowpan.rs:443
Feb 25 02:51:45.784 INFO valid CoAP message, loc: examples/sixlowpan.rs:446
Feb 25 02:51:45.784 INFO CoAP: GET request, loc: examples/sixlowpan.rs:524
Feb 25 02:51:45.785 INFO CoAP: GET /led, loc: examples/sixlowpan.rs:530
Feb 25 02:51:45.785 INFO sending CoAP message, loc: examples/sixlowpan.rs:115
```

- `GET /brightness`, returns "Not Found" because this resource doesn't exist

``` console
$ coap -I lowpan0 GET 'coap://[fe80::2219:220:23:5959]/brightness'
-> coap::Message { version: 1, type: Confirmable, code: Method::Get, message_id: 38597, options: {UriPath: "brightness"} }
<- coap::Message { version: 1, type: Acknowledgement, code: Response::NotFound, message_id: 38597 }
```

``` text
Feb 25 02:52:55.583 INFO new packet, loc: examples/sixlowpan.rs:94
Feb 25 02:52:55.583 INFO valid MAC frame, loc: examples/sixlowpan.rs:176
Feb 25 02:52:55.583 INFO valid 6LoWPAN packet, loc: examples/sixlowpan.rs:219
Feb 25 02:52:55.583 INFO Updating the Neighbor cache, loc: examples/sixlowpan.rs:240
Feb 25 02:52:55.583 INFO payload is LOWPAN_NHC encoded, loc: examples/sixlowpan.rs:413
Feb 25 02:52:55.583 INFO valid UDP packet, loc: examples/sixlowpan.rs:416
Feb 25 02:52:55.583 INFO UDP: destination port is our CoAP port, loc: examples/sixlowpan.rs:443
Feb 25 02:52:55.583 INFO valid CoAP message, loc: examples/sixlowpan.rs:446
Feb 25 02:52:55.583 INFO CoAP: GET request, loc: examples/sixlowpan.rs:524
Feb 25 02:52:55.583 ERRO CoAP: Not Found, loc: examples/sixlowpan.rs:589
Feb 25 02:52:55.583 INFO sending CoAP message, loc: examples/sixlowpan.rs:115
```

- `PUT /led`, changes the state of the LED

``` console
$ coap -I lowpan0 PUT 'coap://[fe80::2219:220:23:5959]/led' '{"led":false}'
-> coap::Message { version: 1, type: Confirmable, code: Method::Put, message_id: 3014, options: {UriPath: "led"} }
<- coap::Message { version: 1, type: Acknowledgement, code: Response::Changed, message_id: 3014 }
```

``` text
Feb 25 02:53:31.024 INFO new packet, loc: examples/sixlowpan.rs:94
Feb 25 02:53:31.025 INFO valid MAC frame, loc: examples/sixlowpan.rs:176
Feb 25 02:53:31.025 INFO valid 6LoWPAN packet, loc: examples/sixlowpan.rs:219
Feb 25 02:53:31.025 INFO Updating the Neighbor cache, loc: examples/sixlowpan.rs:240
Feb 25 02:53:31.025 INFO payload is LOWPAN_NHC encoded, loc: examples/sixlowpan.rs:413
Feb 25 02:53:31.025 INFO valid UDP packet, loc: examples/sixlowpan.rs:416
Feb 25 02:53:31.025 INFO UDP: destination port is our CoAP port, loc: examples/sixlowpan.rs:443
Feb 25 02:53:31.025 INFO valid CoAP message, loc: examples/sixlowpan.rs:446
Feb 25 02:53:31.025 INFO CoAP: PUT request, loc: examples/sixlowpan.rs:550
Feb 25 02:53:31.025 INFO CoAP: PUT /led, loc: examples/sixlowpan.rs:556
Feb 25 02:53:31.025 INFO CoAP: Changed, loc: examples/sixlowpan.rs:559
Feb 25 02:53:31.025 INFO changing LED state, loc: examples/sixlowpan.rs:106
Feb 25 02:53:31.025 INFO sending CoAP message, loc: examples/sixlowpan.rs:115
```
