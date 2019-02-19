# Firmware examples

This directory contains firmware examples that make use of the `jnet` crate.

All these examples feature:

- Proper error handling. No `unwrap`-ing `Result`s or `Option`s.

- Fatal I/O errors are handled using a "fatal error" handler rather than the
  panic handler, which is reserved for programmer errors (AKA bugs).

- Extensive (but super cheap) logging.

- Very few panicking branches after optimization. These are actually unreachable
  but the optimizer is not able to remove them.

## `ipv4`

A simplified IPv4 stack. This stack responds to "ping"s and echoes back UDP
packets.

### Caveats

- The IP address is statically configured and hardcoded in the firmware

- The device does *not* announce or probe its IP address on boot

- The device will *not* attempt to ARP request IP addresses it doesn't know about

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

### `nc`

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

## `ipv6`

A simplified IPv6 stack. This stack responds to "ping"s and echoes back UDP
packets.

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

$ ping -6 -c1 fe80::2219:2ff:fe01:2359%wlan0
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
