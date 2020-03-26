!!!Requests are not working yet
!!!Threadcount is not working correctly

A simple RIOT server example

To try out the server on native, compile it with

$ make all

Then, create a tap interface (to which RIOT will connect):

$ sudo ip tuntap add tap0 mode tap user ${USER}
$ sudo ip link set tap0 up

Run the resulting RIOT binary by invoking:

$ make term

The application is now listening on all it's configured IP addresses.

Now find out its link_layer address:

$ make term
/home/josh/HiWi/Server_2/bin/native/gcoap_example.elf tap0
RIOT native interrupts/signals initialized.
LED_RED_OFF
LED_GREEN_ON
RIOT native board initialized.
RIOT native hardware initialization complete.

main(): This is RIOT! (Version: 2020.04-devel-1371-g54357-HEAD)
gcoap block handler
All up, running the shell now

get ip with ifconfig:

> ifconfig
ifconfig
Iface  6  HWaddr: 3E:BD:A7:BD:32:06
          L2-PDU:1500 MTU:1500  HL:64  Source address length: 6
          Link type: wired
          inet6 addr: fe80::3cbd:a7ff:febd:3206  scope: link  VAL
          inet6 group: ff02::1
          inet6 group: ff02::1:ffbd:3206


The link-layer address in this case is "fe80::e42a:1aff:feca:10ec", the only "scope: local" address set.

Test it with libcoap cli:

Get:
coap-client -m get coap://[fe80::e42a:1aff:feca:10ec%tap0]/string
coap-client -m get coap://[fe80::e42a:1aff:feca:10ec%tap0]/time
coap-client -m get coap://[fe80::e42a:1aff:feca:10ec%tap0]/info

Change the string:
coap-client -m put coap://[fe80::e42a:1aff:feca:10ec%tap0]/riot/value -e example
