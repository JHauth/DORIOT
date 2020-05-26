A simple RIOT server example

1. Change the path in the makefile to your RIOT directory

2. Build the example with make command

3. In RIOT directory execute the following command to setup 2 taps connected via bridge:

    [RIOT]$ sudo dist/tools/tapsetup/tapsetup -c 2

4. Flash two nodes in two separate terminals:

    Terminal 1:
    $ PORT=tap0 make term

    Terminal 2:
    $ PORT=tap1 make terms

5. Find out the ip address of the node in terminal 1:

    > ifconfig
    ifconfig
    Iface  6  HWaddr: 3E:BD:A7:BD:32:06
              L2-PDU:1500 MTU:1500  HL:64  Source address length: 6
              Link type: wired
              inet6 addr: fe80::3cbd:a7ff:febd:3206  scope: link  VAL
              inet6 group: ff02::1
              inet6 group: ff02::1:ffbd:3206

6. Now you can send requests from the node in terminal 2:

    > coap get fe80::3cbd:a7ff:febd:3206%6 5683 /string

    > coap looprequest fe80::3cbd:a7ff:febd:3206%6 5683 /string

    > coap put fe80::3cbd:a7ff:febd:3206%6 5683 /string changed_string
