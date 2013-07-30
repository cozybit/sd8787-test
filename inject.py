#!/usr/bin/python
import pcap
import time
import sys

iface = sys.argv[1]


pc = pcap.pcap(name=iface, promisc=True, immediate=True)

rtap = [
    0x00, 0x00, # version
    0x0b, 0x00, # header
    # bitmap: rate, dbm tx power, antenna
    0x04, 0x0c, 0x00, 0x00,
    0x02, # rate x 2
    0x0c, # tx power - 12 dBm
    0x01  # antenna
]

# beacon frame
frame = [
    0x80, 0x00,                             # fc
    0x00, 0x00,                             # duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,     # da
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66,     # sa
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66,     # bssid/ta
    0x10, 0x00,                             # seq ctrl

    0x60, 0xd9, 0xe4, 0xd2, 0xb4, 0x04,
    0x00, 0x00,                             # tsf

    0x64, 0x00,                             # intvl
    0x31, 0x04,                             # capa

    0x00, 0x04, 0x61, 0x62, 0x63, 0x64      # ssid = 'abcd'
]

seq = 0
SEQ_OFF = 22
while True:

    seq += 1
    frame[SEQ_OFF] = (seq & 0x0f) << 4
    frame[SEQ_OFF + 1] = (seq >> 4) & 0xff

    pkt = ''.join([chr(x) for x in rtap] + [chr(x) for x in frame])

    print 'about to inject...'
    pc.inject(pkt, len(pkt))
    print 'result %s' % pc.geterr()
    time.sleep(.1)


