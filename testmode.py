#!/usr/bin/env python
import struct
import ctypes
import ctypes.util
import genetlink, netlink
from dot11frames import *

NL80211_CMD_GET_WIPHY           = 1
NL80211_CMD_TESTMODE            = 45

NL80211_ATTR_WIPHY              = 1
NL80211_ATTR_WIPHY_NAME         = 2
NL80211_ATTR_IFINDEX            = 3
NL80211_ATTR_TESTDATA           = 69

MWL8787_TM_ATTR_CMD_ID          = 1
MWL8787_TM_ATTR_FW_CMD_ID       = 2
MWL8787_TM_ATTR_DATA            = 3

MWL8787_TM_CMD_FW               = 1
MWL8787_TM_CMD_DATA             = 2

MWL8787_CMD_GET_HW_SPEC         = 0x0003
MWL8787_CMD_802_11_RESET        = 0x0005
MWL8787_CMD_802_11_MAC_ADDRESS  = 0x004d
MWL8787_CMD_802_11_RF_CHANNEL   = 0x001d
MWL8787_CMD_802_11_MAC_CONTROL  = 0x0028
MWL8787_CMD_802_11_RADIO_CONTROL = 0x001c
MWL8787_CMD_802_11_CMD_MONITOR = 0x0102
MWL8787_CMD_BEACON_SET           = 0x00cb
MWL8787_CMD_BEACON_CTRL          = 0x010e

CMD_ACT_GET                     = 0
CMD_ACT_SET                     = 1

libc = ctypes.CDLL(ctypes.util.find_library('c'))
family = genetlink.controller.get_family_id('nl80211')

def if_nametoindex(ifname):
    return libc.if_nametoindex(ifname)

def send_cmd(cmd, attrs, resp=True):
    conn = genetlink.connection
    nlmsg = genetlink.GeNlMessage(family, cmd,
        flags=netlink.NLM_F_REQUEST | netlink.NLM_F_ACK,
        attrs=attrs)
    nlmsg.send(conn)
    if resp:
        while True:
            m = conn.recv()
            if m.seq == nlmsg.seq:
                hdr = genetlink.genl_hdr_parse(m.payload[:4])
                attrs = netlink.parse_attributes(m.payload[4:])
                return (hdr.cmd, attrs)
    return None

def reset(ifindex):
    """ send a reset """
    send_cmd(NL80211_CMD_TESTMODE, [
        netlink.U32Attr(NL80211_ATTR_IFINDEX, ifindex),
        netlink.Nested(NL80211_ATTR_TESTDATA, [
            netlink.U32Attr(MWL8787_TM_ATTR_CMD_ID, MWL8787_TM_CMD_FW),
            netlink.U32Attr(MWL8787_TM_ATTR_FW_CMD_ID, MWL8787_CMD_802_11_RESET),
            netlink.BinaryAttr(MWL8787_TM_ATTR_DATA, '')
        ])
    ], resp=False)

def mac_address(ifindex, address=None):
    """ set/get mac address """
    if not address:
        address = [0] * 6
        action = CMD_ACT_GET
    else:
        action = CMD_ACT_SET
    payload = struct.pack("<H6B", action, *address)

    hdr, attrs = send_cmd(NL80211_CMD_TESTMODE, [
        netlink.U32Attr(NL80211_ATTR_IFINDEX, ifindex),
        netlink.Nested(NL80211_ATTR_TESTDATA, [
            netlink.U32Attr(MWL8787_TM_ATTR_CMD_ID, MWL8787_TM_CMD_FW),
            netlink.U32Attr(MWL8787_TM_ATTR_FW_CMD_ID, MWL8787_CMD_802_11_MAC_ADDRESS),
            netlink.BinaryAttr(MWL8787_TM_ATTR_DATA, payload)
        ])
    ])

    testdata = attrs[NL80211_ATTR_TESTDATA].nested()
    action, address = struct.unpack("<H6s",
        testdata[MWL8787_TM_ATTR_DATA].str())
    return address


def set_channel(ifindex, channel=None):
    """ set/get channel """
    if not channel:
        channel = 0
        action = CMD_ACT_GET
    else:
        action = CMD_ACT_SET
    BANDCHAN = 0 # 2.4 ghz, 20mhz, manual
    payload = struct.pack("<HH2B", action, channel, 0, BANDCHAN)

    hdr, attrs = send_cmd(NL80211_CMD_TESTMODE, [
        netlink.U32Attr(NL80211_ATTR_IFINDEX, ifindex),
        netlink.Nested(NL80211_ATTR_TESTDATA, [
            netlink.U32Attr(MWL8787_TM_ATTR_CMD_ID, MWL8787_TM_CMD_FW),
            netlink.U32Attr(MWL8787_TM_ATTR_FW_CMD_ID, MWL8787_CMD_802_11_RF_CHANNEL),
            netlink.BinaryAttr(MWL8787_TM_ATTR_DATA, payload)
        ])
    ])

def set_mac_ctl(ifindex, mask=None):
    """ set/get mac_ctl (filter) """
    if not mask:
        mask = 0
    payload = struct.pack("<H", mask)

    hdr, attrs = send_cmd(NL80211_CMD_TESTMODE, [
        netlink.U32Attr(NL80211_ATTR_IFINDEX, ifindex),
        netlink.Nested(NL80211_ATTR_TESTDATA, [
            netlink.U32Attr(MWL8787_TM_ATTR_CMD_ID, MWL8787_TM_CMD_FW),
            netlink.U32Attr(MWL8787_TM_ATTR_FW_CMD_ID, MWL8787_CMD_802_11_MAC_CONTROL),
            netlink.BinaryAttr(MWL8787_TM_ATTR_DATA, payload)
        ])
    ])

def radio_control(ifindex, on=False, action=CMD_ACT_SET):
    """ set/get radio on/off """
    if not on:
        control = 0
    else:
        control = 1

    # non-zero is on
    payload = struct.pack("<HH", action, control)

    hdr, attrs = send_cmd(NL80211_CMD_TESTMODE, [
        netlink.U32Attr(NL80211_ATTR_IFINDEX, ifindex),
        netlink.Nested(NL80211_ATTR_TESTDATA, [
            netlink.U32Attr(MWL8787_TM_ATTR_CMD_ID, MWL8787_TM_CMD_FW),
            netlink.U32Attr(MWL8787_TM_ATTR_FW_CMD_ID, MWL8787_CMD_802_11_RADIO_CONTROL),
            netlink.BinaryAttr(MWL8787_TM_ATTR_DATA, payload)
        ])
    ])

def set_monitor(ifindex, on=False, action=CMD_ACT_SET):
    """ set/get monitor mode """
    if not on:
        enable = 0
    else:
        enable = 1

    MONITOR_MODE_ALL = 7
    TYPE = 0x012A
    LEN = 2
    payload = struct.pack("<HHHHH2B", action, enable, MONITOR_MODE_ALL, TYPE, LEN, 0, 1)

    hdr, attrs = send_cmd(NL80211_CMD_TESTMODE, [
        netlink.U32Attr(NL80211_ATTR_IFINDEX, ifindex),
        netlink.Nested(NL80211_ATTR_TESTDATA, [
            netlink.U32Attr(MWL8787_TM_ATTR_CMD_ID, MWL8787_TM_CMD_FW),
            netlink.U32Attr(MWL8787_TM_ATTR_FW_CMD_ID, MWL8787_CMD_802_11_CMD_MONITOR),
            netlink.BinaryAttr(MWL8787_TM_ATTR_DATA, payload)
        ])
    ])

def send_data(ifindex, data=None):
    if not data:
        print "please specify a payload"
        raise

# just ask the fw for mac address :)
    mac = mac_address(ifindex)
    mac = ':'.join('%02x' % ord(x) for x in mac)

    frame = get_mesh_mcast_data(mac, "ff:ff:ff:ff:ff:ff", data)

    fw_send_frame(ifindex, str(frame))

def fw_send_frame(ifindex, frame):

    # frame must be 4-byte aligned
    pad = len(frame) % 4
    for n in range(pad):
        frame = struct.pack("x") + frame

    # 8787 tx descriptor
    BSS_TYPE = 0x3 # TYPE_TM
    BSS_NUM = 0
    LEN = len(frame)
    OFFSET = 16 + pad # 18 == desc. length must start on 4-byte boundary
    TYPE = 0x5 # 802.11
    RES1 = 0
    PRIORITY = 0
    FLAGS = 0
    DELAY = 0
    RES2 = 0

    desc = struct.pack("<BBHHHIBBBB", BSS_TYPE, BSS_NUM, LEN, OFFSET, TYPE, RES1, PRIORITY, FLAGS, DELAY, RES2)
    payload = desc + frame

    hdr, attrs = send_cmd(NL80211_CMD_TESTMODE, [
        netlink.U32Attr(NL80211_ATTR_IFINDEX, ifindex),
        netlink.Nested(NL80211_ATTR_TESTDATA, [
            netlink.U32Attr(MWL8787_TM_ATTR_CMD_ID, MWL8787_TM_CMD_DATA),
            netlink.BinaryAttr(MWL8787_TM_ATTR_DATA, payload)
        ])
    ])

# construct and send a frame of each needed type
def send_all(ifindex):
    MESHID="bazooka"
    PAYLOAD="hello"

    mymac = mac_address(ifindex)
    mymac = ':'.join('%02x' % ord(x) for x in mymac)

# beacon
    pkt = get_mesh_beacon(mymac, MESHID)
    fw_send_frame(ifindex, str(pkt))

# peering open
    pkt = get_mesh_peering_open(mymac, dstmac, MESHID)
    fw_send_frame(ifindex, str(pkt))

# bcast mesh data
    pkt = get_mesh_mcast_data(mymac, "ff:ff:ff:ff:ff:ff", PAYLOAD)
    fw_send_frame(ifindex, str(pkt))

# PREQ
    pkt = get_mesh_preq(mymac, "0c:0c:0c:0c:0c:0c")
    fw_send_frame(ifindex, str(pkt))

# 4addr mesh data
    pkt = get_mesh_4addr_data(mymac, dstmac, PAYLOAD)
    fw_send_frame(ifindex, str(pkt))

def fw_set_beacon(ifindex, meshid, intval):

    intval = int(intval)
    mymac = mac_address(ifindex)
    mymac = ':'.join('%02x' % ord(x) for x in mymac)

    frame = get_mesh_beacon(mymac, meshid)

    # set beacon data
    hdr = struct.pack("<H", len(frame))
    payload = hdr + frame
    hdr, attrs = send_cmd(NL80211_CMD_TESTMODE, [
        netlink.U32Attr(NL80211_ATTR_IFINDEX, ifindex),
        netlink.Nested(NL80211_ATTR_TESTDATA, [
            netlink.U32Attr(MWL8787_TM_ATTR_CMD_ID, MWL8787_TM_CMD_FW),
            netlink.U32Attr(MWL8787_TM_ATTR_FW_CMD_ID, MWL8787_CMD_BEACON_SET),
            netlink.BinaryAttr(MWL8787_TM_ATTR_DATA, payload)
        ])
    ])

    # enable beaconing at the given interval
    payload = struct.pack("<HHH", CMD_ACT_SET, 1, intval)
    hdr, attrs = send_cmd(NL80211_CMD_TESTMODE, [
        netlink.U32Attr(NL80211_ATTR_IFINDEX, ifindex),
        netlink.Nested(NL80211_ATTR_TESTDATA, [
            netlink.U32Attr(MWL8787_TM_ATTR_CMD_ID, MWL8787_TM_CMD_FW),
            netlink.U32Attr(MWL8787_TM_ATTR_FW_CMD_ID, MWL8787_CMD_BEACON_CTRL),
            netlink.BinaryAttr(MWL8787_TM_ATTR_DATA, payload)
        ])
    ])



import getopt, sys

def usage():
    print "usage: prog [opts] [testargs]"
    print "     -i <iface>"
    print "     -t <testname>"

if __name__ == "__main__":
    try:
        opts, args = getopt.getopt(sys.argv[1:], "i:t:a:")
    except getopt.GetoptError as err:
        # print help information and exit:
        print str(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    iface = None
    test = None
    arglist = args
    for o, a in opts:
        if o == "-i":
            iface = a
        elif o == "-t":
            test = a
        else:
            assert False, "unhandled option"

    if not iface or not test:
        usage()
        sys.exit(2)

    ifindex = if_nametoindex(iface)
    hdr, attrs = send_cmd(NL80211_CMD_GET_WIPHY,
                 [netlink.U32Attr(NL80211_ATTR_IFINDEX, ifindex)])

    print 'ifindex: %d' % ifindex
    print 'wiphy: %s' % attrs[NL80211_ATTR_WIPHY].u32()
    print 'wiphy name: %s' % attrs[NL80211_ATTR_WIPHY_NAME].str()

    import __main__

    testargs = arglist[0]
    if test == "reset":
        reset(ifindex)
    elif test == "set_radio":
        radio_control(ifindex, True if testargs == "on" else False)
    elif test == "set_mac":
        testargs = [int(x) for x in testargs.split(":")]
        mac_address(ifindex, address=testargs)
    elif test == "get_mac":
        address = mac_address(ifindex)
        print 'mac addr: %s' % (':'.join('%02x' % ord(x) for x in address))
    elif test == "set_channel":
        set_channel(ifindex, int(testargs))
    elif test == "set_monitor":
        set_monitor(ifindex, True if testargs == "on" else False)
    elif test == "set_mac_ctl":
    # RXon, mcast, bcast, promisc, allmulti, 802.11, mgmt
    #PROMISC=0b0101000111100001
        set_mac_ctl(ifindex, int(testargs, 16))
    elif test == "send_data":
        send_data(ifindex, testargs)
    elif test == "send_all":
        send_all(ifindex)
    elif test in dir(__main__):
        fn = getattr(__main__, test)
        fn(ifindex, **testargs)
