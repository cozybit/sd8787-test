#!/usr/bin/env python
import struct
import ctypes
import ctypes.util
import genetlink, netlink

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

MWL8787_CMD_GET_HW_SPEC         = 0x0003
MWL8787_CMD_802_11_RESET        = 0x0005
MWL8787_CMD_802_11_MAC_ADDRESS  = 0x004d
MWL8787_CMD_802_11_RF_CHANNEL   = 0x001d
MWL8787_CMD_802_11_MAC_CONTROL  = 0x0028
MWL8787_CMD_802_11_RADIO_CONTROL = 0x001c
MWL8787_CMD_802_11_CMD_MONITOR = 0x0102

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

def radio_control(ifindex, on=False):
    """ set/get radio on/off """
    if not on:
        control = 0
        action = CMD_ACT_GET
    else:
        control = 1
        action = CMD_ACT_SET
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

def set_monitor(ifindex, on=False):
    """ set/get monitor mode """
    if not on:
        enable = 0
        action = CMD_ACT_GET
    else:
        enable = 1
        action = CMD_ACT_SET

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


if __name__ == "__main__":
    ifindex = if_nametoindex('wlan0')
    hdr, attrs = send_cmd(NL80211_CMD_GET_WIPHY,
                 [netlink.U32Attr(NL80211_ATTR_IFINDEX, ifindex)])

    print 'ifindex: %d' % ifindex
    print 'wiphy: %s' % attrs[NL80211_ATTR_WIPHY].u32()
    print 'wiphy name: %s' % attrs[NL80211_ATTR_WIPHY_NAME].str()

    reset(ifindex)
    address = mac_address(ifindex)
    print 'mac addr: %s' % (':'.join('%02x' % ord(x) for x in address))
    mac_address(ifindex, address=[0x01,0x02,0x03,0x04,0x05,0x06])
    set_channel(ifindex, 7)

    radio_control(ifindex, True)
    #set_monitor(ifindex, True)
    # RXon, mcast, bcast, promisc, allmulti, 802.11, mgmt
    PROMISC=0b0101000111100001
    set_mac_ctl(ifindex, PROMISC)
    #NONE=0b0
    #set_mac_ctl(ifindex, NONE)
