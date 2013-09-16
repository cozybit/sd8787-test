#!/usr/bin/env python
import struct
import ctypes
import ctypes.util
import genetlink, netlink
import time
from multiprocessing import Process, Queue
from Queue import Empty
from utils import hexdump
from dot11frames import *

CAP_FILE = "/tmp/test_cap.cap"

NL80211_CMD_GET_WIPHY           = 1
NL80211_CMD_TESTMODE            = 45

NL80211_ATTR_WIPHY              = 1
NL80211_ATTR_WIPHY_NAME         = 2
NL80211_ATTR_IFINDEX            = 3
NL80211_ATTR_TESTDATA           = 69

MWL8787_TM_ATTR_CMD_ID          = 1
MWL8787_TM_ATTR_FW_CMD_ID       = 2
MWL8787_TM_ATTR_DATA            = 3
MWL8787_TM_ATTR_FW_EVT_ID       = 4

MWL8787_TM_CMD_FW               = 1
MWL8787_TM_CMD_DATA             = 2

MWL8787_CMD_GET_HW_SPEC         = 0x0003
MWL8787_CMD_802_11_RESET        = 0x0005
MWL8787_CMD_802_11_MAC_ADDRESS  = 0x004d
MWL8787_CMD_802_11_RF_CHANNEL   = 0x001d
MWL8787_CMD_802_11_MAC_CONTROL  = 0x0028
MWL8787_CMD_802_11_RADIO_CONTROL = 0x001c
MWL8787_CMD_802_11_SUBSCRIBE_EVENT    = 0x0075
MWL8787_CMD_802_11_CMD_MONITOR   = 0x0102
MWL8787_CMD_BEACON_SET           = 0x00cb
MWL8787_CMD_802_11_HEART_BEAT    = 0x00da
MWL8787_CMD_BEACON_CTRL          = 0x010e
MWL8787_CMD_SET_PEER             = 0x0110
MWL8787_CMD_DEL_PEER             = 0x0111

CMD_ACT_GET                     = 0
CMD_ACT_SET                     = 1
CMD_ACT_BITWISE_SET             = 2
CMD_ACT_BITWISE_GET             = 3

EVENT_SUBSCRIBE_DATA_TX_FEEDBACK_BITMAP = 0x1000

MWL8787_EVENT_DATA_TX_FEEDBACK = 0x0067

libc = ctypes.CDLL(ctypes.util.find_library('c'))
family = genetlink.controller.get_family_id('nl80211')

def if_nametoindex(ifname):
    return libc.if_nametoindex(ifname)

def send_cmd(cmd, attrs, resp=True):
    """
    Send a testmode command and read the response.

    If the command returns a response (the usual case), the socket
    is read until the matching netlink response is sent back.
    """
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

def next_event():
    """
    Read the next message from the netlink connection.

    Use this when an event is expected; it will block until any
    event is ready and return the first one.  Some events require
    subscription via a specific command, while others just arrive
    based on received frames etc.
    """
    conn = genetlink.mcast_connection
    m = conn.recv()
    hdr = genetlink.genl_hdr_parse(m.payload[:4])
    attrs = netlink.parse_attributes(m.payload[4:])
    return (hdr.cmd, attrs)

def event_trap(ifindex, queue=None):
    """
    Wait for one event, and send it up the queue.
    """
    cmd, attrs = next_event()
    if NL80211_ATTR_TESTDATA not in attrs:
       return

    testdata = attrs[NL80211_ATTR_TESTDATA].nested()
    event_id = struct.unpack("<L", testdata[MWL8787_TM_ATTR_FW_EVT_ID].data)
    data = struct.unpack("<" + str(len(testdata[MWL8787_TM_ATTR_DATA].data)) + "B", testdata[MWL8787_TM_ATTR_DATA].data)
    if queue:
        queue.put([event_id[0], data])

def event_monitor(ifindex):
    """
    Dump all events as they occur.  For debugging -- never exists
    """
    while True:
        cmd, attrs = next_event()
        if NL80211_ATTR_TESTDATA not in attrs:
            continue

        testdata = attrs[NL80211_ATTR_TESTDATA].nested()
        event_id = struct.unpack("<L", testdata[MWL8787_TM_ATTR_FW_EVT_ID].data)
        data = struct.unpack("<L", testdata[MWL8787_TM_ATTR_DATA].data)
        print hex(event_id[0]), hex(data[0])

def do_cmd(cmd_id, payload_tmpl, *payload_args):
    payload = struct.pack(payload_tmpl, *payload_args)
    return send_cmd(NL80211_CMD_TESTMODE, [
        netlink.U32Attr(NL80211_ATTR_IFINDEX, ifindex),
        netlink.Nested(NL80211_ATTR_TESTDATA, [
            netlink.U32Attr(MWL8787_TM_ATTR_CMD_ID, MWL8787_TM_CMD_FW),
            netlink.U32Attr(MWL8787_TM_ATTR_FW_CMD_ID, cmd_id),
            netlink.BinaryAttr(MWL8787_TM_ATTR_DATA, payload)
        ])
    ])


def heartbeat(ifindex, d2h_timer=0):
    """
    Set heartbeat to get periodic events from device

    XXX not supported with current firmware
    """
    h2d_timer = 0               # disabled
    d2h_timer = int(d2h_timer)

    do_cmd(MWL8787_CMD_802_11_HEART_BEAT, "<HHH", CMD_ACT_SET, h2d_timer, d2h_timer)

def subscribe_event(ifindex, event_mask):
    """
    Subscribe to a set of events.
    """
    payload = struct.pack("<HH", CMD_ACT_BITWISE_SET, event_mask)
    hdr, attrs = send_cmd(NL80211_CMD_TESTMODE, [
        netlink.U32Attr(NL80211_ATTR_IFINDEX, ifindex),
        netlink.Nested(NL80211_ATTR_TESTDATA, [
            netlink.U32Attr(MWL8787_TM_ATTR_CMD_ID, MWL8787_TM_CMD_FW),
            netlink.U32Attr(MWL8787_TM_ATTR_FW_CMD_ID, MWL8787_CMD_802_11_SUBSCRIBE_EVENT),
            netlink.BinaryAttr(MWL8787_TM_ATTR_DATA, payload)
        ])
    ])

def reset(ifindex):
    """ send a reset """
    do_cmd(MWL8787_CMD_802_11_RESET, "")

def mac_address(ifindex, address=None):
    """ set/get mac address """
    if not address:
        address = [0] * 6
        action = CMD_ACT_GET
    else:
        action = CMD_ACT_SET

    hdr, attrs = do_cmd(MWL8787_CMD_802_11_MAC_ADDRESS, "<H6B",
                        action, *address)

    testdata = attrs[NL80211_ATTR_TESTDATA].nested()
    action, address = struct.unpack("<H6s",
        testdata[MWL8787_TM_ATTR_DATA].str())
    address = ':'.join('%02x' % ord(x) for x in address)
    return address


def set_channel(ifindex, channel):
    """ set channel """
    channel = int(channel)
    action = CMD_ACT_SET
    BANDCHAN = 0 # 2.4 ghz, 20mhz, manual

    do_cmd(MWL8787_CMD_802_11_RF_CHANNEL, "<HH2B", action, channel,
           0, BANDCHAN)

def set_mac_ctl(ifindex, mask):
    """ set mac_ctl (filter) """
    # RXon, mcast, bcast, promisc, allmulti, 802.11, mgmt
    #PROMISC=0b0101000111100001
    mask = int(mask, base=0)
    do_cmd(MWL8787_CMD_802_11_MAC_CONTROL, "<I", mask)

def radio_control(ifindex, on=False, action=CMD_ACT_SET):
    """ set/get radio on/off """
    if not on:
        control = 0
    else:
        control = 1

    # non-zero is on
    do_cmd(MWL8787_CMD_802_11_RADIO_CONTROL, "<HH", action, control)

def tx_feedback(ifindex, payload):
    subscribe_event(ifindex, EVENT_SUBSCRIBE_DATA_TX_FEEDBACK_BITMAP)
    q = Queue()
    p = Process(target=event_trap, args=(ifindex, q))
    p.start()
    send_data_unicast(ifindex, payload)
    try:
        event_id, event_data = q.get(block = True, timeout = 5)
    except Empty:
        sys.exit(1)
    if event_id != MWL8787_EVENT_DATA_TX_FEEDBACK:
        sys.exit(1)
    event_data = struct.unpack("<L", struct.pack("<4B", *event_data))[0]
    if (event_data >> 24 != 0x00):    # TX queue
        sys.exit(1)
    FAIL = 0
    if (event_data & 0xff != FAIL):   # frame was sent to bogus peer so status should be FAIL
        sys.exit(1)
    MBPS_1 = 0
    if ((event_data >> 8) & 0xff != MBPS_1):  
        # last attempted rate should be 1 Mbps but the first time around the
        # hardware reports a bogus rate.  No big deal.
        # sys.exit(1)
        None
    MAX_RETRIES=0xa
    if ((event_data >> 16) & 0xff != MAX_RETRIES):   
        sys.exit(1)
    p.join()
    sys.exit(0)

def fw_add_peer(ifindex, mac=None):
    if not mac:
        print "please specify a peer mac address to add!"
        raise

    ALL_RATES=0xfff
    macbytes = struct.pack("<6B", *[int(x,16) for x in mac.split(":")])
    do_cmd(MWL8787_CMD_SET_PEER, "<" + str(len(str(macbytes))) + "sI", str(macbytes), ALL_RATES)

def fw_del_peer(ifindex, mac=None):
    if not mac:
        print "please specify a peer mac address to delete!"
        raise

    try:
        do_cmd(MWL8787_CMD_DEL_PEER, "<6B", *[int(x,16) for x in mac.split(":")])
    except OSError as e:
        if (e.errno == 1):
            # sometimes the command / response get mixed up and we "timeout",
            # if so just try again. This command will fail (since the peer is
            # (hopefully) already gone), but at least it will time out if the
            # firmware truly crashed and raise an exception.
            time.sleep(0.5)
            do_cmd(MWL8787_CMD_DEL_PEER, "<6B", *[int(x,16) for x in mac.split(":")])

def send_data_multicast(ifindex, data=None):
    if not data:
        print "please specify a payload"
        raise

    mac = mac_address(ifindex)

    frame = get_mesh_mcast_data(mac, "ff:ff:ff:ff:ff:ff", data)
    fw_send_frame(ifindex, str(frame))

def send_data_unicast(ifindex, data=None):
    if not data:
        print "please specify a payload"
        raise

    mac = mac_address(ifindex)
    PEERMAC = "00:11:22:33:44:55"

    frame = get_mesh_4addr_data(mac, PEERMAC, data)
    fw_add_peer(ifindex, PEERMAC)
    fw_send_frame(ifindex, str(frame))
    fw_del_peer(ifindex, PEERMAC)

def send_to_many_peers(ifindex, data, base_address, address_range):
    if not data:
        print "please specify a payload"
        raise

    mac = mac_address(ifindex)

    for i in range(int(address_range)):
        dst = base_address + "%02x" % i
        frame = get_mesh_4addr_data(mac, dst, data)

        # need to add the peer first
        try:
            fw_add_peer(ifindex, dst)
        except OSError:
            print "couldn't add peer #%d!" % i
            # clean up peers we did add before quitting
            for j in range(i):
                dst = base_address + "%02x" % i
                fw_del_peer(ifindex, dst)
            exit(1)

        try:
            fw_send_frame(ifindex, str(frame))
        except OSError as e:
            if (e.errno == 1):
                # We get this when we try to send data too fast.
                # take a break
                time.sleep(0.5)
                fw_send_frame(ifindex, str(frame))
            else:
                raise

# clean up everything we added
    for i in range(int(address_range)):
        dst = base_address + "%02x" % i
        fw_del_peer(ifindex, dst)

def fw_send_frame(ifindex, frame):

    # 8787 tx descriptor
    BSS_TYPE = 0x3 # TYPE_TM
    BSS_NUM = 0
    LEN = len(frame)
    OFFSET = 16
    TYPE = 0x5 # 802.11
    RES1 = 0x20000 # REQ_TX_STATUS
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
    dstmac="00:11:22:33:44:55"

    mymac = mac_address(ifindex)

# beacon
    pkt = get_mesh_beacon(mymac, MESHID)
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))

# peering open
    pkt = get_mesh_peering_open(mymac, dstmac, MESHID)
    fw_send_frame(ifindex, str(pkt))

# bcast mesh data
    pkt = get_mesh_mcast_data(mymac, "ff:ff:ff:ff:ff:ff", PAYLOAD)
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))

# PREQ
    pkt = get_mesh_preq(mymac, "0c:0c:0c:0c:0c:0c")
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))

# 4addr mesh data
    pkt = get_mesh_4addr_data(mymac, dstmac, PAYLOAD)
    fw_send_frame(ifindex, str(pkt))

def fw_set_beacon(ifindex, meshid, intval):

    intval = int(intval)
    mymac = mac_address(ifindex)

    frame = get_mesh_beacon(mymac, meshid)

    # set beacon data
    do_cmd(MWL8787_CMD_BEACON_SET, "<H" + str(len(str(frame))) + "s", len(str(frame)), str(frame))

    # enable beaconing at the given interval
    do_cmd(MWL8787_CMD_BEACON_CTRL, "<HHH", CMD_ACT_SET, 1, intval)

    return frame


def matches_beacon(tx, rx):
    try:
        rx[Dot11]
    except IndexError:
        return False

    if (tx.subtype != rx.subtype or
        tx.type != rx.type or
        tx.addr1 != rx.addr1 or
        tx.addr2 != rx.addr2 or
        tx.addr3 != rx.addr3 or
        tx.beacon_interval != rx.beacon_interval or
        tx.cap != rx.cap):
           return False

    return True

from subprocess import Popen
import os

def test_tx_bcn(ifindex, monif):

    mac = mac_address(ifindex)
    MESHID="foolfool"

    devnull = open(os.devnull,"w")

# start capture, would be nice to use the pypcap library, but apparently it
# can't passively write to a capture file in the background. Spawn a tcpdump
# session instead. Oh well.
    p = Popen(["tcpdump", "-i" + monif, "-w" + CAP_FILE], stderr=devnull)
    time.sleep(3)

# tx frame type
    pkt = get_mesh_beacon(mac, MESHID)
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    MESHID="foolfoo"
    pkt = get_mesh_beacon(mac, MESHID)
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    MESHID="foolfo"
    pkt = get_mesh_beacon(mac, MESHID)
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    MESHID="foolf"
    pkt = get_mesh_beacon(mac, MESHID)
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    MESHID="fool"
    pkt = get_mesh_beacon(mac, MESHID)
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    MESHID="foo"
    pkt = get_mesh_beacon(mac, MESHID)
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))

    time.sleep(1)
    os.kill(p.pid, 15)

# read frame
    pkts = rdpcap(CAP_FILE)
    found = False
    for p in pkts:
        if matches_beacon(pkt, p):
            found = True
            break

    if found:
        sys.exit(0)
    else:
        sys.exit(1)

def fw_bcn(ifidx, monif):

    devnull = open(os.devnull,"w")

# start capture, would be nice to use the pypcap library, but apparently it
# can't passively write to a capture file in the background. Spawn a tcpdump
# session instead. Oh well.
    p = Popen(["tcpdump", "-i" + monif, "-w" + CAP_FILE], stderr=devnull)
    time.sleep(3)

    frame = fw_set_beacon(ifidx, "Flooloo", 100)

# capture beacons
    time.sleep(3)

    os.kill(p.pid, 15)

    pkts = rdpcap(CAP_FILE)
    bcns = 0
    for p in pkts:
        if matches_beacon(frame, p):
            bcns += 1

# once every 100ms for 3 seconds is ample time to see at least say 5 beacons
# including losses
    if bcns > 5:
        sys.exit(0)
    else:
        sys.exit(1)

def matches_preq(tx, rx):
    try:
        rx[Dot11]
        rx[Dot11Action]
        rx[Dot11Mesh]
    except IndexError:
        return False

    if (tx.subtype != rx.subtype or
        tx.type != rx.type or
        tx.addr1 != rx.addr1 or
        tx.addr2 != rx.addr2 or
        tx.addr3 != rx.addr3 or
        tx[Dot11Action].category != rx[Dot11Action].category or
        tx[Dot11Mesh].mesh_action != rx[Dot11Mesh].mesh_action):
        # can't check rx[Dot11Elt] here since it apparently isn't filled out
        # for dissected frames, oh well, it's definitely a PREQ from tx
           return False

    return True

def tx_preq(ifindex, monif):
    mac = mac_address(ifindex)

    devnull = open(os.devnull,"w")

# start capture, would be nice to use the pypcap library, but apparently it
# can't passively write to a capture file in the background. Spawn a tcpdump
# session instead. Oh well.
    p = Popen(["tcpdump", "-i" + monif, "-w" + CAP_FILE], stderr=devnull)
    time.sleep(3)

    pkt = get_mesh_preq(mac, "11:22:33:44:55:66")
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))
    fw_send_frame(ifindex, str(pkt))

    wrpcap("/tmp/refcap.cap", pkt)

    time.sleep(2)
    os.kill(p.pid, 15)

# read frame
    pkts = rdpcap(CAP_FILE)
    found = False
    for p in pkts:
        if matches_preq(pkt, p):
            found = True
            break

    if found:
        sys.exit(0)
    else:
        sys.exit(1)


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

    import __main__

    # Resist the urge to add new things here, lest we have an
    # unmaintainable mess of an if statement.  Instead, make new
    # test functions take an ifindex and 0 or more string args.
    # They will be called by introspection where the testname
    # is the test function name.
    if test == "set_radio":
        radio_control(ifindex, True if arglist[0] == "on" else False)
    elif test == "set_mac":
        mac = [int(x,16) for x in arglist[0].split(":")]
        mac_address(ifindex, address=mac)
    elif test == "get_mac":
        address = mac_address(ifindex)
        print 'mac addr: %s' % (address)
    elif test in dir(__main__):
        fn = getattr(__main__, test)
        fn(ifindex, *arglist)
    else:
        raise ValueError, 'Unknown test: %s' % test
