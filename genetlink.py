'''
Netlink message generation/parsing

Copyright 2007		Johannes Berg <johannes@sipsolutions.net>

GPLv2; See copying for details.
'''

import struct
from netlink import *

CTRL_CMD_UNSPEC		= 0
CTRL_CMD_NEWFAMILY	= 1
CTRL_CMD_DELFAMILY	= 2
CTRL_CMD_GETFAMILY	= 3
CTRL_CMD_NEWOPS		= 4
CTRL_CMD_DELOPS		= 5
CTRL_CMD_GETOPS		= 6

CTRL_ATTR_UNSPEC	= 0
CTRL_ATTR_FAMILY_ID	= 1
CTRL_ATTR_FAMILY_NAME	= 2
CTRL_ATTR_VERSION	= 3
CTRL_ATTR_HDRSIZE	= 4
CTRL_ATTR_MAXATTR	= 5
CTRL_ATTR_OPS		= 6

class GenlHdr:
    def __init__(self, cmd, version = 0):
        self.cmd = cmd
        self.version = version
    def _dump(self):
        return struct.pack("BBxx", self.cmd, self.version)

def genl_hdr_parse(data):
    return GenlHdr(*struct.unpack("BBxx", data))

GENL_ID_CTRL		= NLMSG_MIN_TYPE

class GeNlMessage(Message):
    def __init__(self, family, cmd, attrs=[], flags=0):
        self.cmd = cmd
        self.attrs = attrs
        self.family = family
        Message.__init__(self, family, flags=flags, payload=[GenlHdr(self.cmd)]+attrs)

class Controller:
    def __init__(self, conn):
        self.conn = conn
    def get_family_id(self, family):
        a = NulStrAttr(CTRL_ATTR_FAMILY_NAME, family)
        m = GeNlMessage(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, flags=NLM_F_REQUEST, attrs=[a])
        m.send(self.conn)
        m = self.conn.recv()
        gh = genl_hdr_parse(m.payload[:4])
        attrs = parse_attributes(m.payload[4:])
        return attrs[CTRL_ATTR_FAMILY_ID].u16()

connection = Connection(NETLINK_GENERIC)
controller = Controller(connection)

# JC: The 'testmode' multicast group id is dynamically assigned when the group
# is registered in the kernel. I could not figure how to look it up from python
# so I'm shooting from the hip here and subscribing to a bunch of groups (16).
# This works for my but is horrible and may not work for you.
mcast_connection = Connection(NETLINK_GENERIC, groups=0xff)
