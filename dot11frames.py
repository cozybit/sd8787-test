#!/usr/bin/env python
from scapy.layers.dot11 import *
from scapy.layers.inet import *
from scapy import *

"""
NOTE:
    This module requires scapy + some patches which are not yet upstream, so
    install the version at: git@github.com:cozybit/scapy.git
"""

def get_mesh_beacon(mac, meshid):
    if not mac or not meshid:
        print "hey give me a mac and meshid!"
        raise

    pkt = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)\
            / Dot11Beacon(cap="ESS")\
            / Dot11Elt(ID="SSID",info="")\
            / Dot11Elt(ID="MeshID", info=meshid)
    return pkt

def get_mesh_4addr_data(src, dst, payload):
    if not src or not dst or not payload:
        print "hey give me a srcmac, dstmac, and payload!"
        raise

# RA TA DA SA
# TXOP=1 mesh control present
    pkt = Dot11(addr1=dst, addr2=src, addr3=dst, addr4=src,
                type="Data", subtype=0x8,FCfield="to-DS+from-DS")\
            / Dot11QoS(TXOP=1)\
            / Dot11MeshControl(mesh_ttl=5, mesh_sequence_number=0x99)\
            / LLC(dsap=0xaa, ssap=0xaa) / SNAP(code=0x0800)
# don't care about upper layers, but might as well put payload in proper UDP/IP
# so we can extract it as a field with tshark later
    pkt = pkt / IP(dst=RandIP(),src=RandIP())\
              / UDP(sport=0x123,dport=0x123)\
              / Packet(payload)
    return pkt

def get_mesh_mcast_data(src, dst, payload):
    if not src or not dst or not payload:
        print "hey give me a srcmac, dstmac, and payload!"
        raise

    pkt = Dot11(addr1=dst, addr2=src, addr3=src,
                type="Data", subtype=0x88,FCfield="from-DS")\
            / Dot11QoS(TXOP=1)\
            / Dot11MeshControl(mesh_ttl=5, mesh_sequence_number=0x99)\
            / LLC(dsap=0xaa, ssap=0xaa) / SNAP(code=0x0800)
    pkt = pkt / IP(dst=RandIP(),src=RandIP())\
              / UDP(sport=0x123,dport=0x123)\
              / Packet(payload)
    return pkt

def get_mesh_peering_open(src, dst, meshid):
    if not src or not dst or not meshid:
        print "hey give me a src+dst mac and meshid!"
        raise

    pkt = Dot11(addr1=dst, addr2=src, addr3=src)\
            / Dot11Action(category="Self-protected")\
            / Dot11SelfProtected(selfprot_action="Mesh Peering Open")\
            / Dot11MeshPeeringOpen(cap=0)\
            / Dot11Elt(ID="MeshID",info=meshid)
    return pkt

def get_mesh_preq(src, tgt):
    if not src or not tgt:
        print "hey give me a src+tgt mac!"
        raise

    HWMP_FLAGS = 0x0
    HOP_COUNT = 0x0
    HWMP_TTL = 31
    HWMP_ID = 0
    ORIG = [int(x, 16) for x in src.split(":")]
    HWMP_OG_SN = 1
    HWMP_LIFETIME = 4882
    HWMP_METRIC = 0
    HWMP_TGT_CNT = 1
    HWMP_TGT_FLAGS = 2
    TGT = [int(x, 16) for x in tgt.split(":")]
    HWMP_TGT_SN = 0

    preq = struct.pack("<BBBI", HWMP_FLAGS, HOP_COUNT, HWMP_TTL, HWMP_ID)
    preq += struct.pack("6B", * ORIG)
    preq += struct.pack("IIIBB", HWMP_OG_SN, HWMP_LIFETIME, HWMP_METRIC, HWMP_TGT_CNT, HWMP_TGT_FLAGS)
    preq += struct.pack("6B", *TGT)
    preq += struct.pack("I", HWMP_TGT_SN)

    pkt = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=src, addr3=src)\
            / Dot11Action(category="Mesh")\
            / Dot11Mesh(mesh_action="HWMP")\
            / Dot11Elt(ID="PREQ",info=preq)
    return pkt
