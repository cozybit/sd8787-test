#!/usr/bin/python
import pcap, sys, radiotap, os, struct

def hexdump(chars, width=16):
    while chars:
        line = chars[:width]
        chars = chars[width:]
        line = line.ljust(width, '\000')
        print "%s" % (' '.join("%02x" % ord(c) for c in line))

def is_beacon(mac):
    fc = mac.get('fc', 0)
    type = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0x0f;

    # mgmt frame and type = 8
    return type == 0 and subtype == 0x8

def is_dtim(mac, ies):
    if not is_beacon(mac):
        return False

    while len(ies) > 2:
        ie_eid, ie_len = struct.unpack_from('<BB', ies, 0)
        if len(ies) < ie_len:
            break

        if ie_eid == 5: # tim
            dtim_ct, = struct.unpack_from('<B', ies, 2)
            if dtim_ct == 0: #dtim
                return True
            else:
                return False
        ies = ies[2+ie_len:]
    return False

def beacon_ts(mac, fixed):
    ts, = struct.unpack_from('<Q', fixed, 0)
    return ts

fn = sys.argv[1]
pc = pcap.pcap(fn)
count = 0
sta_files = {}
window_files = {}
nstas = 0
windows = {}

for ts, pkt in pc:

    rofs, rtap = radiotap.radiotap_parse(pkt)
    ofs, mac = radiotap.ieee80211_parse(pkt, rofs)

    if not rtap.has_key('TSFT'):
	    continue
    ts = rtap['TSFT']

    # check for expiry of any windows, if so write them to window_files
    for sta in windows.keys():
        window = windows[sta]
        if ts > window['end']:
            print >>window_files[sta], '%d %d' % (window['start'], window['end'])
            windows.pop(sta)

    count += 1

    if 'addr2' not in mac:
        continue

    sta = mac['addr2']
    if sta not in sta_files:
        sta_hex = sta.split(':')
        nstas += 1
        sta_files[sta] = open('mesh-sta-%s-%s.dat' %
			(sta_hex[4], sta_hex[5]), 'w')
        window_files[sta] = open('mesh-window-%s-%s.dat' %
			(sta_hex[4], sta_hex[5]), 'w')

    dtim, bcn_ts, beacon = 0, 0, 0
    if is_beacon(mac):
        beacon = 1
        bcn_ts = beacon_ts(mac, pkt[ofs:])
        if is_dtim(mac, pkt[ofs+12:]):
            dtim = 1
        windows.setdefault(sta, {})
        windows[sta]['start'] = ts
        windows[sta]['end'] = ts + 10 * 1024 # FIXME read from awake window IE

    rspi = mac.get('rspi', -1)
    eosp = mac.get('eosp', -1)
    ps_mode = 'unknown'

    if radiotap.is_qos(mac):
        # in data frames:
        # pmfield = 0 -> active
        # pmfield = 1 ->
        #   mesh_ps = 0 -> light sleep
        #           = 1 -> deep sleep
        mesh_ps = mac.get('mesh_ps', 0)
        pm_field = (mac.get('fc') >> 12) & 1
        if pm_field == 0:
            ps_mode = 'active'
        elif mesh_ps == 0:
            ps_mode = 'light'
        else:
            ps_mode = 'deep'

        # a directed frame with eosp = 0 extends the window
        if eosp == 0:
            dest = mac.get('addr1')
            if dest in windows:
                windows[dest]['end'] = ts + 10 * 1024

    print >>sta_files[sta], '%s %s %s %d %d %s %d %d %d' % (ts, sta, bcn_ts, rspi, eosp, ps_mode, bcn_ts % 1024000, beacon, dtim)

for sta in sorted(sta_files):
    sta_files[sta].close()
    window_files[sta].close()

