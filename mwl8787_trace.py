"""
trace-cmd plugin for mwl8787.  Dumps tracepoint traffic to stdout.

To use, copy/link in ~/.trace-cmd/plugins/, then, for example:

$ trace-cmd record -e mac80211 -e mwl8787 iw dev wlan1 scan

"""
import tracecmd

def hexdump(src, prefix='', offset=0, length=16, sep='.'):
    FILTER = ''.join([(len(repr(chr(x))) == 3)
        and chr(x) or sep for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        if len(hex) > 24:
            hex = "%s %s" % (hex[:24], hex[24:])
        printable = ''.join(["%s" % (
            (ord(x) <= 127 and FILTER[ord(x)]) or sep) for x in chars])
        lines.append("%s%08x %-*s |%s|\n" % (prefix, c+offset,
                     length*3, hex, printable))
    return ''.join(lines)

def mwl8787_sdio_handler(trace_seq, event):
    priv = event['priv']
    tx = event['tx']
    port = event['port']
    data = event['buf'].data

    prefix = ">" if int(tx) else "<"

    trace_str = "%s port:0x%x (%u bytes)" % (prefix, port, len(data))

    trace_seq.puts(trace_str)
    print hexdump(data, prefix=prefix + ' ', offset = int(port))

def mwl8787_sdio_reg_handler(trace_seq, event):
    priv = event['priv']
    tx = event['tx']
    port = event['port']
    val = event['val']
    ret = event['ret']
    prefix = ">" if int(tx) else "<"

    trace_str = "%s port:0x%x val:0x%x ret:%d" % (prefix, port, val, ret)
    trace_seq.puts(trace_str)
    print "%s %04x %02x" % (prefix, port, val)


def register(pevent):
    pevent.register_event_handler("mwl8787", "mwl8787_sdio", mwl8787_sdio_handler)
    pevent.register_event_handler("mwl8787", "mwl8787_sdio_reg", mwl8787_sdio_reg_handler)

