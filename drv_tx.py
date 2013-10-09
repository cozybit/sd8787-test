#!/usr/bin/env python
# generate uni/multicast udp frames in python

import fcntl, sys, socket, struct

def if_addr(ifname):
    print 'ifname %s' % ifname
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

def unicast(iface, count, dest='10.10.10.1:9876',
            data="some test data"):
    """
    send count unicast frames originating on iface
    """

    dest_ip, dest_port = dest.split(':')
    dest_port = int(dest_port)

    ifaddr = if_addr(iface)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.bind((ifaddr, 0))

    for i in range(0, int(count)):
        sock.sendto(data, (dest_ip, dest_port))


def mcast(iface, count, dest='224.1.1.1:9876',
          data="some test data"):
    """
    send count mcast frames originating on iface
    """
    dest_ip, dest_port = dest.split(':')
    dest_port = int(dest_port)

    ifaddr = if_addr(iface)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    # select us as outgoing iface
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(ifaddr))

    for i in range(0, int(count)):
        sock.sendto(data, (dest_ip, dest_port))

if __name__ == "__main__":
    import __main__

    cmd = sys.argv[1]
    arglist = sys.argv[2:]
    print 'arglist: %s' % arglist
    if cmd in dir(__main__):
        fn = getattr(__main__, cmd)
        fn(*arglist)

