#!/bin/bash

source `dirname $0`/common.sh

CH=11
CAP_FILE=out.cap
PAYLOAD="01234567890123456789"

[ "$1" != "noreload" ] && reload_card
PHY_8787="phy$(get_phy $IFACE)"

# should use common's if_add here instead to add meshy if
# then change type to mp

iw phy $PHY_8787 interface add mesh0 type mp
# change the mac address
ifconfig mesh0 hw ether 00:19:88:52:75:86
#ip addr add dev mesh0 192.168.0.55/24


# managed
ip addr add dev $IFACE 192.168.0.33/24
link_up $IFACE
iw dev $IFACE connect -w cozyguest

sleep 10

iw dev mesh0 set channel 11
link_up mesh0

sudo iw dev mesh0 mesh join mymesh
sudo ifconfig mesh0 10.10.10.200

