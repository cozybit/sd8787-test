#!/bin/bash

source `dirname $0`/common.sh

CH=11
CAP_FILE=out.cap
PAYLOAD="01234567890123456789"

[ "$1" != "noreload" ] && reload_card
PHY_8787=`if2phy $IFACE`

# should use common's if_add here instead to add meshy if
# then change type to mp
echo "add mesh if..."

sudo iw phy $PHY_8787 interface add mesh0 type mp
# change the mac address
setmac mesh0 00:19:88:52:75:86
sudo ip addr add dev mesh0 192.168.0.55/24

# managed
echo "add managed if..."
sudo ip addr add dev $IFACE 192.168.0.33/24
link_up $IFACE
sudo iw dev $IFACE connect -w cozyguest || echo "failed to connect to ap"

declare -A bss1
bss1[ssid]=mymesh
bss1[channel]=11
bss1[ch_type]=NO_HT

declare -A meshable
meshable[if]="mesh0"
set_bss meshable bss1

# if_up in start_mesh is trying to add the routing magic
start_mesh meshable

#sudo ifconfig mesh0 10.10.10.200

