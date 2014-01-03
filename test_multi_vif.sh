#!/bin/bash
source `dirname $0`/common.sh

CH=6
CAP_FILE=out.cap
PAYLOAD="01234567890123456789"

[ "$1" != "noreload" ] && reload_card
PHY_8787=`if2phy $IFACE`

connect_mesh () {
	# should use common's if_add here instead to add meshy if
	# then change type to mp
	echo "add mesh if..."

	sudo iw phy $PHY_8787 interface add mesh0 type mp
	# change the mac address
	setmac mesh0 00:19:88:52:75:86


	declare -A bss1
	bss1[ssid]=mymesh
	bss1[channel]=${CH}
	bss1[ch_type]=NO_HT
	bss1[ip]=192.168.0.55

	declare -A meshable
	meshable[if]="mesh0"
	set_bss meshable bss1
	assign_ip meshable bss1

	# if_up in start_mesh is trying to add the routing magic
	start_mesh meshable
}

connect_ap () {
	# managed
	echo "add managed if..."
	link_up $IFACE
	sudo iw dev $IFACE connect -w lets_connect | grep fail && echo "failed to connect to ap"
	sudo udhcpc -i$IFACE
}

usage () {
	echo "Usage: $0 [-a] [-m]\n-a for AP connection\n-m for mesh connection" 1>&2
	exit
}

while getopts "ma" o; do
	case "${o}" in
		m)
			connect_mesh;;
		a)
			connect_ap;;
		*)
			usage;;
	esac
done
