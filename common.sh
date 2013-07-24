#!/bin/bash

fail() {
	echo "$@"
	exit 1
}

reload_card() {
	sudo modprobe -r $DRIVER
	echo "reload card..."
	read
	sudo modprobe mwl8787_sdio
	# wait for firmware load
	sleep 3
}

set_monitor() {
	local iface=$1
	sudo iw $iface set type monitor
}

link_up() {
	local iface=$1
	sudo ip link set $iface up
}

[ -z "$DRIVER" -o -z "$IFACE" ] && fail "please specify driver and iface"

