#!/bin/bash

source config

fail() {
	echo "$@"
	exit 1
}

testmode() {
	local iface=$1
	local testcase=$2
	shift 2
	local args=$@
	sudo ./testmode.py -i$iface -t $testcase $args || fail
}

reload_card() {
	sudo modprobe -r $DRIVER
	# XXX: rfkill?
	echo "reload card..."
	read
	sudo modprobe mwl8787_sdio
	# wait for firmware load
	sleep 3
}

set_monitor() {
	local iface=$1
	link_down $iface
	sudo iw $iface set type monitor || fail
	link_up $iface
}

start_capture() {
	local iface=$1
	local file=$2
	sudo tcpdump -i$iface -w$file
}

set_channel() {
	local iface=$1
	local ch=$2
	sudo iw $iface set channel $ch || fail
}

link_up() {
	local iface=$1
	sudo ip link set $iface up || fail
}

link_down() {
	local iface=$1
	sudo ip link set $iface down || fail
}

fw_set_ch() {
	local iface=$1
	local ch=$2
	testmode $iface set_channel $ch
}

fw_tx_data() {
	local iface=$1
	local data=$2
	testmode $iface send_data $data
}

if2mac () {
	sudo iw dev | grep $1 -A3 | grep addr | awk '{print $2}'
}

[ -z "$DRIVER" -o -z "$IFACE" ] && fail "please specify driver and iface"
[ ! -z "$MON_IFACE" ] && set_monitor $MON_IFACE
