#!/bin/bash

source config

fail() {
	echo "$@"
	cleanup
	exit 1
}

testmode() {
	local iface=$1
	local testcase=$2
	shift 2
	local args=$@
	sudo ./testmode.py -i$iface -t $testcase $args || fail "$testcase failed!"
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

set_mesh() {
	local iface=$1
	link_down $iface
	sudo iw $iface set type mp || fail
	link_up $iface
}

start_capture() {
	local iface=$1
	local file=$2
	sudo tcpdump -i$iface -w$file &>/dev/null
}

start_capture_filter_mac() {
    local iface=$1
    local file=$2
    local addr=`if2mac $3`
    capfilter="wlan addr1 $addr or wlan addr2 $addr"
    sudo tshark -i$iface -w- -f"$capfilter" 2>/dev/null >$file
}

stop_all_captures() {
    sudo killall -w tshark &>/dev/null
    sudo killall -w tcpdump &>/dev/null
}

set_channel() {
	local iface=$1
	local ch=$2
	local chtype=$3
	sudo iw $iface set channel $ch $chtype || fail
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

if2mac () {
	sudo iw dev | grep $1 -A3 | grep addr | awk '{print $2}' | uniq
}

setmac() {
	local iface=$1
	local addr=$2
	link_down $iface
	sudo ip link set $iface addr $addr
	link_up $iface
}

# prune interfaces on $PHY
# clean_phy $PHY
clean_phy () {
	local n=`echo $1 | sed 's/phy//'`
	local phy="phy#$n"

	local IFS=`iw dev | grep $phy -A 100 | grep -v $phy | \
	     sed '/^phy.*/,$d' | grep Interface | awk '{print $2}'`

	for iface in $IFS; do
		sudo iw $iface interface del || fail
	done
}

# if2ip <iface>
if2ip () {
	local iface=$1

        echo -n `sudo ip addr show $iface | grep -m 1 "inet" | awk '{print$2}' | cut -d'/' -f1`
}

# if2idx <iface>
if2idx () {
	echo -n `sudo iw dev | grep $1 -A2 | grep "\<ifindex\>" | awk '{print $2}'`
}

# increment_ip <ip>
# TODO: roll over
increment_ip () {
	local b4=`echo $1 | cut -f4 -d'.'`
	(( b4 += 1))
	echo $1 | sed "s/[[:digit:]]*$/$b4/"
}

# assign new ip to $node from subnet defined in $bss
# assign_ip <node> <bss>
assign_ip () {
	local node=$1
	local bss=$2

	# ready a new "unique" IP for this bss
	eval $bss[ip]=$(increment_ip $(eval echo \${$bss[ip]}))
	eval $node[ip]=$(eval echo \${$bss[ip]})
}

start_mesh() {
	local bss=$(eval echo \${$1[bss]})
	local if=$(eval echo \${$1[if]})
	local ssid=$(eval echo \${$bss[ssid]})
	local ch=$(eval echo \${$bss[channel]})
	local chtype=$(eval echo \${$bss[chtype]})

	set_mesh $if
	set_channel $if $ch $chtype
	sudo iw $if mesh join $ssid
	if_up $1
}
# bring up $node on node[if] with ip node[ip]
# if_up $node
if_up () {
	local if=$(eval echo \${$1[if]})
	local ip=$(eval echo \${$1[ip]})
	local idx=`if2idx $if`

	# magic: accept packets with local source addresses, only reply to ARP
	# requests on own interface, create new entries in ARP table for
	# gratuitous ARPs, turn off forwarding (router) mode and rp_filter
	echo "echo 1 > /proc/sys/net/ipv4/conf/$if/accept_local" | sudo sh
	echo "echo 1 > /proc/sys/net/ipv4/conf/$if/arp_filter" | sudo sh
	echo "echo 1 > /proc/sys/net/ipv4/conf/$if/arp_accept" | sudo sh
	echo "echo 0 > /proc/sys/net/ipv4/conf/$if/forwarding" | sudo sh
	echo "echo 0 > /proc/sys/net/ipv4/conf/$if/rp_filter" | sudo sh

	sudo ip address add dev $if $ip/24
	sudo ip link set $if up

	# create a rule for packets originating from this local address to 
	# be routed by a simpler table that just sends the packet to the
	# interface without doing any checks on the destination address
	sudo ip rule del prio 5$idx 2> /dev/null
	sudo ip rule add prio 5$idx from $ip/32 table 5$idx

	# create the simple table (50$i) that will be used for packets
	# that match the previous rule
	sudo ip route flush table 5$idx 2>/dev/null
	sudo ip route add default dev $if table 5$idx

	# restore the local table for incoming traffic  so it's
	# processed normally by the IP stack
	sudo ip rule del prio $idx 2>/dev/null
	sudo ip rule add prio $idx iif $if lookup local
}

# create new $if on $phy specified in $node
# if_add $node
if_add () {
	local if=$(eval echo \${$1[if]})
	local phy=$(eval echo \${$1[phy]})

	iw dev | grep "Interface $if" >/dev/null && return
	sudo iw $phy interface add $if type managed
}

# apply BSS described in $bss to $node, and set node-specific parameters
# set_bss $node $bss
set_bss () {
	local node=$1
	local bss=$2

	# get new ip this bss
	assign_ip $node $bss
	eval $node[bss]=$bss
}

# check ping a -> b
# check_ping $a $b
check_ping () {
	local ifa=$(eval echo \${$1[if]})
	local ipb=$(eval echo \${$2[ip]})

	sudo ping -I$ifa $ipb -f -w4 -Q 0xf0 &>/dev/null || fail "ping $2 from $1"
}

# start iperf session from node a -> b
# start_straffic $a $b
start_traffic () {
	local a=$1
	local b=$2
	local ip_a=$(eval echo \${$a[ip]})
	local ip_b=$(eval echo \${$b[ip]})
	local sta_a=$(eval echo \${$a[if]})
	local sta_b=$(eval echo \${$b[if]})
	local IPERF_LOG="log/iperf_${sta_a}_${sta_b}"

	# server
	# XXX: ugh, we can't use CSV reports since there is a bug when printing
	# the throughput on pandaboard?
	iperf -s -B$ip_b -u -i1 > $IPERF_LOG &
	eval $b[iperf_pid]=$!
	eval $b[iperf_log]=$IPERF_LOG
	sleep 2	# wait for server to start

	# client
	iperf -B $ip_a -c $ip_b -i1 -t1000000 -u -b100M > /dev/null &
	eval $a[iperf_pid]=$!
}

# iperf sessions are all forked off, so we need to stop them manually
stop_traffic () {
	local a=$1
	local b=$2
	local pid_a=$(eval echo \${$a[iperf_pid]})
	local pid_b=$(eval echo \${$b[iperf_pid]})

	kill $pid_a && wait $pid_a
	kill $pid_b && wait $pid_b

	eval $a[iperf_pid]=""
	eval $b[iperf_pid]=""
}

# get throughput from destination (server) node, hopefully in Mbps
# get_throughput $node
get_throughput () {
	local iperf_log=$(eval echo \${$1[iperf_log]})

	[ -z "$iperf_log" ] && { echo "no iperf log?"; return 1; }

	cat $iperf_log | grep -v "out-of-order" | tail -n1 | awk '{print $7}'
}

kill_routes () {
	local ip=$(eval echo \${$1[ip]})
	local if=$(eval echo \${$1[if]})

	[[ -z $"$ip" ]] && return
	sudo ip route del to $ip/24
	sudo ip rule del from $ip
	sudo ip rule del iif $if
}

cleanup () {
	local exit_code=$1
	sudo killall iperf &> /dev/null
	# restore routing tables
	for node in $NODES; do
		kill_routes $node
	done
	sudo ip rule add priority 0 from all lookup local
	sudo ip rule del prio 1000
	exit $exit_code
}
trap "cleanup" INT TERM

mkdir -p log

#### routing hacks  ####
# move local routing table to lower priority in preparation to the new routing
# tables that we create later
sudo ip rule add priority 10000 table local
sudo ip rule del priority 0 &> /dev/null

# only reply to ARP requests for addresses configured on the device
echo "echo 1 > /proc/sys/net/ipv4/conf/all/arp_ignore" | sudo sh

[ -z "$DRIVER" -o -z "$IFACE" ] && fail "please specify driver and iface"
[ -z "$REF_DRIVER" -o -z "$REF_IFACE" ] && fail "please specify reference driver and iface"
[ ! -z "$MON_IFACE" ] && set_monitor $MON_IFACE

declare -A bss0
bss0[ssid]=foo
bss0[ip]=10.10.10.0
bss0[channel]=6
bss0[chtype]=HT20

declare -A dev0
dev0[if]=$IFACE
set_bss dev0 bss0
NODES="$NODES dev0"

declare -A ref0
ref0[if]=$REF_IFACE
set_bss ref0 bss0
NODES="$NODES ref0"
