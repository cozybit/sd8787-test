#!/bin/bash

mkdir -p logs

tests="2-1-test_drv_load 2-3-test_drv_cap 2-4-test_drv_ifmsh
test_mon test_set_channel test_tx_feedback test_tx_unicast
test_tx_mcast test_tx_bcn test_fw_bcn test_many_peers test_tx_preq
test_bcn_rx_bcn test_max_fail test_mesh_iperf"

for test in $tests; do

	[ "${test}" = "test_mon" ] && ARG="noreload"

	./$test ${ARG}

	if [ $? == 0 ]; then
		printf "%-40s\e[00;32mPASS\e[00m\n" $test
	else
		printf "%-40s\e[00;31mFAIL\e[00m\n" $test
	fi
done
