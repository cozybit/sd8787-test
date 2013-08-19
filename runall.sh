#!/bin/bash

mkdir -p logs

tests="2-1-test_drv_load test_mon test_set_channel test_tx_feedback test_tx_unicast test_tx_mcast test_tx_bcn test_fw_bcn test_many_peers"

for test in $tests; do

	[ "${test}" = "test_mon" ] && ARG="noreload"

	./$test ${ARG}

	if [ $? == 0 ]; then
		printf "%-40s\e[00;32mPASS\e[00m\n" $test
	else
		printf "%-40s\e[00;31mFAIL\e[00m\n" $test
	fi
done
