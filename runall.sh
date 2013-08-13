#!/bin/bash

mkdir -p logs

tests="2-1-test_drv_load test_mon test_set_channel test_tx_unicast test_tx_mcast test_tx_bcn"

for test in $tests; do

	[ "${test}" = "test_mon" ] && ARG="noreload"

	./$test ${ARG} | tee logs/${test}_log

	echo -n $test:
	if [ $? == 0 ]; then
		echo -e "\e[00;32mPASS\e[00m"
	else
		echo -e "\e[00;31mFAIL\e[00m"
	fi
done
