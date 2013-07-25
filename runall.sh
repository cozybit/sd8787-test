#!/bin/bash

mkdir -p logs

tests="test_mon test_set_channel"

for test in $tests; do
	echo running $test

	./$test | tee logs/${test}_log

	echo -n $test:
	if [ $? == 0 ]; then
		echo PASS
	else
		echo FAIL
	fi
done
