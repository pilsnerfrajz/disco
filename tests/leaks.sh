#!/bin/bash

BIN="./bin/disco"

run_test() {
	ERR_LOG=$(mktemp)

	# run binary with argument
	$BIN "$@" > /dev/null 2> "$ERR_LOG"
	if grep -q "Sanitizer" "$ERR_LOG"; then
		echo "❌ Leak test with arguments '$@': failed"
		cat "$ERR_LOG"
		exit 1
	else
		echo "✅ Leak test with arguments '$@': passed"
	fi
	rm -f "$ERR_LOG"
}

run_test "-h"
run_test --help
run_test

run_test localhost -P
run_test localhost --ping-only
run_test localhost -a
run_test localhost --arp-only
run_test localhost -S
run_test localhost --syn-only
run_test localhost -n

run_test localhost -p 80
run_test localhost -p 22,80,443
run_test localhost -p 1-100
run_test localhost -p 1-5,80,8080-8090

run_test localhost -p 0
run_test localhost -p 70000
run_test localhost -p 80,,22
run_test 0.0.0.0 -P
run_test 255.255.255.255 -P

run_test localhost -P -w out.txt
rm -f out.txt

run_test localhost -p 80 -o -f
run_test localhost -n -p 22,80 -w out.txt
rm -f out.txt

run_test 192.168.1.1 -P
run_test 192.168.1.1 --ping-only
run_test 192.168.1.1 -a
run_test 192.168.1.1 --arp-only
run_test 192.168.1.1 -S
run_test 192.168.1.1 --syn-only
run_test 192.168.1.1 -n

run_test 192.168.1.1 -p 80
run_test 192.168.1.1 -p 22,80,443
run_test 192.168.1.1 -p 1-100
run_test 192.168.1.1 -p 1-5,80,8080-8090

run_test 192.168.1.1 -p 0
run_test 192.168.1.1 -p 70000
run_test 192.168.1.1 -p 80,,22
run_test 0.0.0.0 -P
run_test 255.255.255.255 -P

run_test 192.168.1.1 -P -w out.txt
rm -f out.txt

run_test 192.168.1.1 -p 80 -o -f
run_test 192.168.1.1 -n -p 22,80 -w out.txt
rm -f out.txt