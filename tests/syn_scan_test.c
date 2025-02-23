#include <stdio.h>
#include "../include/syn_scan.h"
#include "../include/error.h"

void syn_scan_test(void)
{
	printf("-- SYN SCAN TESTS --\n");
	int ret;
	if ((ret = port_scan("192.168.1.1")) == SUCCESS)
		printf("✅ Basic test: Passed\n");
	else
		print_err("❌ IPv4 Basic test failed", ret);
	if ((ret = port_scan("2606:2800:21f:cb07:6820:80da:af6b:8b2c")) == SUCCESS)
		printf("✅ Basic test: Passed\n");
	else
		print_err("❌ IPv6 Basic test failed", ret);
}
