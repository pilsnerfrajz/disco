#include <stdio.h>
#include "../include/syn_scan.h"
#include "../include/error.h"

void syn_scan_test(void)
{
	printf("-- SYN SCAN TESTS --\n");
	int ret;
	if ((ret = port_scan("93.184.215.14")) == SUCCESS)
		printf("✅ Basic test: Passed\n");
	else
		print_err("❌ Basic test failed", ret);
}
