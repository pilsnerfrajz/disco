#include <stdio.h>

#include "include/arp_test.h"
#include "include/ping_test.h"
#include "include/syn_scan_test.h"
#include "include/cli_test.h"

int main(void)
{
	ping_test();
	printf("\n");
	arp_test();
	printf("\n");
	syn_scan_test();
	printf("\n");
	cli_test();

	return 0;
}
