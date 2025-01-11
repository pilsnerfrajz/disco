#include <stdio.h>
#include "../include/arp.h"

void arp_test(void)
{
	int ret;
	printf("-- ARP TESTS --\n");
	if ((ret = arp("192.168.1.1") == 0))
		printf("✅ Local IP supports ARP test: Passed\n");
	else
		printf("❌ Local IP supports ARP test: Failed. Return code: %d\n", ret);

	if ((ret = arp("8.8.8.8") != 0))
		printf("✅ Remote IP does not support ARP test: Passed\n");
	else
		printf("❌ Remote IP does not support ARP test: Failed. Return code: %d\n", ret);
}
