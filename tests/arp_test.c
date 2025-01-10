#include <stdio.h>
#include "../include/arp.h"

void arp_test(void)
{
	int ret;
	printf("-- ARP TESTS --\n");
	if ((ret = arp("192.168.1.100") == 0))
		printf("✅ Local IP supports ARP test passed\n");
	else
		printf("❌ Local IP supports ARP test failed. Return code: %d\n", ret);

	if ((ret = arp("8.8.8.8") != 0))
		printf("✅ Remote IP does not support ARP test passed\n");
	else
		printf("❌ Remote IP does not support ARP test failed. Return code: %d\n", ret);
}
