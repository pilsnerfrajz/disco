#include <stdio.h>
#include "../include/arp.h"

void arp_test(void)
{
	int ret = get_mac_addr();
	printf("%d\n", ret);
}
