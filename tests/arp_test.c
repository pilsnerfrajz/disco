#include <stdio.h>
#include "../include/arp.h"

void arp_test(void)
{
	printf("-- ARP TESTS --\n");
	printf("\tARP possible test\n");
	int ret = arp("192.168.1.100");
	printf("ARP good test: %d\n", ret);

	printf("\tARP not possible test\n");
	ret = arp("8.8.8.8");
	printf("ARP bad test: %d\n", ret);
}
