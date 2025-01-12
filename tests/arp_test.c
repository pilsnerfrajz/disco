#include <stdio.h>
#include <stdlib.h>
#include "../include/arp.h"
#include "../include/sock_utils.h"

int arp_possible_test(char *address)
{
	struct addrinfo *dst_info = get_dst_addr_struct(address, SOCK_DGRAM);
	if (dst_info == NULL)
	{
		freeaddrinfo(dst_info);
		return -1;
	}

	u_int8_t sender_ip[4];
	u_int8_t sender_mac[6];
	size_t if_size = 100;
	char *if_name = malloc(if_size);
	if (if_name == NULL)
	{
		freeaddrinfo(dst_info);
		return -1;
	}

	int ret = get_arp_details((struct sockaddr_in *)dst_info->ai_addr,
							  sender_ip, sender_mac, if_name, if_size);
	if (ret != 0)
	{
		freeaddrinfo(dst_info);
		free(if_name);
		return -1;
	}
	return 0;
}

void arp_test(void)
{
	int ret;
	char *ip = "8.8.8.8";
	printf("-- ARP TESTS --\n");
	if ((ret = arp_possible_test(ip) != 0))
		printf("✅ Remote IP %s does not support ARP test: Passed\n", ip);
	else
		printf("❌ Remote IP %s does not support ARP test: Failed. Return code: %d\n", ip, ret);

	ip = "192.168.1.1";
	if ((ret = arp_possible_test(ip) == 0))
		printf("✅ Local live host %s supports ARP test: Passed\n", ip);
	else
		printf("❌ Local live host %s supports ARP test: Failed. Return code: %d\n", ip, ret);

	if (arp(ip) == 0)
		printf("✅ ARP request to live host %s received reply test: Passed\n", ip);
	else
		printf("❌ ARP request to live host %s received reply test: Failed. Return code: %d\n", ip, ret);

	ip = "192.168.1.100";
	if (arp(ip) != 0)
		printf("✅ ARP request to down host %s received no reply test: Passed\n", ip);
	else
		printf("❌ ARP request to down host %s received no reply test: Failed. Return code: %d\n", ip, ret);
}
