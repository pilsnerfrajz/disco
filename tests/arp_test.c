#include <stdio.h>
#include <stdlib.h>
#include "../include/arp.h"
#include "../include/utils.h"
#include "../include/error.h"

#define IF_NAME_SIZE 128

int arp_possible_test(char *address)
{
	struct addrinfo *dst_info = get_dst_addr_struct(address, SOCK_DGRAM);
	if (dst_info == NULL)
	{
		free_dst_addr_struct(dst_info);
		return UNKNOWN_HOST;
	}

	u_int8_t sender_ip[4];
	u_int8_t sender_mac[6];
	char *if_name = malloc(IF_NAME_SIZE);
	if (if_name == NULL)
	{
		free_dst_addr_struct(dst_info);
		return MEM_ALLOC_ERROR;
	}

	int ret = get_arp_details((struct sockaddr_in *)dst_info->ai_addr,
							  sender_ip, sender_mac, if_name, IF_NAME_SIZE);
	if (ret != SUCCESS)
	{
		free_dst_addr_struct(dst_info);
		free(if_name);
		return ret;
	}
	return ret;
}

void arp_test(void)
{
	int ret;
	char *ip = "8.8.8.8";
	printf("-- ARP TESTS --\n");
	if ((ret = arp_possible_test(ip)) == ARP_NOT_SUPP)
		printf("✅ Remote IP %s does not support ARP test: Passed\n", ip);
	else
		printf("❌ Remote IP %s does not support ARP test: Failed. %s\n", ip, error_strings[ret]);

	ip = "192.168.1.1";
	if ((ret = arp_possible_test(ip)) == ARP_SUPP)
		printf("✅ Local live host %s supports ARP test: Passed\n", ip);
	else
		printf("❌ Local live host %s supports ARP test: Failed. %s\n", ip, error_strings[ret]);

	if (arp(ip) == SUCCESS)
		printf("✅ ARP request to live host %s received reply test: Passed\n", ip);
	else
		printf("❌ ARP request to live host %s received reply test: Failed. %s\n", ip, error_strings[ret]);

	ip = "192.168.1.100";
	if (arp(ip) == NO_RESPONSE)
		printf("✅ ARP request to down host %s received no reply test: Passed\n", ip);
	else
		printf("❌ ARP request to down host %s received no reply test: Failed. %s\n", ip, error_strings[ret]);
}
