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
	printf("-- ARP TESTS --\n");
	if ((ret = arp_possible_test("8.8.8.8")) == ARP_NOT_SUPP)
		printf("✅ Remote IP 8.8.8.8 does not support ARP test: Passed\n");
	else
		print_err("❌ Remote IP 8.8.8.8 does not support ARP test failed", ret);

	if ((ret = arp_possible_test("192.168.1.1")) == ARP_SUPP)
		printf("✅ Local live host 192.168.1.1 supports ARP test: Passed\n");
	else
		print_err("❌ Local live host 192.168.1.1 supports ARP test failed", ret);

	if (arp("192.168.1.1") == SUCCESS)
		printf("✅ ARP request to live host 192.168.1.1 received reply test: Passed\n");
	else
		print_err("❌ ARP request to live host 192.168.1.1 received reply test failed", ret);

	if (arp("192.168.1.100") == NO_RESPONSE)
		printf("✅ ARP request to down host 192.168.1.100 received no reply test: Passed\n");
	else
		print_err("❌ ARP request to down host 192.168.1.100 received no reply test failed", ret);
}
