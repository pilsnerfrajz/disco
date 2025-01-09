#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <net/if_dl.h>	  /* sockaddr_dl */
#include <net/if_types.h> /* IFT_ETHER */

#include <pcap/pcap.h>

#include "../include/arp.h"
#include "../include/sock_utils.h"

int arp(char *address)
{
	/*char errbuf[PCAP_ERRBUF_SIZE];
	int rv = pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
	if (rv != 0)
	{
		fprintf(stderr, "Pcap_init error: %s\n", errbuf);
		return -1;
	}*/

	// pcap_inject();

	struct addrinfo *dst_info = get_dst_addr_struct(address, SOCK_DGRAM);
	if (dst_info == NULL)
	{
		freeaddrinfo(dst_info);
		return STRUCT_ERROR;
	}

	int ret = get_mac_addr((struct sockaddr_in *)dst_info->ai_addr);

	freeaddrinfo(dst_info);
	return ret;
}

int compare_subnets(in_addr_t src, in_addr_t dst, in_addr_t mask)
{
	int src_net = ntohl(src) & ntohl(mask);
	int dst_net = ntohl(dst) & ntohl(mask);

	printf("src_net: %08x, dst_net: %08x\n", src_net, dst_net);

	if (src_net == dst_net)
	{
		return 0;
	}
	return -1;
}

int get_mac_addr(struct sockaddr_in *dst)
{
	struct ifaddrs *ifap;
	struct ifaddrs *ifa;
	int rv = getifaddrs(&ifap);
	if (rv != 0)
	{
		perror("getifaddrs");
		return STRUCT_ERROR;
	}

	// TODO save IP and MAC.

	int net_mask = 0;
	int ip_addr = 0;
	int mac_addr = 0;
	char *iface = "";
	unsigned char *mac;
	struct sockaddr_in *ip;
	struct sockaddr_in *mask;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
	{
		/* Check if interface is loopback. Continue if it is */
		if (ip_addr)
		{
			if (((ntohl(ip->sin_addr.s_addr) & 0xFF000000) == 0x7F000000))
			{
				ip_addr = 0;
				continue;
			}
		}

		if (ip_addr && mac_addr && net_mask)
		{
			/* If target and host are on the same subnet, ARP is possible */
			if (compare_subnets(ip->sin_addr.s_addr,
								dst->sin_addr.s_addr,
								mask->sin_addr.s_addr) != 0)
			{
				printf("ARP is not possible!\n");
				net_mask = 0;
				ip_addr = 0;
				mac_addr = 0;
				continue;
			}

			printf("ARP is possible for:\nInterface: %s\n", iface);

			char print_ip[INET_ADDRSTRLEN];
			if (inet_ntop(AF_INET, &ip->sin_addr.s_addr, print_ip, INET_ADDRSTRLEN) == NULL)
			{
				perror("inet_ntop");
			}
			printf("IP: %s\n", print_ip);

			char print_mask[INET_ADDRSTRLEN];
			if (inet_ntop(AF_INET, &mask->sin_addr, print_mask, INET_ADDRSTRLEN) == NULL)
			{
				perror("inet_ntop");
			}
			printf("MASK: %s\n", print_mask);

			printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
				   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

			freeifaddrs(ifap);
			return SUCCESS;
		}

		if (ifa->ifa_name != NULL)
		{
			if (strncmp(iface, ifa->ifa_name, strlen(iface)) != 0)
			{
				iface = ifa->ifa_name;
				net_mask = 0;
				ip_addr = 0;
				mac_addr = 0;
			}
		}

		/* AF_LINK = macOS interface */
		if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_LINK)
		{
			/* https://www.illumos.org/man/3SOCKET/sockaddr_dl */
			struct sockaddr_dl *s = (struct sockaddr_dl *)ifa->ifa_addr;

			if (s->sdl_type == IFT_ETHER)
			{
				/* Jump to address in sdl_data with macro */
				mac = (unsigned char *)LLADDR(s);
				mac_addr = 1;
			}
		}

		/* Add Linux support ^ */

		if (ifa->ifa_netmask != NULL && ifa->ifa_netmask->sa_family == AF_INET)
		{
			mask = (struct sockaddr_in *)(ifa->ifa_netmask);
			net_mask = 1;
		}

		if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_INET)
		{
			ip = (struct sockaddr_in *)ifa->ifa_addr;
			ip_addr = 1;
		}
	}

	freeifaddrs(ifap);
	return -1;
}
