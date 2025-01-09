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
	char errbuf[PCAP_ERRBUF_SIZE];
	int rv = pcap_init(PCAP_CHAR_ENC_LOCAL, errbuf);
	if (rv != 0)
	{
		fprintf(stderr, "Pcap_init error: %s\n", errbuf);
		return -1;
	}

	// pcap_inject();

	/*struct addrinfo *dst_info = get_dst_addr_struct(address, SOCK_RAW);
	if (dst_info == NULL)
	{
		freeaddrinfo(dst_info);
		return STRUCT_ERROR;
	}

	freeaddrinfo(dst_info);*/
	return SUCCESS;
}

int get_mac_addr(void)
{
	struct ifaddrs *ifap;
	struct ifaddrs *ifa;
	int rv = getifaddrs(&ifap);
	if (rv != 0)
	{
		perror("getifaddrs");
		return STRUCT_ERROR;
	}
	/*
	 * Get MAC, IP, subnet mask from interface. Check if source and target are
	 * on the same subnet.
	 * If not continue until found or list is null.
	 * Else save IP and MAC.
	 */
	int net_mask = 0;
	int ip_addr = 0;
	int mac_addr = 0;
	char *iface = "";
	unsigned char *mac;
	struct sockaddr_in *ip;
	struct sockaddr_in *mask;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
	{
		// check if loopback and continue
		/*if (ip != NULL && ip->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
		{
			continue;
		}*/

		if (ip_addr && mac_addr && net_mask)
		{
			printf("Interface: %s\n", iface);

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
			break;
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
				// iface = ifa->ifa_name;
				//  printf("%s\n", ifa->ifa_name);
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
	return SUCCESS;
}
