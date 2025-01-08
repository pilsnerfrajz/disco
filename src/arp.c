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
	// TODO Use getsockname to get the IP.
	// TODO Combine with this code to get the correct interface
	// TODO Check that MAC and IP belong to the same interface
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
	{
		/* AF_LINK = macOS interface */
		if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_LINK)
		{
			/* https://www.illumos.org/man/3SOCKET/sockaddr_dl */
			struct sockaddr_dl *s = (struct sockaddr_dl *)ifa->ifa_addr;

			/* Jump to address in sdl_data with macro */
			unsigned char *mac = (unsigned char *)LLADDR(s);

			if (s->sdl_type == IFT_ETHER)
			{
				printf("%s\t", ifa->ifa_name);
				printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
					   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
			}
		}
	}

	freeifaddrs(ifap);
	return SUCCESS;
}
