#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>

#include <net/if_dl.h>

#include "../include/arp.h"

void arp(void)
{
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

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next)
	{
		/* AF_LINK = macOS interface */
		if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_LINK)
		{
			/* https://www.illumos.org/man/3SOCKET/sockaddr_dl */
			struct sockaddr_dl *s = (struct sockaddr_dl *)ifa->ifa_addr;

			/* Jump to address in sdl_data */
			unsigned char *mac = (unsigned char *)LLADDR(s);
			printf("%s\t", ifa->ifa_name);
			printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
				   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
		}
	}

	freeifaddrs(ifap);
	return SUCCESS;
}
